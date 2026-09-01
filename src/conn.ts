import WebSocket from 'ws';
import { randomBytes, bytesToHex } from '@noble/hashes/utils';
import { signFrame, agentIdFor, b64, type KeyPair } from './crypto.js';
import { DEFAULT_KEEP_ALIVE, KeepAliveWatchdog, type KeepAliveOptions } from './keepalive.js';
import { optStr, persistDapConfig, type ClientSecretSource } from './config.js';

export interface Timers {
  setInterval: (fn: () => void, ms: number) => unknown;
  clearInterval: (handle: unknown) => void;
}

export type TimerHandle = NodeJS.Timeout;

export interface Backoff {
  initial: number;
  max: number;
}

export const DEFAULT_BACKOFF: Backoff = { initial: 1000, max: 30000 };

export interface MsgFrame {
  op: 'msg';
  /** Set on DM deliveries — hub deliverDM echoes the recipient id. */
  to?: string;
  channel?: string;
  from: string;
  id: string;
  ts: number;
  ciphertext: string;
}

/** One agent in a presence snapshot (hub registry view). */
export interface PresenceAgent {
  agentId: string;
  name?: string;
  online: boolean;
  lastSeen?: number;
}

/** Hub `presence` frame: an ANSWER echoes the presence_query request id as
 *  `replyTo` (additive hub field); broadcast pushes (peer join/offline to
 *  channel-mates) never carry it. */
export interface PresenceFrame {
  op: 'presence';
  agents: PresenceAgent[];
  /** Echo of the request `id` — present only on answers. */
  replyTo?: string;
}

export interface AgentInfo {
  agentId: string;
  pubkey: string;
  /** Agent's X25519 public key (b64); empty string when the peer did not send one. */
  x25519: string;
  name?: string;
  online: boolean;
}

export interface WelcomeInfo {
  agentId: string;
}

export interface DapOptions {
  url: string;
  keys: KeyPair;
  name?: string;
  backoff?: Partial<Backoff>;
  timers?: Timers;
  /** Client keepalive: ping the hub while idle, terminate on missed pong. */
  keepAlive?: Partial<KeepAliveOptions>;
  /** Hub-issued client secret (config/env-resolved upstream: DAP_CLIENT_SECRET
   *  > config.json). When absent but DAP_MASTER_SECRET is set, the dial
   *  carries the master secret and enrolls after welcome; the issued secret
   *  is persisted and every later dial uses it. */
  clientSecret?: string;
  /** Where `clientSecret` was resolved from (resolveDapSettings sets it):
   *  'config' = persisted cache — a hub 401 may recover it via ONE
   *  enroll-mode retry; 'env' = DAP_CLIENT_SECRET / explicit override —
   *  user intent, never wiped; unset (no secret, or caller-resolved
   *  elsewhere) never escalates. */
  clientSecretSource?: ClientSecretSource;
}

type Listener = (value: unknown) => void;

/**
 * DAP/1 wire client: hello handshake, signed send frames, flush after
 * welcome, and a setInterval-driven reconnect loop with exponential
 * backoff (1s doubling, 30s cap, reset on welcome).
 */
export class DapClient {
  /** Identity follows the keypair: agentId = hex(sha256(pub))[:16]. */
  get agentId(): string {
    return agentIdFor(this.opts.keys.pub);
  }
  connected = false;
  helloCount = 0;
  welcomeCount = 0;
  /** Delays handed to setInterval for each reconnect — spec-visible backoff. */
  readonly backoffSchedule: number[] = [];

  private readonly backoff: Backoff;
  private readonly timers: Timers;
  private readonly watchdog: KeepAliveWatchdog;
  private ws: WebSocket | undefined;
  private delay: number;
  private timer: unknown;
  private stopped = false;
  /** Master-secret dial in flight: send {"t":"enroll"} after welcome. */
  private enrollPending = false;
  /** 401 streak marker: 'denied' fires once per failure streak (no spam). */
  private denied = false;
  /** What the CURRENT dial's bearer was: 'client' secret, 'master' secret
   *  (enroll-mode), or 'none' — decides whether a 401 is recoverable. */
  private dialToken: 'client' | 'master' | 'none' = 'none';
  private readonly listeners = new Map<string, Set<Listener>>();
  private readonly emitCounts = new Map<string, number>();
  private readonly frameListeners = new Set<(frame: MsgFrame) => void | Promise<void>>();

  private readonly whoisCache = new Map<string, AgentInfo>();
  private readonly whoisWaiters = new Map<string, Array<(info: AgentInfo | undefined) => void>>();
  /** Pending presence_query calls, keyed by request id (see presence()). */
  private readonly presenceWaiters = new Map<string, Array<(agents: PresenceAgent[]) => void>>();
  /** ponytail: sticky client-lifetime latch — a replyTo echo proves the hub
   *  is echo-capable, so id-less presence frames are broadcasts (never
   *  answers) and must not complete waiters. NOT reset on reconnect: echo
   *  capability doesn't flip with our socket, and resetting reopens the
   *  every-other-restart reconnect race. Armed proactively by the
   *  welcome-time warm-up (see warmUpPresence). */
  private echoSeen = false;
  /** Warm-up attempts spent on THIS connection (1 try + 2 retries). */
  private warmupAttempts = 0;
  /** Subscribe to inbound msg frames. Every subscriber receives each frame
   *  (one client is shared by every omp session in the process — delivery
   *  must fan out, not go to the last subscriber). Returns an unsubscriber. */
  onFrame(fn: (frame: MsgFrame) => void | Promise<void>): () => void {
    this.frameListeners.add(fn);
    return () => this.frameListeners.delete(fn);
  }

  constructor(private readonly opts: DapOptions) {
    // agentId is a getter over opts.keys — no field to set.
    this.backoff = { ...DEFAULT_BACKOFF, ...opts.backoff };
    this.delay = this.backoff.initial;
    this.timers =
      opts.timers ?? {
        setInterval: (fn, ms) => setInterval(fn, ms),
        clearInterval: (h) => clearInterval(h as TimerHandle),
      };
    this.watchdog = new KeepAliveWatchdog({ ...DEFAULT_KEEP_ALIVE, ...opts.keepAlive });
  }

  connect(): void {
    if (this.stopped) return;
    this.helloCount++;
    const clientSecret = this.opts.clientSecret;
    const masterSecret = clientSecret ? undefined : optStr(process.env.DAP_MASTER_SECRET);
    const token = clientSecret ?? masterSecret;
    this.dialToken = clientSecret ? 'client' : masterSecret !== undefined ? 'master' : 'none';
    this.enrollPending = masterSecret !== undefined;
    const ws = new WebSocket(this.opts.url, token ? { headers: { Authorization: `Bearer ${token}` } } : {});
    this.ws = ws;
    ws.on('error', () => {}); // 'close' always follows; schedule from there
    // Registered so ws emits 'unexpected-response' instead of a generic
    // 'error' — the HTTP status is the auth verdict (hub 401s pre-upgrade).
    // With a listener registered ws leaves the socket open: we tear it down
    // so every failed dial deterministically reaches the 'close' path.
    ws.on('unexpected-response', (_req, res) => {
      if (this.ws !== ws) return; // stale socket: superseded by retarget/reconnect
      if (res.statusCode === 401 && !this.escalateStaleSecret() && !this.denied) {
        this.denied = true;
        this.emit('denied', res.statusCode);
      }
      ws.close();
    });
    ws.on('open', () => {
      if (this.ws !== ws) {
        // stale socket: superseded by retarget/reconnect; its replacement owns
        // the state now. Drop it unauthenticated — it must never hello: an
        // orphan hello would evict the live socket at the hub.
        ws.close();
        return;
      }
      this.watchdog.start(ws); // refresh while idle; terminate a dead conn
      this.sendHello();
    });
    ws.on('message', (data) => {
      if (this.ws !== ws) return; // stale socket: superseded by retarget/reconnect
      this.handleFrame(data.toString());
    });
    ws.on('close', () => {
      if (this.ws !== ws) return; // stale socket: superseded by retarget/reconnect
      this.onClose();
    });
  }

  /** Runtime retarget (dap_connect): stop everything, swap url and/or
   *  identity keys and display name, then connect fresh. A new name means
   *  a new identity (name-derived key file) — a different agentId. */
  retarget(next: { url?: string; keys?: KeyPair; name?: string }): void {
    if (this.timer !== undefined) this.timers.clearInterval(this.timer);
    this.timer = undefined;
    this.watchdog.stop();
    // Detach BEFORE closing: ws dispatches 'close' synchronously inside
    // .close() in some states, and the socket-identity guard must already
    // see this socket as stale — else onClose runs mid-retarget and arms a
    // spurious reconnect (observed live: one self-evict per /dap retarget).
    const old = this.ws;
    this.ws = undefined;
    old?.close();
    this.connected = false;
    this.stopped = false; // connect() again after the implicit stop
    if (next.url) this.opts.url = next.url;
    if (next.keys) {
      this.opts.keys = next.keys;
      this.whoisCache.clear();
    }
    if (next.name !== undefined) this.opts.name = next.name;
    this.delay = this.backoff.initial;
    this.connect();
  }

  stop(): void {
    this.stopped = true;
    this.watchdog.stop();
    if (this.timer !== undefined) this.timers.clearInterval(this.timer);
    this.timer = undefined;
    this.ws?.close();
  }

  send(frame: Record<string, unknown>): void {
    if (this.ws?.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify(frame));
  }

  /** Build, sign and send a `send` frame; `id` binds the E2E payload (HKDF salt / AAD). */
  signedSend(payload: { channel?: string; to?: string; id: string; ciphertext: string }): number {
    const frame: Record<string, unknown> = {
      op: 'send',
      id: payload.id,
      ts: Date.now(),
      ciphertext: payload.ciphertext,
    };
    if (payload.channel) frame.channel = payload.channel;
    if (payload.to) frame.to = payload.to;
    frame.sig = signFrame(this.opts.keys.priv, 'send', frame);
    this.send(frame);
    return frame.ts as number;
  }

  /** Channel membership (spec § join): first join creates the channel and
   * registers chanPubkey; re-join is idempotent — safe on every reconnect. */
  join(channel: string, chanPubkeyB64: string): void {
    this.send({ op: 'join', channel, chanPubkey: chanPubkeyB64 });
  }

  /** Presence snapshot: every agent the hub knows (id, name, online, lastSeen).
   *  The query carries a unique request id; a current hub echoes it back as
   *  `replyTo` on the ANSWER, so only our own answer completes the wait — a
   *  concurrent broadcast can never satisfy it with a partial roster. */
  presence(): Promise<PresenceAgent[]> {
    const id = bytesToHex(randomBytes(16)); // same convention as the hello nonce
    const { promise, resolve, reject } = Promise.withResolvers<PresenceAgent[]>();
    let timer: NodeJS.Timeout;
    const entry = (agents: PresenceAgent[]) => {
      clearTimeout(timer);
      resolve(agents);
    };
    const waiters = this.presenceWaiters.get(id) ?? [];
    waiters.push(entry);
    this.presenceWaiters.set(id, waiters);
    timer = setTimeout(() => {
      const list = this.presenceWaiters.get(id);
      const i = list?.indexOf(entry) ?? -1;
      if (list && i >= 0) {
        list.splice(i, 1);
        if (!list.length) this.presenceWaiters.delete(id);
      }
      reject(new Error('timeout waiting for presence'));
    }, 5000);
    this.send({ op: 'presence_query', id });
    return promise;
  }

  /** Welcome-time warm-up (once per connection, re-run on reconnect): one
   *  throwaway presence_query whose replyTo echo arms `echoSeen` BEFORE any
   *  consumer query — a fresh connection's own join broadcast lands in the
   *  unarmed window and would otherwise steal the first query's waiter via
   *  the one-completes-all legacy path. The result is discarded. A legacy
   *  hub answers without replyTo: the latch stays unarmed, the chain gives
   *  up after 1 try + 2 retries, and the legacy path remains. */
  private warmUpPresence(): void {
    if (this.echoSeen || this.warmupAttempts >= 3) return;
    this.warmupAttempts++;
    void this.presence().then(() => this.warmUpPresence()).catch(() => {});
  }

  /** Pubkey directory lookup (needed for DM key agreement). The cache is
   * fine for key material (a pubkey never changes under an agentId) but
   * `online`/`lastSeen` are volatile — callers surfacing presence (the
   * dap_whois tool) must pass `{ fresh: true }` or they may serve a
   * stale online verdict forever (the cache only clears on our own
   * re-key). */
  whois(agentId: string, opts?: { fresh?: boolean }): Promise<AgentInfo | undefined> {
    if (!opts?.fresh) {
      const cached = this.whoisCache.get(agentId);
      if (cached) return Promise.resolve(cached);
    }
    const { promise, resolve } = Promise.withResolvers<AgentInfo | undefined>();
    const waiters = this.whoisWaiters.get(agentId) ?? [];
    waiters.push(resolve);
    this.whoisWaiters.set(agentId, waiters);
    this.send({ op: 'whois', agentId });
    return promise;
  }

  on(event: string, listener: Listener): () => void {
    const set = this.listeners.get(event) ?? new Set();
    set.add(listener);
    this.listeners.set(event, set);
    return () => set.delete(listener);
  }

  /** Emission counter for an event (monotonic; enables wait-for-the-Nth). */
  eventCount(event: string): number {
    return this.emitCounts.get(event) ?? 0;
  }

  /** Resolve with the first emission of `event` AFTER `prev` emissions
   *  already happened. Registering before the trigger avoids races. */
  waitForAfter<T>(event: string, prev: number, timeoutMs = 5000): Promise<T> {
    if (this.eventCount(event) > prev) return Promise.resolve(undefined as T);
    const { promise, resolve, reject } = Promise.withResolvers<T>();
    const off = this.on(event, (value) => {
      if (this.eventCount(event) <= prev) return;
      clearTimeout(timer);
      off();
      resolve(value as T);
    });
    const timer = setTimeout(() => {
      off();
      reject(new Error('timeout waiting for ' + event));
    }, timeoutMs);
    return promise;
  }

  private sendHello(): void {
    const frame: Record<string, unknown> = {
      op: 'hello',
      v: 1,
      pubkey: b64(this.opts.keys.pub),
      x25519: b64(this.opts.keys.xpub), // additive, covered by the signature
      nonce: bytesToHex(randomBytes(16)),
      ts: Date.now(),
    };
    if (this.opts.name) frame.name = this.opts.name;
    frame.sig = signFrame(this.opts.keys.priv, 'hello', frame);
    this.send(frame);
  }

  private handleFrame(text: string): void {
    let frame: Record<string, unknown>;
    try {
      frame = JSON.parse(text) as Record<string, unknown>;
    } catch {
      return;
    }
    switch (frame.op) {
      case 'welcome':
        this.onWelcome(frame as unknown as WelcomeInfo & Record<string, unknown>);
        break;
      case 'msg': {
        const msgFrame = frame as unknown as MsgFrame;
        // 'inbound' fires only after EVERY subscriber's async chain (decrypt,
        // inbox, steer) settled — tests can rely on it deterministically.
        void Promise.all(
          [...this.frameListeners].map((fn) => Promise.resolve(fn(msgFrame)).catch(() => {})),
        ).then(() => this.emit('inbound', msgFrame));
        break;
      }
      case 'presence': {
        const pf = frame as unknown as PresenceFrame;
        if (typeof pf.replyTo === 'string') {
          this.echoSeen = true;
          // Strict match: only the query this answer echoes completes. A
          // foreign/stale echo or a broadcast must never satisfy a pending
          // query with a partial roster.
          const waiters = this.presenceWaiters.get(pf.replyTo);
          this.presenceWaiters.delete(pf.replyTo);
          for (const resolve of waiters ?? []) resolve(pf.agents);
        } else if (!this.echoSeen) {
          // ponytail: legacy hub answers carry no replyTo and are
          // indistinguishable on the wire from broadcast pushes, so they
          // complete all waiters one-completes-all — a broadcast landing in
          // that window can still satisfy a query with a partial roster.
          // Residual legacy-hub race only; the hub-side replyTo echo (every
          // current hub) is the real fix.
          const waiters = [...this.presenceWaiters.values()].flat();
          this.presenceWaiters.clear();
          for (const resolve of waiters) resolve(pf.agents);
        }
        this.emit('presence', pf);
        break;
      }
      case 'agent_info': {
        const info = frame as unknown as AgentInfo;
        this.whoisCache.set(info.agentId, info);
        for (const resolve of this.whoisWaiters.get(info.agentId) ?? []) resolve(info);
        this.whoisWaiters.delete(info.agentId);
        this.emit('agent_info', info);
        break;
      }
      case 'joined':
        this.emit('joined', frame);
        break;
      case 'flushed':
        this.emit('flushed', frame);
        break;
      case 'presence':
        this.emit('presence', frame);
        break;
      case 'error':
        for (const waiters of this.whoisWaiters.values()) for (const resolve of waiters) resolve(undefined);
        this.whoisWaiters.clear();
        this.emit('error', frame);
        break;
      default:
        // Enrollment reply travels as {"t":"enrolled",…} — typed, not an op.
        if (frame.t === 'enrolled') this.onEnrolled(frame);
        break;
    }
  }

  private onWelcome(welcome: WelcomeInfo & Record<string, unknown>): void {
    this.connected = true;
    this.welcomeCount++;
    this.denied = false; // authenticated again: a later 401 streak re-surfaces

    this.delay = this.backoff.initial; // backoff resets after a successful welcome
    this.send({ op: 'flush' }); // drain offline mailbox
    if (this.enrollPending) this.send({ t: 'enroll' }); // master-auth connection only
    this.warmupAttempts = 0; // reconnect re-runs the warm-up (cheap)
    this.warmUpPresence();
    this.emit('welcome', welcome);
  }

  /** {"t":"enrolled","secret"}: bind the issued secret to this identity,
   *  persist it (config file; the master secret is never stored or logged)
   *  and use it for every later dial — this process (opts mutation) and
   *  future launches (config.json). */
  private onEnrolled(frame: Record<string, unknown>): void {
    const secret = typeof frame.secret === 'string' ? frame.secret : '';
    if (!this.enrollPending || !secret) return;
    this.enrollPending = false;
    this.opts.clientSecret = secret;
    persistDapConfig({ clientSecret: secret });
    this.emit('enrolled', frame);
  }

  /** Stale persisted cache (live incident: a hub restart wiped server-side
   *  secrets, so every previously enrolled client 401-loops on its config
   *  clientSecret). A 401 on a CONFIG-sourced bearer is recoverable when
   *  DAP_MASTER_SECRET is available: drop the stale secret from this
   *  process AND config.json; the scheduled reconnect dials ONCE in
   *  enroll-mode (master bearer -> hello -> enroll -> onEnrolled re-persists
   *  the issued secret). Env-sourced and master dials never escalate: env
   *  is explicit user intent, and a 401 on the enroll-mode dial itself is
   *  fatal — exactly one retry, no loops. Identity keys are never touched:
   *  re-enrollment binds to the same hello identity. */
  private escalateStaleSecret(): boolean {
    if (this.dialToken !== 'client' || this.opts.clientSecretSource !== 'config') return false;
    if (!optStr(process.env.DAP_MASTER_SECRET)) return false;
    this.opts.clientSecret = undefined;
    persistDapConfig({ clientSecret: null }); // drop the stale cache entry
    return true;
  }

  private onClose(): void {
    this.watchdog.stop();
    const wasConnected = this.connected;
    this.connected = false;
    this.ws = undefined;
    this.emit('close', { wasConnected });
    if (!this.stopped) this.scheduleReconnect();
  }

  private scheduleReconnect(): void {
    if (this.timer !== undefined) return; // one pending attempt at a time
    const ms = this.delay;
    this.backoffSchedule.push(ms);
    // A throw in a raw (unmanaged) timer callback kills the whole omp session — the body must never throw.
    this.timer = this.timers.setInterval(() => {
      try {
        this.timers.clearInterval(this.timer);
        this.timer = undefined;
        this.connect();
      } catch {
        // swallowed: connect() errors surface via the ws 'close' path, which reschedules
      }
    }, ms);
    this.delay = Math.min(this.delay * 2, this.backoff.max);
  }

  private emit(event: string, value: unknown): void {
    this.emitCounts.set(event, (this.emitCounts.get(event) ?? 0) + 1);
    for (const listener of this.listeners.get(event) ?? []) listener(value);
  }
}
