import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { WebSocketServer, type WebSocket } from 'ws';
import { verifyFrame, agentIdFor, unb64, type KeyPair } from '../src/crypto.js';

/** Signature check that treats malformed input as a bad signature, never a crash. */
function verifies(edPub: Uint8Array, op: string, frame: Record<string, unknown>): boolean {
  try {
    return verifyFrame(edPub, op, frame);
  } catch {
    return false;
  }
}

interface HubAgent {
  ws?: WebSocket;
  pub: string;
  x25519: string;
  name?: string;
  lastSeen: number;
}

interface SendFrame {
  op: 'send';
  channel?: string;
  to?: string;
  id: string;
  ts: number;
  ciphertext: string;
  sig: string;
}

/**
 * Local fake DAP/1 hub for tests: verifies hello signatures exactly per
 * spec, fans out / mailboxes sends, serves whois + flush. Ciphertext-only.
 */
export class FakeHub {
  readonly agents = new Map<string, HubAgent>();
  /** channel -> member agentIds (spec § join). */
  readonly channelMembers = new Map<string, Set<string>>();
  readonly mailboxes = new Map<string, Record<string, unknown>[]>();
  readonly verifiedSends: SendFrame[] = [];
  readonly rejected: { code: string; agentId?: string }[] = [];
  readonly log: string[] = [];
  private readonly server = http.createServer((req, res) => {
    if (req.url === '/healthz') {
      res.end('ok');
      return;
    }
    res.statusCode = 404;
    res.end();
  });
  private readonly wss = new WebSocketServer({ noServer: true });
  private readonly noncesSeen = new Set<string>();
  private readonly mailboxFull = new Set<string>();
  private readonly offlineWaiters = new Map<string, Array<() => void>>();
  private readonly sendWaiters: Array<() => void> = [];
  /** Enrollment auth (undefined = auth disabled — legacy tests dial freely). */
  private readonly masterSecret: string | undefined;
  /** Authorization bearer captured per upgrade attempt (test assertions). */
  readonly upgrades: (string | undefined)[] = [];
  /** Secrets issued via {"t":"enroll"} — accepted as bearer on later dials. */
  private readonly issuedSecrets = new Set<string>();
  /** agentIds that enrolled (asserts hello-before-enroll, one per connection). */
  readonly enrollRequests: string[] = [];
  port = 0;
  url = '';

  constructor(opts: { masterSecret?: string } = {}) {
    this.masterSecret = opts.masterSecret;
    // Bearer auth is enforced pre-upgrade (the hub 401s before Accept).
    this.server.on('upgrade', (req, socket, head) => {
      const token = bearerOf(req.headers.authorization);
      this.upgrades.push(token);
      const authed =
        this.masterSecret === undefined ||
        token === this.masterSecret ||
        (token !== undefined && this.issuedSecrets.has(token));
      if (req.url !== '/ws' || !authed) {
        socket.write('HTTP/1.1 401 Unauthorized\r\nContent-Length: 12\r\n\r\nunauthorized');
        socket.destroy();
        return;
      }
      this.wss.handleUpgrade(req, socket, head, (ws) => this.wss.emit('connection', ws, req));
    });
    this.wss.on('connection', (ws, req) => {
      const bearer = bearerOf(req.headers.authorization);
      let agentId = '';
      ws.on('error', () => {});
      ws.on('message', (data) => {
        agentId = this.handle(ws, agentId, String(data), bearer) ?? agentId;
      });
      ws.on('close', () => {
        if (agentId && this.agents.get(agentId)?.ws === ws) {
          this.agents.get(agentId)!.ws = undefined;
          for (const resolve of this.offlineWaiters.get(agentId) ?? []) resolve();
          this.offlineWaiters.delete(agentId);
        }
      });
    });
  }

  async listen(): Promise<this> {
    await new Promise<void>((resolve) => this.server.listen(0, '127.0.0.1', resolve));
    this.port = (this.server.address() as { port: number }).port;
    this.url = 'ws://127.0.0.1:' + this.port + '/ws';
    return this;
  }

  /** Resolve once `n` send frames passed signature verification. */
  waitVerifiedSends(n: number): Promise<void> {
    if (this.verifiedSends.length >= n) return Promise.resolve();
    const { promise, resolve } = Promise.withResolvers<void>();
    this.sendWaiters.push(() => {
      if (this.verifiedSends.length >= n) resolve();
    });
    return promise;
  }

  async close(): Promise<void> {
    for (const client of this.wss.clients) client.terminate();
    this.wss.close(() => {});
    this.server.closeAllConnections();
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }

  /** Drop one agent's connection server-side (reconnect tests). */
  drop(agentId: string): void {
    this.agents.get(agentId)?.ws?.close();
  }

  /** Push an error frame to a connected agent (rejection-surfacing tests). */
  sendError(agentId: string, code: string, msg: string): void {
    this.agents.get(agentId)?.ws?.send(JSON.stringify({ op: 'error', code, msg }));
  }

  /** Resolve once the hub has processed an agent's disconnect. */
  waitOffline(agentId: string): Promise<void> {
    if (this.agents.get(agentId)?.ws === undefined) return Promise.resolve();
    const { promise, resolve } = Promise.withResolvers<void>();
    const waiters = this.offlineWaiters.get(agentId) ?? [];
    waiters.push(resolve);
    this.offlineWaiters.set(agentId, waiters);
    return promise;
  }

  private handle(ws: WebSocket, agentId: string, text: string, bearer: string | undefined): string | undefined {
    let frame: Record<string, unknown>;
    try {
      frame = JSON.parse(text) as Record<string, unknown>;
    } catch {
      this.error(ws, 'bad_frame');
      return undefined;
    }
    if (frame.op === 'hello') return this.hello(ws, frame);
    if (!agentId) {
      this.error(ws, 'not_authenticated');
      return undefined;
    }
    if (frame.t === 'enroll') return this.enroll(ws, agentId, bearer);
    if (frame.op === 'whois') return this.whois(ws, String(frame.agentId));
    if (frame.op === 'join') return this.join(agentId, ws, frame);
    if (frame.op === 'presence_query') return this.presence(ws, frame);
    if (frame.op === 'send') return this.send(agentId, ws, frame as unknown as SendFrame);
    if (frame.op === 'flush') return this.flush(ws, agentId);
    this.error(ws, 'bad_frame');
    return undefined;
  }

  private hello(ws: WebSocket, frame: Record<string, unknown>): string | undefined {
    const id = agentIdFor(unb64(String(frame.pubkey)));
    if (Math.abs(Date.now() - Number(frame.ts)) > 300_000) {
      this.reject(ws, id, 'stale_ts');
      return undefined;
    }
    const nonce = String(frame.nonce);
    if (this.noncesSeen.has(nonce)) {
      this.reject(ws, id, 'replayed_nonce');
      return undefined;
    }
    if (!verifies(unb64(String(frame.pubkey)), 'hello', frame)) {
      this.reject(ws, id, 'bad_signature');
      return undefined;
    }
    this.noncesSeen.add(nonce);
    const prev = this.agents.get(id)?.ws; // one connection per agent: evict old
    if (prev && prev !== ws) {
      this.log.push('evict:' + id);
      prev.close();
    }
    this.agents.set(id, {
      ws,
      pub: String(frame.pubkey),
      x25519: typeof frame.x25519 === 'string' ? frame.x25519 : '',
      name: optName(frame.name),
      lastSeen: Date.now(),
    });
    this.log.push('hello-verified:' + id);
    ws.send(JSON.stringify({ op: 'welcome', agentId: id }));
    return id;
  }

  private join(agentId: string, ws: WebSocket, frame: Record<string, unknown>): undefined {
    const name = String(frame.channel);
    const members = this.channelMembers.get(name) ?? new Set<string>();
    members.add(agentId);
    this.channelMembers.set(name, members);
    this.log.push('join:' + name + ':' + agentId);
    ws.send(JSON.stringify({ op: 'joined', channel: name })); // first join creates it
    return undefined;
  }

  private whois(ws: WebSocket, agentId: string): undefined {
    const agent = this.agents.get(agentId);
    if (!agent) {
      this.error(ws, 'unknown_agent');
      return undefined;
    }
    ws.send(
      JSON.stringify({
        op: 'agent_info',
        agentId,
        pubkey: agent.pub,
        x25519: agent.x25519, // echoed opaquely; '' when absent
        name: agent.name,
        online: agent.ws !== undefined,
      }),
    );
    return undefined;
  }

  private presence(ws: WebSocket, frame: Record<string, unknown>): undefined {
    // Hand the query to a parked waiter, else queue it for waitPresenceQuery.
    const waiter = this.presenceQueryWaiters.shift();
    if (waiter) waiter(frame);
    else this.presenceQueries.push(frame);
    const agents = [...this.agents.entries()].map(([agentId, a]) => ({
      agentId,
      name: a.name,
      online: a.ws !== undefined,
      lastSeen: a.lastSeen,
    }));
    // Hub contract: an answer echoes a request id as replyTo (absent when
    // the query carried none); broadcast pushes never carry one. Legacy
    // mode models a pre-replyTo hub that never echoes.
    const answer: Record<string, unknown> = { op: 'presence', agents };
    if (!this.legacyAnswers && typeof frame.id === 'string') answer.replyTo = frame.id;
    if (this.holdPresence) this.heldPresence.push({ ws, answer });
    else ws.send(JSON.stringify(answer));
    return undefined;
  }

  /** Regression hooks: hold answers so a test can interleave injected
   *  frames between the query and its reply (deterministic, no sleeps). */
  holdPresence = false;
  private readonly heldPresence: Array<{ ws: WebSocket; answer: Record<string, unknown> }> = [];
  legacyAnswers = false;
  private readonly presenceQueries: Record<string, unknown>[] = [];
  private readonly presenceQueryWaiters: Array<(f: Record<string, unknown>) => void> = [];
  /** Next presence_query the hub received (carries the request id). */
  waitPresenceQuery(): Promise<Record<string, unknown>> {
    const next = this.presenceQueries.shift();
    if (next) return Promise.resolve(next);
    const { promise, resolve } = Promise.withResolvers<Record<string, unknown>>();
    this.presenceQueryWaiters.push(resolve);
    return promise;
  }

  /** Flush held presence answers, oldest first. */
  releasePresence(): void {
    for (const { ws, answer } of this.heldPresence.splice(0)) ws.send(JSON.stringify(answer));
  }
  /** Push a crafted raw frame to one connected agent (stale echoes,
   *  broadcasts). */
  sendTo(agentId: string, frame: Record<string, unknown>): void {
    this.agents.get(agentId)?.ws?.send(JSON.stringify(frame));
  }

  private send(from: string, ws: WebSocket, frame: SendFrame): undefined {
    const agent = this.agents.get(from)!;
    if (!verifies(unb64(agent.pub), 'send', frame as unknown as Record<string, unknown>)) {
      this.rejected.push({ code: 'bad_signature', agentId: from });
      this.error(ws, 'bad_signature');
      return undefined;
    }
    this.verifiedSends.push(frame);
    for (const wake of this.sendWaiters) wake();
    const targets = frame.to ? [frame.to] : [...this.agents.keys()].filter((a) => a !== from);
    const msg: Record<string, unknown> = {
      op: 'msg',
      from,
      id: frame.id,
      ts: frame.ts,
      ciphertext: frame.ciphertext,
    };
    // Real-hub shape (hub/relay.go deliverDM): DM frames carry `to`,
    // channel frames carry `channel` (omitempty).
    if (frame.to) msg.to = frame.to;
    if (frame.channel) msg.channel = frame.channel;
    for (const target of targets) {
      const targetWs = this.agents.get(target)?.ws;
      if (targetWs) targetWs.send(JSON.stringify(msg));
      else this.enqueue(target, msg);
    }
    return undefined;
  }

  private enqueue(agentId: string, msg: Record<string, unknown>): void {
    const queue = this.mailboxes.get(agentId) ?? [];
    if (queue.length >= 100) {
      queue.shift(); // overflow drops oldest
      if (!this.mailboxFull.has(agentId)) {
        this.mailboxFull.add(agentId);
        this.rejected.push({ code: 'mailbox_full', agentId });
      }
    }
    queue.push(msg);
    this.mailboxes.set(agentId, queue);
  }

  private flush(ws: WebSocket, agentId: string): undefined {
    const queue = this.mailboxes.get(agentId) ?? [];
    for (const msg of queue) ws.send(JSON.stringify(msg));
    this.mailboxes.set(agentId, []);
    ws.send(JSON.stringify({ op: 'flushed', count: queue.length }));
    return undefined;
  }

  private reject(ws: WebSocket, agentId: string, code: string): void {
    this.rejected.push({ code, agentId });
    this.error(ws, code);
    ws.close();
  }

  private error(ws: WebSocket, code: string): void {
    ws.send(JSON.stringify({ op: 'error', code, msg: code }));
  }

  /** Enroll op (master-auth connections only): issue a fresh 32-byte
   *  base64url client secret and accept it as bearer on later dials. */
  private enroll(ws: WebSocket, agentId: string, bearer: string | undefined): undefined {
    if (this.masterSecret === undefined) return undefined; // open hub: no auth, nothing to issue
    if (bearer !== this.masterSecret) {
      this.error(ws, 'not_master_auth');
      return undefined;
    }
    const secret = randomBytes(32).toString('base64url');
    this.issuedSecrets.add(secret);
    this.enrollRequests.push(agentId);
    ws.send(JSON.stringify({ t: 'enrolled', secret }));
    return undefined;
  }
}

function optName(v: unknown): string | undefined {
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

function bearerOf(v: string | undefined): string | undefined {
  return typeof v === 'string' && v.startsWith('Bearer ') ? v.slice('Bearer '.length) : undefined;
}
