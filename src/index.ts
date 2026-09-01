import { loadOrCreateKeys, x25519, b64, unb64, type KeyPair } from './crypto.js';
import { DapClient, type Backoff, type Timers, type PresenceAgent } from './conn.js';
import { Inbox, type InboxEntry } from './inbox.js';
import {
  encryptForChannel,
  encryptForDM,
  decryptInbound,
  type PayloadCryptoContext,
} from './codec.js';
import {
  resolveDapSettings,
  optStr,
  defaultKeyPath,
  persistDapConfig,
  readDapConfig,
  type PendingInvite,
} from './config.js';
import {
  loadChannelKeys,
  persistChannelKeys,
  newChannelKeypair,
  type ChannelKeys,
} from './channels.js';
import type { AgentToolResult, CommandCtx, ExtensionAPI, SessionCtx } from './types.js';

export interface ExtensionOptions {
  /** Test/config overrides; otherwise env (DAP_HUB_URL / DAP_KEY_PATH /
   *  DAP_AGENT_NAME / DAP_CHANNELS_FILE) > ~/.dap/config.json > defaults. */
  url?: string;
  keyPath?: string;
  name?: string;
  channelsFile?: string;
  channels?: Record<string, string>;
  channelPrivs?: Record<string, string>;
  backoff?: Partial<Backoff>;
  timers?: Timers;
}

export interface DapExtension {
  client: DapClient;
  inbox: Inbox;
  dispose(): void;
}

const str = (v: unknown): string => {
  if (typeof v !== 'string' || v.length === 0) throw new Error('expected non-empty string');
  return v;
};

/** Real omp pi has no timers: DapClient's own default is the raw-timer
 *  fallback (with a throw-safe callback body — see conn.ts). */
const toolResult = (result: unknown): AgentToolResult => ({
  content: [{ type: 'text', text: JSON.stringify(result) }],
  details: result,
});

/** Shareable host[:port] for connect lines: strip the ws(s):// scheme and
 *  the trailing /ws path from a full hub URL. */
const hostOf = (url: string): string => url.replace(/^wss?:\/\//, '').replace(/\/ws$/, '');

/** Hub 401 on the bearer token (frozen text, identical in every adapter):
 *  surfaced via surface() so the verdict reaches the user even headless. */
const DENIED_HINT =
  'hub rejected connection (HTTP 401): set DAP_MASTER_SECRET to enroll, or DAP_CLIENT_SECRET / config clientSecret to connect';

/** Injection text: enough context for the steered turn to answer in-channel. */
function formatEntry(entry: InboxEntry, peerName: string): string {
  const where = entry.channel ? '#' + entry.channel : 'DM';
  return `[dap] ${where} from ${peerName}: ${entry.text}`;
}

/** Channels file -> cryptoCtx maps (pub for sending, priv for decrypting). */
function channelsFromFile(file: string): { channels: Record<string, string>; channelPrivs: Record<string, string> } {
  const channels: Record<string, string> = {};
  const channelPrivs: Record<string, string> = {};
  for (const [name, keys] of Object.entries(loadChannelKeys(file))) {
    channels[name] = keys.pub;
    channelPrivs[name] = keys.priv;
  }
  return { channels, channelPrivs };
}

/** A DM whose decrypted text is exactly a channel-invite payload. */
function parseChankeyInvite(text: string): { channel: string; pub: string; priv: string } | undefined {
  if (text.charCodeAt(0) !== 0x7b) return undefined; // not JSON — regular chat
  try {
    const v = JSON.parse(text) as { t?: unknown; channel?: unknown; pub?: unknown; priv?: unknown };
    if (v.t !== 'chankey') return undefined;
    if (typeof v.channel !== 'string' || typeof v.pub !== 'string' || typeof v.priv !== 'string') {
      return undefined;
    }
    if (unb64(v.pub).length !== 32 || unb64(v.priv).length !== 32) return undefined;
    return { channel: v.channel, pub: v.pub, priv: v.priv };
  } catch {
    return undefined;
  }
}

/** omp runs this factory once per agent session (main + every subagent),
 *  each instance opening its own socket with the same identity key — the
 *  hub's one-connection-per-agent law turns that into an N-way eviction war
 *  (every hello evicts the previous socket). One client per identity+url per
 *  process, shared and refcounted across sessions, ends it. Tests always
 *  pass overrides and bypass the map entirely. */
interface SharedClient {
  client: DapClient;
  refs: number;
  key: string;
}
const sharedClients = new Map<string, SharedClient>();

/**
 * oh-my-pi DAP/1 extension. Default-export factory:
 * registers dap_send/dap_dm/dap_invite/dap_inbox/dap_whois tools, keeps one
 * outbound WS to the hub (signed hello, flush after welcome, setInterval
 * reconnect), and delivers inbound msg frames as steer injections + durable
 * inbox entries. Channel keys auto-generate on first send and persist to
 * ~/.dap/channels.json; invites travel as E2E DMs (see dap_invite).
 */
export default function dapExtension(ctx: ExtensionAPI, overrides: ExtensionOptions = {}): DapExtension {
  const settings = resolveDapSettings(overrides);
  let keys: KeyPair = loadOrCreateKeys(settings.keyPath);

  // Production omp path (no overrides): share/refcount one client per
  // identity+url across sessions; tests pass overrides and stay singleton-free.
  const shareKey = Object.keys(overrides).length === 0 ? settings.keyPath + '|' + settings.url : undefined;
  const existing = shareKey === undefined ? undefined : sharedClients.get(shareKey);
  const client = existing?.client ?? new DapClient({
    url: settings.url,
    keys,
    name: settings.name,
    backoff: overrides.backoff,
    timers: overrides.timers,
    clientSecret: settings.clientSecret,
    clientSecretSource: settings.clientSecretSource,
  });
  let shared: SharedClient | undefined;
  if (shareKey !== undefined) {
    shared = existing ?? { client, refs: 0, key: shareKey };
    if (!existing) sharedClients.set(shareKey, shared);
    shared.refs++;
  }
  const created = existing === undefined; // this call constructed the client
  // client.agentId is read LIVE everywhere below — a captured value went
  // stale after a /dap re-key (status kept the pre-retarget id).
  ctx.setLabel('DAP — distributed agents');
  // Persistent connection line in the omp footer (visible without asking):
  // DAP <name|id> · <host> · <state> · #chan1,#chan2. ui reference is
  // captured at session_start; setStatus is a no-op in headless modes and
  // a fire-and-forget request in RPC — safe to call from any event.
  let ui: SessionCtx['ui'] | undefined;
  const renderStatus = (state: string): void => {
    const who = settings.name ?? client.agentId;
    const host = hostOf(settings.url);
    const chans = Object.keys(cryptoCtx.channels)
      .map((c) => '#' + c)
      .join(',');
    ui?.setStatus?.('dap', `DAP ${who} · ${host} · ${state}${chans ? ' · ' + chans : ''}`);
  };
  ctx.on('session_start', (_event, sctx) => {
    ui = sctx.ui;
    pollerCtx = sctx; // managed timers for the pending-invite poller
    startPoller();
    if (sctx.hasUI && sctx.ui) {
      sctx.ui.notify(`DAP connected as ${client.agentId}${settings.name ? ` (${settings.name})` : ''}`, 'info');
    }
    renderStatus(client.connected ? 'connected' : 'connecting…');
  });
  const inbox = new Inbox(100, (entry) => ctx.appendEntry('io.dap.message', entry));
  // Explicit channel maps (tests) opt out of the channels-file lifecycle;
  // otherwise keys live in settings.channelsFile (default ~/.dap/channels.json).
  const useChannelFile = !(overrides.channels || overrides.channelPrivs);
  const fromFile = useChannelFile ? channelsFromFile(settings.channelsFile) : null;
  const cryptoCtx: PayloadCryptoContext = {
    // Live getters, not captured values: connectTo swaps `keys` and the
    // client's identity at runtime (/dap re-key). A captured selfAgentId
    // left the DM AAD on the PRE-retarget id — every inbound DM after a
    // re-key failed AEAD verification and died in io.dap.undecryptable
    // (durable but never steered): the agent went deaf while its own
    // outbound kept working.
    get keys(): KeyPair {
      return keys;
    },
    get selfAgentId(): string {
      return client.agentId;
    },
    channels: overrides.channels ?? fromFile?.channels ?? {},
    channelPrivs: overrides.channelPrivs ?? fromFile?.channelPrivs ?? {},
    peerXPub: async (agentId) => (await client.whois(agentId))?.x25519,
  };

  /** Zero-config channel creation: the first user generates the keypair,
   *  persists it (read-modify-write, keeps other channels) and joins —
   *  creating the channel. */
  const createChannel = (channel: string): ChannelKeys => {
    const created = newChannelKeypair();
    cryptoCtx.channels[channel] = created.pub;
    cryptoCtx.channelPrivs[channel] = created.priv;
    if (useChannelFile) persistChannelKeys(settings.channelsFile, channel, created);
    client.join(channel, created.pub);
    return created;
  };

  /** Full keypair for inviting: create the channel zero-config when its
   *  private key isn't held; derive pub from priv when only priv is known. */
  const channelKeysFor = (channel: string): ChannelKeys => {
    const priv = cryptoCtx.channelPrivs[channel];
    if (!priv) return createChannel(channel);
    return { pub: cryptoCtx.channels[channel] ?? b64(x25519.getPublicKey(unb64(priv))), priv };
  };

  // Trust model: possession of the channel private key IS v1 membership; the
  // introducer is whoever DM'd you (same trust as manually sharing the file).
  const acceptInvite = (invite: { channel: string; pub: string; priv: string }, from: string): void => {
    cryptoCtx.channels[invite.channel] = invite.pub;
    cryptoCtx.channelPrivs[invite.channel] = invite.priv;
    if (useChannelFile) persistChannelKeys(settings.channelsFile, invite.channel, invite);
    client.join(invite.channel, invite.pub);
    ctx.sendMessage(`[dap] invited to #${invite.channel} by ${from}`, { deliverAs: 'steer', triggerTurn: true });
  };

  // Subscribe (not assign): every session of a shared client receives each
  // frame — a later session must never steal delivery from an earlier one.
  const offMessage = client.onFrame((frame) =>
    decryptInbound(frame, cryptoCtx)
      .then((payload) => {
        const invite = payload.dm ? parseChankeyInvite(payload.text) : undefined;
        if (invite) {
          acceptInvite(invite, frame.from); // not chat: no inbox entry, just the notice
          return;
        }
        const entry = inbox.add({
          id: frame.id,
          ts: frame.ts,
          from: frame.from,
          channel: payload.channel,
          dm: payload.dm,
          text: payload.text,
        });
        // Steer + triggerTurn: steers the live turn AND starts one when the
        // agent is idle — without triggerTurn an idle agent shows nothing.
        ctx.sendMessage(formatEntry(entry, frame.from), { deliverAs: 'steer', triggerTurn: true });
      })
      .catch((err: unknown) =>
        ctx.appendEntry('io.dap.undecryptable', { type: 'dap_undecryptable', id: frame.id, error: String(err) }),
      ));

  // Membership: join every configured channel after each welcome (idempotent;
  // first join ever creates the channel and registers its public key).
  client.on('welcome', () => {
    for (const [name, pub] of Object.entries(cryptoCtx.channels)) client.join(name, pub);
    startPoller(); // the session context may exist before the socket does
    pollPending(); // restart with pendings armed: deliver without waiting a tick
    renderStatus('connected');
  });

  client.on('close', () => renderStatus('reconnecting…'));

  // Hub rejections (unknown_agent, access_denied, replay, …) must never be
  // silent: the sending tool already returned ok (it only proves the frame
  // was signed and put on the wire) — the verdict arrives here.
  client.on('error', (f) => {
    const code = typeof f === 'object' && f !== null && 'code' in f ? String(f.code) : 'error';
    const msg = typeof f === 'object' && f !== null && 'msg' in f ? String(f.msg) : JSON.stringify(f);
    ctx.appendEntry('io.dap.error', { code, msg });
    ctx.sendMessage(`[dap] hub rejected a frame — ${code}: ${msg}`, {
      deliverAs: 'steer',
      triggerTurn: true,
    });
  });

  /** Honest failure: never report ok for a frame that left nothing —
   * sends while disconnected are dropped silently by the socket layer. */
  const requireConnected = (): { ok: false; error: string } | undefined =>
    client.connected ? undefined : { ok: false, error: 'not connected to the hub (reconnecting with backoff — retry in a moment)' };
  /** Outcome of the shared invite path (tool result or footer verdict). */
  interface InviteOutcome {
    ok: boolean;
    channel?: string;
    to?: string;
    id?: string;
    ts?: number;
    error?: string;
  }
  /** One invite path (dap_invite tool + /dap invite command): DM the
   *  channel keypair to another agent — channelKeysFor auto-creates the
   *  channel zero-config when we don't hold the private key yet. */
  const sendInvite = async (channel: string, to: string): Promise<InviteOutcome> => {
    const down = requireConnected();
    if (down) return down;
    const keys = channelKeysFor(channel);
    const frameId = crypto.randomUUID();
    const payload = JSON.stringify({ t: 'chankey', channel, pub: keys.pub, priv: keys.priv });
    const ciphertext = await encryptForDM(payload, to, frameId, cryptoCtx);
    const ts = client.signedSend({ to, id: frameId, ciphertext });
    return { ok: true, channel, to, id: frameId, ts };
  };

  /** Never-silent failure path shared by the invite flows: footer + durable
   *  entry + steer — the verdict must reach the user even headless. */
  const surface = (msg: string): void => {
    renderStatus(msg);
    ctx.appendEntry('io.dap.error', { code: 'invite_failed', msg });
    ctx.sendMessage(`[dap] ${msg}`, { deliverAs: 'steer', triggerTurn: true });
  };
  // Enrollment auth: a 401 dial failure is never silent; a successful
  // enrollment is logged without ever printing the secret itself.
  client.on('denied', () => surface(DENIED_HINT));
  client.on('enrolled', () => renderStatus('enrolled: client secret persisted'));
  /** Pending by-name invites: `/dap invite <name>` against a user not yet on
   *  the hub. The chankey DM fires automatically once the name appears
   *  online; entries survive restarts in ~/.dap/config.json. */
  const configFile = optStr(process.env.DAP_CONFIG_FILE);
  const pendingInvites: PendingInvite[] = readDapConfig(configFile).invites ?? [];
  const persistInvites = (): void => persistDapConfig({ invites: [...pendingInvites] }, configFile);
  /** Shared delivery engine (poller tick + arm-time check): one presence
   *  snapshot, every matching pending gets its chankey DM. Never throws —
   *  it runs inside managed timers. */
  let delivering = false;
  const deliverPending = async (): Promise<void> => {
    if (delivering || pendingInvites.length === 0 || !client.connected) return;
    delivering = true;
    try {
      const agents = await client.presence();
      for (let i = pendingInvites.length - 1; i >= 0; i--) {
        const pending = pendingInvites[i];
        const online = agents.filter((a) => a.online && a.agentId !== client.agentId && a.name?.toLowerCase() === pending.name.toLowerCase());
        if (online.length !== 1) continue; // still away (or ambiguous): keep waiting
        const outcome = await sendInvite(pending.channel, online[0].agentId);
        if (!outcome.ok) continue; // retried on the next tick
        pendingInvites.splice(i, 1);
        persistInvites();
        renderStatus(`invited ${pending.name} to #${pending.channel}`);
        ui?.notify(`invited ${pending.name} to #${pending.channel}`, 'info');
      }
    } finally {
      delivering = false;
    }
  };
  const pollPending = (): void => {
    void deliverPending().catch((err: unknown) => surface(`pending invite check failed: ${String(err)}`));
  };
  /** Managed ctx.setInterval poller (~15s): starts once the session context
   *  (timers) and the first welcome both exist; dispose clears it. */
  const INVITE_POLL_MS = 15000;
  let pollerCtx: SessionCtx | undefined;
  let pollerHandle: unknown;
  const startPoller = (): void => {
    if (pollerHandle !== undefined || !pollerCtx) return;
    pollerHandle = pollerCtx.setInterval(pollPending, INVITE_POLL_MS);
  };

  ctx.registerTool({
    name: 'dap_send',
    description: 'Send an end-to-end-encrypted message to a DAP channel.',
    parameters: {
      type: 'object',
      properties: {
        channel: { type: 'string', description: 'Channel name, e.g. general' },
        text: { type: 'string', description: 'Message text' },
      },
      required: ['channel', 'text'],
    },
    execute: async (_toolCallId, params) => {
      const down = requireConnected();
      if (down) return toolResult(down);
      const channel = str(params.channel);
      // Unknown channel -> zero-config keygen + persist + join (spec § join:
      // senders only need the channel public key).
      if (!cryptoCtx.channels[channel]) cryptoCtx.channels[channel] = createChannel(channel).pub;
      const frameId = crypto.randomUUID();
      const ciphertext = await encryptForChannel(str(params.text), channel, frameId, cryptoCtx);
      const ts = client.signedSend({ channel, id: frameId, ciphertext });
      return toolResult({ ok: true, channel, id: frameId, ts });
    },
  });

  ctx.registerTool({
    name: 'dap_dm',
    description: 'Send an end-to-end-encrypted direct message to another agent (by agentId).',
    parameters: {
      type: 'object',
      properties: {
        to: { type: 'string', description: 'Recipient agentId' },
        text: { type: 'string', description: 'Message text' },
      },
      required: ['to', 'text'],
    },
    execute: async (_toolCallId, params) => {
      const down = requireConnected();
      if (down) return toolResult(down);
      const to = str(params.to);
      const frameId = crypto.randomUUID();
      const ciphertext = await encryptForDM(str(params.text), to, frameId, cryptoCtx);
      const ts = client.signedSend({ to, id: frameId, ciphertext });
      return toolResult({ ok: true, to, id: frameId, ts });
    },
  });

  ctx.registerTool({
    name: 'dap_invite',
    description: 'Invite another agent to a channel: DMs them the channel keypair (normal E2E DM encryption; the text payload happens to be JSON).',
    parameters: {
      type: 'object',
      properties: {
        channel: { type: 'string', description: 'Channel name, e.g. general' },
        to: { type: 'string', description: 'Recipient agentId' },
      },
      required: ['channel', 'to'],
    },
    execute: async (_toolCallId, params) => toolResult(await sendInvite(str(params.channel), str(params.to))),
  });

  ctx.registerTool({
    name: 'dap_inbox',
    description: 'List recent DAP messages delivered to this agent (durable inbox).',
    parameters: {
      type: 'object',
      properties: {
        limit: { type: 'number', description: 'Max entries (default 20)' },
        channel: { type: 'string', description: 'Filter to one channel' },
      },
    },
    execute: async (_toolCallId, params) =>
      toolResult({
        count: inbox.size,
        entries: inbox.list(
          typeof params.limit === 'number' ? params.limit : 20,
          optStr(params.channel),
        ),
      }),
  });

  ctx.registerTool({
    name: 'dap_whois',
    description: 'Look up another agent (pubkey, display name, online) by agentId. Ids are 16-hex — discover them via dap_peers, never names.',
    parameters: {
      type: 'object',
      properties: { agentId: { type: 'string' } },
      required: ['agentId'],
    },
    execute: async (_toolCallId, params) => {
      const info = await client.whois(str(params.agentId), { fresh: true });
      return toolResult(info ?? { error: 'unknown_agent' });
    },
  });

  /** One payload for the dap_status tool and the /dap_status command (DRY). */
  const statusPayload = () => ({
    connected: client.connected,
    agentId: client.agentId,
    name: settings.name,
    url: settings.url,
    channels: Object.keys(cryptoCtx.channels),
    welcomes: client.welcomeCount,
    hellos: client.helloCount,
  });
  ctx.registerTool({
    name: 'dap_status',
    description: 'Own DAP connection status: are we connected to the hub, our agentId, name, hub url, known channels.',
    parameters: { type: 'object', properties: {} },
    execute: async () => toolResult(statusPayload()),
  });

  /** dap_peers snapshot: ONLINE agents only, own entry kept and marked self
   *  (client-side marking: entry.agentId === our agentId — hub wire format
   *  is unchanged). */
  const onlinePeers = async (): Promise<Array<PresenceAgent & { self: boolean }>> =>
    (await client.presence())
      .filter((a) => a.online)
      .map((a) => ({ ...a, self: a.agentId === client.agentId }));

  ctx.registerTool({
    name: 'dap_peers',
    description: 'Online agents on the hub: online peers only; your own entry is present and marked self (self: true). Discover agentIds here — they are 16-hex ids, never names.',
    parameters: { type: 'object', properties: {} },
    execute: async () => {
      const agents = await onlinePeers();
      return toolResult({ agents });
    },
  });

  /** dap_connect: manual invitation to any DAP server — host, optional
   *  name (a new name = a new identity: name-derived key file), optional
   *  default room (persisted; auto-joined on every later launch). */
  const normalizeHost = (h: string): string => {
    const u = new URL(/^wss?:\/\//.test(h) ? h : 'ws://' + h);
    if (u.pathname === '/' || u.pathname === '') u.pathname = '/ws';
    return u.toString().replace(/\/$/, '');
  };
  const connectTo = (host?: string, name?: string, channel?: string) => {
    const url = host ? normalizeHost(host) : settings.url;
    let nextKeys: KeyPair | undefined;
    if (name) {
      settings.name = name;
      settings.keyPath = defaultKeyPath(name); // a later host-only retarget
      // must key the shared client by the NEW path — the original
      // settings.keyPath made a fresh session compute a different shareKey
      // and spawn a second socket under the OLD identity.
      nextKeys = loadOrCreateKeys(settings.keyPath);
      keys = nextKeys; // cryptoCtx.keys is a live getter over this binding
    }
    if (host) settings.url = url;
    persistDapConfig({ url: host ? url : undefined, name, channels: channel ? [channel] : undefined }, configFile);
    if (channel && !cryptoCtx.channels[channel]) cryptoCtx.channels[channel] = createChannel(channel).pub;
    client.retarget({ url: host ? url : undefined, keys: nextKeys, name });
    // Sessions spawned after this resolve the persisted url/name to nextKey —
    // re-key so they reuse this retargeted client instead of a second socket.
    const nextKey = settings.keyPath + '|' + settings.url;
    if (shared !== undefined && nextKey !== shared.key) {
      if (sharedClients.get(shared.key) === shared) sharedClients.delete(shared.key);
      shared.key = nextKey;
      sharedClients.set(nextKey, shared);
    }
    renderStatus('connecting…');
    return { ok: true, url: settings.url, name: settings.name ?? client.agentId, agentId: client.agentId, channels: Object.keys(cryptoCtx.channels) };
  };
  ctx.registerTool({
    name: 'dap_connect',
    description: "Connect to any DAP hub at runtime (a manual invitation): host (hub.example.com, hub:8787, or ws(s)://…), optional name (display name AND identity — same name = same agent everywhere), optional channel (default room, joined after connect and on every later launch; persisted to ~/.dap/config.json). NOTE: if the room already exists on that hub under another member's key, ask a member to dap_invite you — otherwise you can post but members cannot read you.",
    parameters: {
      type: 'object',
      properties: {
        host: { type: 'string', description: 'hub host[:port] or ws(s):// URL' },
        name: { type: 'string', description: 'agent name (new identity)' },
        channel: { type: 'string', description: 'default room to join after connect' },
      },
    },
    execute: async (_toolCallId, params) => {
      const host = optStr(params.host);
      const name = optStr(params.name);
      const channel = optStr(params.channel);
      if (!host && !name) return toolResult({ ok: false, error: 'host or name required' });
      return toolResult(connectTo(host, name, channel));
    },
  });
  /** The paste-ready connect line for a brand-new user (sent out-of-band). */
  const shareLine = (): string =>
    `send to other user:  /dap ${hostOf(settings.url)} <name>\nfirst connect needs DAP_MASTER_SECRET set (enrolls once, then stored)`;
  /** /dap invite <name|agentId> [channel]: names resolve via presence
   *  (case-insensitive; 16-hex ids pass straight through). A name that is
   *  unknown or offline arms a pending invite — the chankey DM fires
   *  automatically when that name comes online. Sync handler → the async
   *  verdict lands in the footer status and (on failure) a steer — never
   *  swallowed, even headless. */
  const inviteCommand = (args: string[], cmdCtx?: CommandCtx): string => {
    const [who, channelArg] = args;
    if (!who) return shareLine();
    const down = requireConnected();
    if (down) return down.error;
    const channel = channelArg ?? 'general';
    const report = (r: InviteOutcome): void => {
      if (r.ok) renderStatus(`invited ${r.to} to #${r.channel}`);
      else surface(`invite failed: ${r.error}`);
    };
    /** Arm a pending invite: create the channel under our key (same
     *  zero-config path as sendInvite), remember {name, channel}, hand
     *  back the paste-ready connect line for the invitee. */
    const arm = (): void => {
      channelKeysFor(channel);
      if (!pendingInvites.some((p) => p.name.toLowerCase() === who.toLowerCase() && p.channel === channel)) {
        pendingInvites.push({ name: who, channel });
        persistInvites();
      }
      const line = `send to ${who}:  /dap ${hostOf(settings.url)} ${who}`;
      cmdCtx?.ui?.notify(line, 'info');
      pollPending(); // arm-time check: the name may have connected just now
    };
    if (/^[0-9a-f]{16}$/.test(who)) {
      void sendInvite(channel, who).then(report, (err: unknown) => surface(`invite failed: ${String(err)}`));
    } else {
      const wanted = who.toLowerCase();
      void client
        .presence()
        .then((agents) => {
          const matches = agents.filter((a) => a.name?.toLowerCase() === wanted);
          if (matches.length === 1 && matches[0].online) return void sendInvite(channel, matches[0].agentId).then(report);
          if (matches.length > 1)
            return surface(`invite failed: "${who}" is ambiguous — use an id: ${matches.map((m) => m.agentId).join(', ')}`);
          arm(); // unknown or offline: not an error — invite on arrival
        })
        .catch((err: unknown) => surface(`invite failed: ${String(err)}`));
    }
    return `inviting ${who} to #${channel}…`;
  };
  const dispatchDap = (args: string, cmdCtx?: CommandCtx): string => {
    const parts = args.trim().split(/\s+/).filter(Boolean);
    if (parts[0] === 'invite') return inviteCommand(parts.slice(1), cmdCtx);
    const [host, name, channel] = parts;
    if (!host) return `current: ${settings.url}${settings.name ? ' as ' + settings.name : ''}\n${shareLine()}`;
    return JSON.stringify(connectTo(optStr(host), optStr(name), optStr(channel)));
  };
  ctx.registerCommand?.('dap', {
    description:
      '/dap <host[:port]|ws(s)://…> [name] [channel] — connect to a DAP hub; /dap invite — print the connect line to share with a new user; /dap invite <name|agentId> [channel] — DM them the channel keypair (a name not yet online is invited automatically when they connect)',
    handler: (args: string, cmdCtx?: CommandCtx): string => {
      const out = dispatchDap(args, cmdCtx);
      // omp discards handler return values — the line must go through the UI.
      cmdCtx?.ui?.notify(out, 'info');
      return out;
    },
  });
  ctx.registerCommand?.('dap_status', {
    description: '/dap_status — own DAP connection status (agentId, name, hub url, channels, welcome/hello counts)',
    handler: (_args: string, cmdCtx?: CommandCtx): string => {
      const out = JSON.stringify(statusPayload());
      cmdCtx?.ui?.notify(out, 'info');
      return out;
    },
  });
  ctx.registerCommand?.('dap_peers', {
    description: '/dap_peers — online agents on the hub (own entry marked self)',
    handler: (_args: string, cmdCtx?: CommandCtx): string => {
      const down = requireConnected();
      if (down) {
        cmdCtx?.ui?.notify(down.error, 'error');
        return down.error;
      }
      void onlinePeers()
        .then((agents) => {
          const rows = agents
            .map((a) => `on ${a.agentId}${a.name ? ' ' + a.name : ''}${a.self ? ' (self)' : ''}`)
            .join('\n');
          const out = rows || 'no agents online';
          cmdCtx?.ui?.notify(out, 'info');
        })
        .catch((err: unknown) => cmdCtx?.ui?.notify(`peers failed: ${String(err)}`, 'error'));
      // omp discards handler return values — the verdict goes through the UI.
      return 'listing online agents…';
    },
  });
  const dispose = (): void => {
    offMessage(); // dead sessions must not keep receiving (or steering) frames
    if (pollerHandle !== undefined) pollerCtx?.clearTimer(pollerHandle);
    pollerHandle = undefined;
    if (shared === undefined) {
      client.stop();
      return;
    }
    if (--shared.refs > 0) return; // another session still holds this client
    // Last session out: stop the socket; reclaim only the map slot we own
    // (a retarget may have re-keyed it to a fresh identity).
    if (sharedClients.get(shared.key) === shared) sharedClients.delete(shared.key);
    client.stop();
  };
  // Clean exit: closing the socket lets the hub deregister immediately
  // (identity + mailbox survive for offline DMs).
  ctx.on('session_shutdown', dispose);
  if (created) client.connect(); // a reused client is already connected
  return { client, inbox, dispose };
}
