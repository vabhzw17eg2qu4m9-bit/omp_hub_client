import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import dapExtension, { type DapExtension } from '../src/index.js';
import { agentIdFor, b64, canonicalJSON, loadOrCreateKeys, unb64 } from '../src/crypto.js';
import { persistDapConfig, readDapConfig, resolveDapSettings } from '../src/config.js';
import { loadChannelKeys, newChannelKeypair } from '../src/channels.js';
import { DapClient, type MsgFrame, type Timers } from '../src/conn.js';
import type { CommandCtx, ExtensionAPI, SendMessageOptions, SessionCtx, ToolDefinition } from '../src/types.js';
import { FakeHub } from './fake-hub.js';

const KEYDIR = fs.mkdtempSync(path.join(os.tmpdir(), 'dap-omp-test-'));
let keySeq = 0;
const nextKeyPath = (): string => path.join(KEYDIR, 'key-' + ++keySeq + '.json');

// Determinism: pin HOME (defaults resolve under KEYDIR) and clear any DAP_*
// env leaked in from the machine running the tests.
process.env.HOME = KEYDIR;
const DAP_ENV_KEYS = ['DAP_HUB_URL', 'DAP_KEY_PATH', 'DAP_AGENT_NAME', 'DAP_CHANNELS_FILE', 'DAP_CLIENT_SECRET', 'DAP_MASTER_SECRET'];
const savedEnv = Object.fromEntries(DAP_ENV_KEYS.map((k) => [k, process.env[k]]));
for (const k of DAP_ENV_KEYS) delete process.env[k];

test.after(() => {
  for (const [k, v] of Object.entries(savedEnv)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  fs.rmSync(KEYDIR, { recursive: true, force: true });
});

/** Wait for the next emission of `event` after this call — race-free. */
function nextEvent<T>(client: DapClient, event: string): Promise<T> {
  return client.waitForAfter<T>(event, client.eventCount(event));
}

/** Wait until `event` has fired at least `n` times. Wire frames can batch
 *  into one macrotask, so a nextEvent registered after a prior await can
 *  miss emissions that already landed. */
async function eventCountAtLeast(client: DapClient, event: string, n: number): Promise<void> {
  while (client.eventCount(event) < n) await client.waitForAfter(event, client.eventCount(event));
}

/** Macrotask-boundary drain: every pending microtask continuation (e.g. an
 *  in-flight delivery pass) settles before the next test step. */
async function microtasksSettled(): Promise<void> {
  const { promise, resolve } = Promise.withResolvers<void>();
  setImmediate(resolve);
  await promise;
}

interface CapturedCommand {
  description: string;
  handler: (args: string, cmdCtx?: CommandCtx) => string;
}

interface Captured {
  ctx: ExtensionAPI;
  tools: Map<string, ToolDefinition>;
  commands: Map<string, CapturedCommand>;
  sent: { msg: string; opts: SendMessageOptions | undefined }[];
  entries: { type: string; data: unknown }[];
  labels: string[];
  fire(event: string, sctx: SessionCtx): void;
}

/** Fake ExtensionAPI matching the real omp surface exactly. */
function fakeCtx(): Captured {
  const tools = new Map<string, ToolDefinition>();
  const sent: Captured['sent'] = [];
  const entries: Captured['entries'] = [];
  const labels: string[] = [];
  const handlers = new Map<string, (event: unknown, ctx: SessionCtx) => void | Promise<void>>();
  const commands = new Map<string, CapturedCommand>();
  const ctx: ExtensionAPI = {
    registerTool: (tool) => void tools.set(tool.name, tool),
    sendMessage: (msg, opts) => void sent.push({ msg, opts }),
    appendEntry: (type, data) => void entries.push({ type, data }),
    setLabel: (label) => void labels.push(label),
    on: (event, handler) => void handlers.set(event, handler),
    registerCommand: (name, def) => void commands.set(name, def),
  };
  return {
    ctx,
    tools,
    sent,
    entries,
    labels,
    commands,
    fire: (event, sctx) => void handlers.get(event)?.(event, sctx),
  };
}

/** Deterministic stand-in for setInterval: tests fire due callbacks manually. */
class ManualTimers {
  private readonly tasks = new Map<number, () => void>();
  private next = 1;
  readonly timers: Timers = {
    setInterval: (fn) => {
      const id = this.next++;
      this.tasks.set(id, fn);
      return id;
    },
    clearInterval: (h) => void this.tasks.delete(h as number),
  };
  fireAll(): void {
    for (const fn of [...this.tasks.values()]) fn();
  }
}

const tool = (c: Captured, name: string): ToolDefinition => {
  const t = c.tools.get(name);
  assert.ok(t, 'tool not registered: ' + name);
  return t;
};

const command = (c: Captured, name: string): CapturedCommand => {
  const cmd = c.commands.get(name);
  assert.ok(cmd, 'command not registered: ' + name);
  return cmd;
};

/** Invoke a registered tool the way omp does: execute(toolCallId, params);
 *  returns the details field of the AgentToolResult. */
const run = async <T>(c: Captured, name: string, params: Record<string, unknown> = {}): Promise<T> =>
  (await tool(c, name).execute('test-call-id', params)).details as T;

const lastEntry = <T>(c: Captured): T => c.entries.at(-1)!.data as T;

test('canonicalJSON: sorted keys, no whitespace, no HTML escaping (Go SetEscapeHTML(false) parity)', () => {
  assert.equal(canonicalJSON({ b: 1, a: [{ z: true, y: null }] }), '{"a":[{"y":null,"z":true}],"b":1}');
  assert.equal(canonicalJSON({ s: '<&>»' }), '{"s":"<&>»"}', 'no \\u003c-style escaping');
});

test('hello handshake: signed hello -> welcome, key file created 0600', async () => {
  const hub = await new FakeHub().listen();
  const keyPath = nextKeyPath();
  const cap = fakeCtx();
  const ext = dapExtension(cap.ctx, { url: hub.url, keyPath, name: 'tester <&>' });
  try {
    const welcome = await nextEvent<{ agentId: string }>(ext.client, 'welcome');

    const keys = loadOrCreateKeys(keyPath);
    const expectedId = agentIdFor(keys.pub);
    assert.equal(welcome.agentId, expectedId);
    assert.equal(ext.client.agentId, expectedId);
    assert.ok(hub.agents.has(expectedId), 'hub registered the agent');
    assert.ok(hub.log.includes('hello-verified:' + expectedId), 'hub verified the signature');
    assert.equal(fs.statSync(keyPath).mode & 0o777, 0o600, 'key file mode 0600');
  } finally {
    ext.dispose();
    await hub.close();
  }
});

test('signed channel send accepted; E2E fan-out, hub sees ciphertext only', async () => {
  const hub = await new FakeHub().listen();
  const chan = newChannelKeypair();
  const a = fakeCtx();
  const b = fakeCtx();
  const extA = dapExtension(a.ctx, { url: hub.url, keyPath: nextKeyPath(), channels: { general: chan.pub } });
  const extB = dapExtension(b.ctx, { url: hub.url, keyPath: nextKeyPath(), channelPrivs: { general: chan.priv } });
  try {
    await nextEvent(extA.client, 'welcome');
    await nextEvent(extB.client, 'welcome');
    const text = 'check ignition and may god’s love be with you';

    const inbound = nextEvent<MsgFrame>(extB.client, 'inbound');
    const result = await run<{ ok: boolean; id: string }>(a, 'dap_send', { channel: 'general', text });
    assert.equal(result.ok, true);
    const raw = await inbound;

    assert.equal(hub.verifiedSends.length, 1, 'hub verified the Ed25519 send signature');
    assert.notEqual(raw.ciphertext, Buffer.from(text).toString('base64'));
    assert.ok(!JSON.stringify(hub.verifiedSends).includes(text), 'plaintext never reaches the hub');

    assert.equal(b.sent.length, 1, 'inbound msg steered into the turn');
    assert.match(b.sent[0].msg, /#general/);
    assert.match(b.sent[0].msg, new RegExp(text));
    assert.equal(b.sent[0].opts?.deliverAs, 'steer');
    assert.equal(b.sent[0].opts?.triggerTurn, true, 'triggerTurn wakes an idle agent');
    assert.equal(b.entries.at(-1)!.type, 'io.dap.message', 'namespaced durable entry');
    const entry = lastEntry<{ text: string; channel: string }>(b);
    assert.equal(entry.text, text);
    assert.equal(entry.channel, 'general');
  } finally {
    extA.dispose();
    extB.dispose();
    await hub.close();
  }
});

test('DM decrypt round-trip between two client instances (both directions)', async () => {
  const hub = await new FakeHub().listen();
  const a = fakeCtx();
  const b = fakeCtx();
  const extA = dapExtension(a.ctx, { url: hub.url, keyPath: nextKeyPath(), name: 'alice' });
  const extB = dapExtension(b.ctx, { url: hub.url, keyPath: nextKeyPath(), name: 'bob' });
  try {
    await nextEvent(extA.client, 'welcome');
    await nextEvent(extB.client, 'welcome');

    const inboundB = nextEvent<MsgFrame>(extB.client, 'inbound');
    await run(a, 'dap_dm', { to: extB.client.agentId, text: 'psst, ping' });
    await inboundB;
    assert.equal(b.sent.length, 1);
    assert.match(b.sent[0].msg, /DM/);
    assert.match(b.sent[0].msg, /psst, ping/);
    const dmEntry = lastEntry<{ dm: boolean; text: string }>(b);
    assert.equal(dmEntry.dm, true);
    assert.equal(dmEntry.text, 'psst, ping');
    assert.equal(hub.verifiedSends[0]?.to, extB.client.agentId, 'DM delivered to the recipient only');

    const inboundA = nextEvent(extA.client, 'inbound');
    await run(b, 'dap_dm', { to: extA.client.agentId, text: 'pong' });
    await inboundA;
    assert.match(a.sent[0].msg, /pong/);
  } finally {
    extA.dispose();
    extB.dispose();
    await hub.close();
  }
});

test('hub rejects a send frame with a bad signature', async () => {
  const hub = await new FakeHub().listen();
  const cap = fakeCtx();
  const ext = dapExtension(cap.ctx, { url: hub.url, keyPath: nextKeyPath() });
  try {
    await nextEvent(ext.client, 'welcome');
    const gotError = nextEvent<{ code: string }>(ext.client, 'error');
    ext.client.send({
      op: 'send',
      channel: 'general',
      id: crypto.randomUUID(),
      ts: Date.now(),
      ciphertext: Buffer.from('forged').toString('base64'),
      sig: Buffer.from('not-a-signature').toString('base64'),
    });
    const err = await gotError;
    assert.equal(err.code, 'bad_signature');
    assert.deepEqual(hub.rejected, [{ code: 'bad_signature', agentId: ext.client.agentId }]);
    assert.equal(hub.verifiedSends.length, 0);
  } finally {
    ext.dispose();
    await hub.close();
  }
});

test('reconnect after server drop: setInterval loop, backoff reset on welcome', async () => {
  const hub = await new FakeHub().listen();
  const cap = fakeCtx();
  const clock = new ManualTimers();
  const ext = dapExtension(cap.ctx, { url: hub.url, keyPath: nextKeyPath(), timers: clock.timers });
  try {
    await nextEvent(ext.client, 'welcome');
    assert.equal(ext.client.helloCount, 1);

    const closed = nextEvent(ext.client, 'close');
    hub.drop(ext.client.agentId);
    await closed;
    assert.deepEqual(ext.client.backoffSchedule, [1000], 'first retry scheduled at 1s');

    const welcomed = nextEvent(ext.client, 'welcome');
    clock.fireAll();
    await welcomed;
    assert.equal(ext.client.helloCount, 2, 'hello re-sent on reconnect');
    assert.equal(ext.client.welcomeCount, 2);
    assert.equal(
      hub.log.filter((l) => l === 'hello-verified:' + ext.client.agentId).length,
      2,
      'hub verified both hellos',
    );

    const closedAgain = nextEvent(ext.client, 'close');
    hub.drop(ext.client.agentId);
    await closedAgain;
    assert.deepEqual(ext.client.backoffSchedule, [1000, 1000], 'backoff reset after successful welcome');
  } finally {
    ext.dispose();
    await hub.close();
  }
});

test('backoff doubles 1s..30s cap against a dead endpoint (no real sleeps)', async () => {
  const cap = fakeCtx();
  const clock = new ManualTimers();
  const ext = dapExtension(cap.ctx, { url: 'ws://127.0.0.1:9/ws', keyPath: nextKeyPath(), timers: clock.timers });
  try {
    await nextEvent(ext.client, 'close'); // initial attempt: connection refused
    for (let i = 0; i < 7; i++) {
      const closed = nextEvent(ext.client, 'close');
      clock.fireAll();
      await closed;
    }
    assert.deepEqual(ext.client.backoffSchedule, [1000, 2000, 4000, 8000, 16000, 30000, 30000, 30000]);
  } finally {
    ext.dispose();
  }
});

/** Upgrade-only stub: answers every dial with the hub's pre-Accept 401 and
 *  records each attempt's Authorization header. */
async function deniedHub(): Promise<{ url: string; seen: (string | undefined)[]; close(): Promise<void> }> {
  const server = http.createServer();
  const seen: (string | undefined)[] = [];
  server.on('upgrade', (req, socket) => {
    seen.push(req.headers.authorization);
    socket.write('HTTP/1.1 401 Unauthorized\r\nContent-Length: 12\r\n\r\nunauthorized');
    socket.destroy();
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as { port: number }).port;
  return {
    url: 'ws://127.0.0.1:' + port + '/ws',
    seen,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

test('dial carries Authorization: Bearer (clientSecret, or DAP_MASTER_SECRET in enroll mode)', async () => {
  const hub = await deniedHub();
  let c = new DapClient({ url: hub.url, keys: loadOrCreateKeys(nextKeyPath()), clientSecret: 'client-secret-1' });
  try {
    const denied = nextEvent(c, 'denied');
    c.connect();
    await denied;
    c.stop(); // within the 1s backoff window: no second dial
    assert.deepEqual(hub.seen, ['Bearer client-secret-1']);

    process.env.DAP_MASTER_SECRET = 'master-secret-1';
    c = new DapClient({ url: hub.url, keys: loadOrCreateKeys(nextKeyPath()) });
    const denied2 = nextEvent(c, 'denied');
    c.connect();
    await denied2;
    assert.deepEqual(hub.seen, ['Bearer client-secret-1', 'Bearer master-secret-1'], 'master secret dials in enroll mode');
  } finally {
    delete process.env.DAP_MASTER_SECRET;
    c.stop();
    await hub.close();
  }
});

test('token precedence: DAP_CLIENT_SECRET env beats the persisted config clientSecret', async () => {
  const hub = await deniedHub();
  const cfgFile = path.join(KEYDIR, 'cfg-tok-' + ++keySeq + '.json');
  fs.writeFileSync(cfgFile, JSON.stringify({ clientSecret: 'from-config' }));
  const prevCfg = process.env.DAP_CONFIG_FILE;
  const prevEnv = process.env.DAP_CLIENT_SECRET;
  process.env.DAP_CONFIG_FILE = cfgFile;
  process.env.DAP_CLIENT_SECRET = 'from-env';
  const clock = new ManualTimers();
  let ext = dapExtension(fakeCtx().ctx, { url: hub.url, keyPath: nextKeyPath(), timers: clock.timers });
  try {
    await nextEvent(ext.client, 'denied');
    assert.equal(hub.seen[0], 'Bearer from-env', 'env beats config file');
    ext.dispose();
    delete process.env.DAP_CLIENT_SECRET;
    ext = dapExtension(fakeCtx().ctx, { url: hub.url, keyPath: nextKeyPath(), timers: clock.timers });
    await nextEvent(ext.client, 'denied');
    assert.equal(hub.seen[1], 'Bearer from-config', 'persisted clientSecret used when env is silent');
  } finally {
    if (prevCfg === undefined) delete process.env.DAP_CONFIG_FILE;
    else process.env.DAP_CONFIG_FILE = prevCfg;
    if (prevEnv === undefined) delete process.env.DAP_CLIENT_SECRET;
    else process.env.DAP_CLIENT_SECRET = prevEnv;
    ext.dispose();
    await hub.close();
  }
});

test('headerless dial: hub 401 surfaces the frozen error text (once per streak)', async () => {
  const hub = await deniedHub();
  const cap = fakeCtx();
  const clock = new ManualTimers();
  const ext = dapExtension(cap.ctx, { url: hub.url, keyPath: nextKeyPath(), timers: clock.timers });
  try {
    const denied = nextEvent(ext.client, 'denied');
    const closed1 = nextEvent(ext.client, 'close'); // pre-registered: close follows denied in the same burst
    await denied;
    await closed1; // close armed the reconnect timer
    clock.fireAll(); // dial 2
    await nextEvent(ext.client, 'close');
    clock.fireAll(); // dial 3
    await nextEvent(ext.client, 'close');
    assert.deepEqual(hub.seen, [undefined, undefined, undefined], 'no secrets: headerless dials');
    assert.deepEqual(cap.sent.map((s) => s.msg), [
      '[dap] hub rejected connection (HTTP 401): set DAP_MASTER_SECRET to enroll, or DAP_CLIENT_SECRET / config clientSecret to connect',
    ]);
  } finally {
    ext.dispose();
    await hub.close();
  }
});

test('auto-enroll: master dial -> {"t":"enroll"} -> issued secret persisted and reused on reconnect', async () => {
  const hub = await new FakeHub({ masterSecret: 'master-enroll-token' }).listen();
  const cfgFile = path.join(KEYDIR, 'cfg-enroll-' + ++keySeq + '.json');
  const prevCfg = process.env.DAP_CONFIG_FILE;
  const prevMaster = process.env.DAP_MASTER_SECRET;
  process.env.DAP_CONFIG_FILE = cfgFile;
  process.env.DAP_MASTER_SECRET = 'master-enroll-token';
  const cap = fakeCtx();
  const clock = new ManualTimers();
  const ext = dapExtension(cap.ctx, { url: hub.url, keyPath: nextKeyPath(), name: 'enrollee', timers: clock.timers });
  try {
    const enrolled = nextEvent<{ secret: string }>(ext.client, 'enrolled');
    await nextEvent(ext.client, 'welcome');
    const { secret } = await enrolled;
    assert.deepEqual(hub.enrollRequests, [ext.client.agentId], 'enroll only after hello, master-auth only');
    assert.equal(readDapConfig(cfgFile).clientSecret, secret, 'issued secret persisted to DAP_CONFIG_FILE');
    assert.ok(!fs.readFileSync(cfgFile, 'utf8').includes('master-enroll-token'), 'master secret never persisted');
    assert.ok(!JSON.stringify(cap.sent).includes(secret), 'secret never surfaces in messages');

    // Reconnect: the issued secret rides the dial; no second enroll.
    const closed = nextEvent(ext.client, 'close');
    hub.drop(ext.client.agentId);
    await closed;
    const welcome2 = nextEvent(ext.client, 'welcome');
    clock.fireAll();
    await welcome2;
    assert.deepEqual(hub.upgrades, ['master-enroll-token', secret], 'reconnect used the issued secret');
    assert.deepEqual(hub.enrollRequests, [ext.client.agentId], 'no re-enroll with the client secret');
  } finally {
    if (prevCfg === undefined) delete process.env.DAP_CONFIG_FILE;
    else process.env.DAP_CONFIG_FILE = prevCfg;
    if (prevMaster === undefined) delete process.env.DAP_MASTER_SECRET;
    else process.env.DAP_MASTER_SECRET = prevMaster;
    ext.dispose();
    await hub.close();
  }
});

test('stale config clientSecret: 401 wipes the cache, ONE enroll-mode retry re-persists (identity unchanged)', async () => {
  const hub = await new FakeHub({ masterSecret: 'master-stale-1' }).listen();
  const cfgFile = path.join(KEYDIR, 'cfg-stale-' + ++keySeq + '.json');
  // The stale cache carries other fields too — the wipe must keep them.
  fs.writeFileSync(cfgFile, JSON.stringify({ url: 'ws://keep:9/ws', clientSecret: 'stale-cfg-secret' }));
  const prevCfg = process.env.DAP_CONFIG_FILE;
  const prevMaster = process.env.DAP_MASTER_SECRET;
  process.env.DAP_CONFIG_FILE = cfgFile;
  process.env.DAP_MASTER_SECRET = 'master-stale-1';
  const clock = new ManualTimers();
  const c = new DapClient({
    url: hub.url,
    keys: loadOrCreateKeys(nextKeyPath()),
    clientSecret: 'stale-cfg-secret',
    clientSecretSource: 'config',
    timers: clock.timers,
  });
  try {
    const agentId = c.agentId;
    const closed1 = nextEvent(c, 'close');
    const enrolled = nextEvent<{ secret: string }>(c, 'enrolled');
    const welcome = nextEvent<{ agentId: string }>(c, 'welcome');
    c.connect();
    await closed1; // dial 1: stale bearer 401'd, escalation armed (no 'denied' yet)
    clock.fireAll(); // dial 2: master bearer in enroll-mode
    await welcome;
    const { secret } = await enrolled; // hub processed the enroll frame
    assert.equal(c.agentId, agentId, 'identity unchanged across re-enroll');
    assert.deepEqual(hub.upgrades, ['stale-cfg-secret', 'master-stale-1'], 'stale bearer rejected, exactly one master retry');
    assert.deepEqual(hub.enrollRequests, [agentId], 'retry enrolled the SAME identity');
    const saved = JSON.parse(fs.readFileSync(cfgFile, 'utf8')) as { url?: string; clientSecret?: string };
    assert.equal(saved.url, 'ws://keep:9/ws', 'other config fields survive the wipe');
    const reissued = saved.clientSecret;
    assert.equal(reissued, secret, 'fresh secret persisted, stale one gone');
  } finally {
    if (prevCfg === undefined) delete process.env.DAP_CONFIG_FILE;
    else process.env.DAP_CONFIG_FILE = prevCfg;
    if (prevMaster === undefined) delete process.env.DAP_MASTER_SECRET;
    else process.env.DAP_MASTER_SECRET = prevMaster;
    c.stop();
    await hub.close();
  }
});

test('env-sourced clientSecret: 401 is fatal, config untouched', async () => {
  const hub = await deniedHub();
  const cfgFile = path.join(KEYDIR, 'cfg-env401-' + ++keySeq + '.json');
  fs.writeFileSync(cfgFile, JSON.stringify({ url: 'ws://keep:9/ws', clientSecret: 'from-config' }));
  const prevCfg = process.env.DAP_CONFIG_FILE;
  const prevEnv = process.env.DAP_CLIENT_SECRET;
  process.env.DAP_CONFIG_FILE = cfgFile;
  process.env.DAP_CLIENT_SECRET = 'from-env';
  const clock = new ManualTimers();
  const c = new DapClient({
    url: hub.url,
    keys: loadOrCreateKeys(nextKeyPath()),
    clientSecret: 'from-env',
    clientSecretSource: 'env',
    timers: clock.timers,
  });
  try {
    const denied = nextEvent(c, 'denied');
    const closed1 = nextEvent(c, 'close');
    c.connect();
    await denied; // hard fail on the FIRST 401: env secret is explicit user intent
    await closed1;
    clock.fireAll();
    await nextEvent(c, 'close'); // dial 2 retries the env token, still no recovery
    assert.deepEqual(hub.seen, ['Bearer from-env', 'Bearer from-env'], 'no escalation: env secret never swapped for master');
    assert.equal(c.eventCount('denied'), 1);
    assert.deepEqual(JSON.parse(fs.readFileSync(cfgFile, 'utf8')), { url: 'ws://keep:9/ws', clientSecret: 'from-config' }, 'config cache untouched');
  } finally {
    if (prevCfg === undefined) delete process.env.DAP_CONFIG_FILE;
    else process.env.DAP_CONFIG_FILE = prevCfg;
    if (prevEnv === undefined) delete process.env.DAP_CLIENT_SECRET;
    else process.env.DAP_CLIENT_SECRET = prevEnv;
    c.stop();
    await hub.close();
  }
});

test('config-sourced clientSecret, no master: 401 hard-fails, cache kept', async () => {
  const hub = await deniedHub();
  const cfgFile = path.join(KEYDIR, 'cfg-nomaster-' + ++keySeq + '.json');
  fs.writeFileSync(cfgFile, JSON.stringify({ clientSecret: 'from-config' }));
  const prevCfg = process.env.DAP_CONFIG_FILE;
  process.env.DAP_CONFIG_FILE = cfgFile; // no DAP_MASTER_SECRET anywhere
  const clock = new ManualTimers();
  const c = new DapClient({
    url: hub.url,
    keys: loadOrCreateKeys(nextKeyPath()),
    clientSecret: 'from-config',
    clientSecretSource: 'config',
    timers: clock.timers,
  });
  try {
    const denied = nextEvent(c, 'denied');
    const closed1 = nextEvent(c, 'close');
    c.connect();
    await denied; // nothing to escalate to: today's fatal verdict
    await closed1;
    clock.fireAll();
    await nextEvent(c, 'close');
    assert.deepEqual(hub.seen, ['Bearer from-config', 'Bearer from-config'], 'cache secret not wiped without a master to re-enroll with');
    assert.equal(c.eventCount('denied'), 1);
    assert.equal(readDapConfig(cfgFile).clientSecret, 'from-config', 'stale cache kept (may still be valid elsewhere)');
  } finally {
    if (prevCfg === undefined) delete process.env.DAP_CONFIG_FILE;
    else process.env.DAP_CONFIG_FILE = prevCfg;
    c.stop();
    await hub.close();
  }
});

test('stale config clientSecret: enroll retry also 401s -> fatal once, no loop', async () => {
  const hub = await deniedHub(); // rejects EVERY bearer, records each header
  const cfgFile = path.join(KEYDIR, 'cfg-stale2-' + ++keySeq + '.json');
  fs.writeFileSync(cfgFile, JSON.stringify({ clientSecret: 'stale-cfg-secret' }));
  const prevCfg = process.env.DAP_CONFIG_FILE;
  const prevMaster = process.env.DAP_MASTER_SECRET;
  process.env.DAP_CONFIG_FILE = cfgFile;
  process.env.DAP_MASTER_SECRET = 'master-stale-2';
  const clock = new ManualTimers();
  const c = new DapClient({
    url: hub.url,
    keys: loadOrCreateKeys(nextKeyPath()),
    clientSecret: 'stale-cfg-secret',
    clientSecretSource: 'config',
    timers: clock.timers,
  });
  try {
    const denied = nextEvent(c, 'denied');
    const closed1 = nextEvent(c, 'close');
    c.connect();
    await closed1; // dial 1: stale bearer 401'd, escalation armed silently
    clock.fireAll(); // dial 2: master bearer -> 401 again -> fatal
    await denied;
    clock.fireAll(); // dial 3: still enroll-mode, no second escalation
    await nextEvent(c, 'close');
    assert.deepEqual(hub.seen, ['Bearer stale-cfg-secret', 'Bearer master-stale-2', 'Bearer master-stale-2'], 'exactly one escalation; loop stays enroll-mode');
    assert.equal(c.eventCount('denied'), 1, 'fatal verdict surfaces once');
    assert.deepEqual(readDapConfig(cfgFile), { invites: [] }, 'stale cache stays wiped');
  } finally {
    if (prevCfg === undefined) delete process.env.DAP_CONFIG_FILE;
    else process.env.DAP_CONFIG_FILE = prevCfg;
    if (prevMaster === undefined) delete process.env.DAP_MASTER_SECRET;
    else process.env.DAP_MASTER_SECRET = prevMaster;
    c.stop();
    await hub.close();
  }
});

test('retarget does not self-evict: stale socket close is inert (the /dap host name bug)', async () => {
  const hub = await new FakeHub().listen();
  // Reconnect-interval capture: after retarget settles, NOTHING may be scheduled
  // (the bug scheduled a reconnect from the old socket's late 'close' event).
  const scheduled: { fn: () => void }[] = [];
  const timers: Timers = {
    setInterval: (fn) => {
      const t = { fn };
      scheduled.push(t);
      return t;
    },
    clearInterval: (h) => {
      const i = scheduled.indexOf(h as { fn: () => void });
      if (i >= 0) scheduled.splice(i, 1);
    },
  };
  const client = new DapClient({
    url: hub.url,
    keys: loadOrCreateKeys(nextKeyPath()),
    name: 'original',
    timers,
  });
  try {
    client.connect();
    await eventCountAtLeast(client, 'welcome', 1);

    client.retarget({ keys: loadOrCreateKeys(nextKeyPath()), name: 'renamed' });
    await eventCountAtLeast(client, 'welcome', 2);
    await microtasksSettled();
    await microtasksSettled(); // the old socket's async 'close' must have landed by now

    assert.equal(client.welcomeCount, 2);
    assert.equal(client.helloCount, 2, 'exactly the two real connects helloed');
    assert.ok(!hub.log.some((l) => l.startsWith('evict:')), 'no self-eviction: ' + hub.log.join(' | '));
    assert.equal(scheduled.length, 0, 'stale close schedules no reconnect');
    assert.equal(client.connected, true, 'stale close did not clobber live state');
    const agents = await client.presence(); // the user-visible symptom was this timing out
    assert.ok(agents.some((a) => a.agentId === client.agentId && a.name === 'renamed'), 'renamed agent online');
  } finally {
    client.stop();
    await hub.close();
  }
});

test('offline mailbox: flush after welcome -> steer + durable inbox; inbox/whois tools', async () => {
  const hub = await new FakeHub().listen();
  const a = fakeCtx();
  const aKeyPath = nextKeyPath();
  const bKeyPath = nextKeyPath();
  const extA = dapExtension(a.ctx, { url: hub.url, keyPath: aKeyPath });
  try {
    await nextEvent(extA.client, 'welcome');
    const bKeys = loadOrCreateKeys(bKeyPath);
    const bId = agentIdFor(bKeys.pub);

    // B was online, then went offline -> its bounded mailbox starts queuing.
    const b1 = dapExtension(fakeCtx().ctx, { url: hub.url, keyPath: bKeyPath });
    await nextEvent(b1.client, 'welcome');
    b1.dispose();
    await hub.waitOffline(bId);

    await run(a, 'dap_dm', { to: bId, text: 'while you were out (1)' });
    await run(a, 'dap_dm', { to: bId, text: 'while you were out (2)' });
    await hub.waitVerifiedSends(2);
    assert.equal(hub.mailboxes.get(bId)?.length, 2);
    assert.ok(!JSON.stringify(hub.mailboxes).includes('while you were out'), 'mailbox holds ciphertext only');

    const b2 = fakeCtx();
    const extB = dapExtension(b2.ctx, { url: hub.url, keyPath: bKeyPath });
    try {
      const flushed = await nextEvent<{ count: number }>(extB.client, 'flushed');
      assert.equal(flushed.count, 2, 'mailbox drained in order');
      await extB.client.waitForAfter('inbound', extB.client.eventCount('inbound') + 1);
      assert.equal(b2.sent.length, 2, 'both messages steered in');
      assert.match(b2.sent[0].msg, /while you were out \(1\)/, 'delivered in mailbox order');
      assert.match(b2.sent[1].msg, /while you were out \(2\)/);
      assert.equal(b2.entries.length, 2, 'appendEntry persisted both');

      const inbox = await run<{
        count: number;
        entries: { text: string; dm: boolean; from: string }[];
      }>(b2, 'dap_inbox', { limit: 10 });
      assert.equal(inbox.count, 2);
      assert.deepEqual(
        inbox.entries.map((e) => e.text),
        ['while you were out (2)', 'while you were out (1)'],
        'latest first',
      );
      assert.ok(inbox.entries.every((e) => e.dm && e.from === extA.client.agentId));

      const info = await run<{
        online: boolean;
        pubkey: string;
        x25519: string;
      }>(b2, 'dap_whois', { agentId: extA.client.agentId });
      assert.equal(info.online, true);
      assert.equal(info.pubkey, b64(loadOrCreateKeys(aKeyPath).pub));
      assert.equal(info.x25519, b64(loadOrCreateKeys(aKeyPath).xpub), 'agent_info echoes the x25519 pub');
    } finally {
      extB.dispose();
    }
  } finally {
    extA.dispose();
    await hub.close();
  }
});

test('settings precedence: override > env > ~/.dap/config.json > defaults; channelsFile default ~/.dap/channels.json', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'dap-omp-cfg-'));
  const prevHome = process.env.HOME;
  process.env.HOME = home;
  try {
    // No config file, no env: plain defaults. Identity file is derived from
    // the agent name (hostname when unnamed) — two agents on one machine
    // never collide, and it is auto-generated on first use.
    let s = resolveDapSettings();
    assert.equal(s.url, 'ws://127.0.0.1:8787/ws');
    assert.equal(s.keyPath, path.join(home, '.dap', 'keys', `${os.hostname()}.key`));
    assert.equal(s.channelsFile, path.join(home, '.dap', 'channels.json'));
    assert.equal(s.name, undefined);
    assert.equal(s.clientSecret, undefined);
    assert.equal(s.clientSecretSource, undefined, 'no secret anywhere: master-only/tokenless dial');

    // Config file fills every unset field.
    fs.mkdirSync(path.join(home, '.dap'), { recursive: true });
    const cfgFile = path.join(home, '.dap', 'config.json');
    fs.writeFileSync(
      cfgFile,
      JSON.stringify({ url: 'ws://cfg:1/ws', name: 'cfg-agent', keyPath: '/cfg/key.json', channelsFile: '/cfg/channels.json', clientSecret: 'cfg-secret' }),
    );
    s = resolveDapSettings();
    assert.equal(s.url, 'ws://cfg:1/ws');
    assert.equal(s.name, 'cfg-agent');
    assert.equal(s.keyPath, '/cfg/key.json');
    assert.equal(s.channelsFile, '/cfg/channels.json');
    assert.equal(s.clientSecret, 'cfg-secret');
    assert.equal(s.clientSecretSource, 'config', 'persisted cache is recoverable on 401');

    // Env beats the file; the file still beats the defaults.
    process.env.DAP_HUB_URL = 'ws://env:2/ws';
    process.env.DAP_CHANNELS_FILE = '/env/channels.json';
    s = resolveDapSettings();
    assert.equal(s.url, 'ws://env:2/ws');
    assert.equal(s.channelsFile, '/env/channels.json');
    assert.equal(s.keyPath, '/cfg/key.json', 'file beats default when env is silent');

    // Secret source follows the same precedence: env-cached secret is
    // explicit intent ('env'), the persisted cache is recoverable ('config').
    process.env.DAP_CLIENT_SECRET = 'env-secret';
    s = resolveDapSettings();
    assert.equal(s.clientSecret, 'env-secret');
    assert.equal(s.clientSecretSource, 'env', 'env beats the config cache');
    assert.equal(resolveDapSettings({ clientSecret: 'ov-secret' }).clientSecretSource, 'env', 'explicit override is user intent too');
    delete process.env.DAP_CLIENT_SECRET;

    // Explicit override beats env.
    assert.equal(resolveDapSettings({ url: 'ws://ov:3/ws' }).url, 'ws://ov:3/ws');

    // An invalid config file counts as absent.
    fs.writeFileSync(cfgFile, '{not json');
    delete process.env.DAP_HUB_URL;
    delete process.env.DAP_CHANNELS_FILE;
    s = resolveDapSettings();
    assert.equal(s.url, 'ws://127.0.0.1:8787/ws');
    assert.equal(s.channelsFile, path.join(home, '.dap', 'channels.json'));
  } finally {
    process.env.HOME = prevHome;
    delete process.env.DAP_HUB_URL;
    delete process.env.DAP_CHANNELS_FILE;
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('auto-keygen: send to an unknown channel persists keys; a second instance joins and decrypts', async () => {
  const hub = await new FakeHub().listen();
  const channelsFile = path.join(KEYDIR, 'auto-keygen-' + ++keySeq + '.json');
  const a = fakeCtx();
  const b = fakeCtx();
  const extA = dapExtension(a.ctx, { url: hub.url, keyPath: nextKeyPath(), channelsFile });
  try {
    await nextEvent(extA.client, 'welcome');

    // First-ever use of #general: keygen + persist + join, then the send works.
    const joinedGeneral = nextEvent<{ channel: string }>(extA.client, 'joined');
    const result = await run<{ ok: boolean }>(a, 'dap_send', { channel: 'general', text: 'zero config' });
    assert.equal(result.ok, true);
    assert.equal((await joinedGeneral).channel, 'general');
    // A second unknown channel: read-modify-write keeps the first one.
    const joinedRandom = nextEvent<{ channel: string }>(extA.client, 'joined');
    await run(a, 'dap_send', { channel: 'random', text: 'still zero config' });
    assert.equal((await joinedRandom).channel, 'random');
    const saved = loadChannelKeys(channelsFile);
    assert.deepEqual(Object.keys(saved), ['general', 'random']);
    assert.equal(unb64(saved.general.pub).length, 32, 'x25519 public key persisted');
    assert.equal(unb64(saved.general.priv).length, 32, 'x25519 private key persisted');
    assert.ok(hub.channelMembers.get('general')?.has(extA.client.agentId), 'creator joined');

    // Fresh factory, same channels file: picks the keys up with zero config.
    const extB = dapExtension(b.ctx, { url: hub.url, keyPath: nextKeyPath(), channelsFile });
    try {
      await nextEvent(extB.client, 'welcome');
      await nextEvent(extB.client, 'joined'); // auto-joined #general + #random from the file
      assert.ok(hub.channelMembers.get('general')?.has(extB.client.agentId));

      const inbound = nextEvent<MsgFrame>(extB.client, 'inbound');
      await run(a, 'dap_send', { channel: 'general', text: 'second message' });
      await inbound;
      assert.equal(b.sent.length, 1, 'B decrypted the channel message');
      assert.match(b.sent[0].msg, /#general/);
      assert.match(b.sent[0].msg, /second message/);
    } finally {
      extB.dispose();
    }
  } finally {
    extA.dispose();
    await hub.close();
  }
});

test('invite: A auto-creates #general, dap_invite DMs the chankey to B; B joins and decrypts later sends', async () => {
  const hub = await new FakeHub().listen();
  const fileA = path.join(KEYDIR, 'invite-a-' + ++keySeq + '.json');
  const fileB = path.join(KEYDIR, 'invite-b-' + ++keySeq + '.json');
  fs.writeFileSync(fileB, '{}'); // B literally starts with an empty channels file
  const a = fakeCtx();
  const b = fakeCtx();
  const extA = dapExtension(a.ctx, { url: hub.url, keyPath: nextKeyPath(), channelsFile: fileA, name: 'alice' });
  const extB = dapExtension(b.ctx, { url: hub.url, keyPath: nextKeyPath(), channelsFile: fileB, name: 'bob' });
  try {
    await nextEvent(extA.client, 'welcome');
    await nextEvent(extB.client, 'welcome');
    assert.equal(Object.keys(loadChannelKeys(fileB)).length, 0, 'B holds no channel keys yet');

    // dap_invite on a channel A doesn't hold yet: zero-config creation inlined.
    const joinedA = nextEvent<{ channel: string }>(extA.client, 'joined');
    const invite = await run<{ ok: boolean }>(a, 'dap_invite', { channel: 'general', to: extB.client.agentId });
    assert.equal(invite.ok, true);
    assert.equal((await joinedA).channel, 'general', 'A created + joined #general');
    assert.ok(loadChannelKeys(fileA).general?.pub, 'creator keypair persisted');
    await nextEvent(extB.client, 'inbound'); // invite DM fully processed (deterministic)
    await nextEvent(extB.client, 'joined');

    assert.equal(b.sent.length, 1, 'one steer so far: the invite notice');
    assert.ok(
      b.sent[0].msg.includes('[dap] invited to #general by ' + extA.client.agentId),
      'notice text: ' + b.sent[0].msg,
    );
    assert.equal(b.sent[0].opts?.deliverAs, 'steer');
    assert.equal(b.entries.length, 0, 'chankey DM is not chat: no inbox entry');
    assert.equal(
      loadChannelKeys(fileB).general?.pub,
      loadChannelKeys(fileA).general?.pub,
      'B persisted the invited keypair',
    );
    assert.ok(hub.channelMembers.get('general')?.has(extB.client.agentId), 'B joined after the invite');

    // The actual payload the hub routed was ciphertext-wrapped JSON over E2E DM.
    const dmSend = hub.verifiedSends.find((f) => f.to === extB.client.agentId);
    assert.ok(dmSend && !dmSend.ciphertext.includes('chankey'), 'hub never sees the invite plaintext');

    const inbound = nextEvent<MsgFrame>(extB.client, 'inbound');
    await run(a, 'dap_send', { channel: 'general', text: 'welcome aboard' });
    await inbound;
    assert.match(b.sent.at(-1)!.msg, /#general/);
    assert.match(b.sent.at(-1)!.msg, /welcome aboard/);
  } finally {
    extA.dispose();
    extB.dispose();
    await hub.close();
  }
});

test('/dap invite: name (case-insensitive) and agentId forms share the tool path; B gets the chankey DM, joins, persists', async () => {
  const hub = await new FakeHub().listen();
  const fileA = path.join(KEYDIR, 'cmd-invite-a-' + ++keySeq + '.json');
  const fileB = path.join(KEYDIR, 'cmd-invite-b-' + ++keySeq + '.json');
  fs.writeFileSync(fileB, '{}'); // B starts with an empty channels file
  const a = fakeCtx();
  const b = fakeCtx();
  const extA = dapExtension(a.ctx, { url: hub.url, keyPath: nextKeyPath(), channelsFile: fileA, name: 'alice' });
  const extB = dapExtension(b.ctx, { url: hub.url, keyPath: nextKeyPath(), channelsFile: fileB, name: 'bob' });
  try {
    await nextEvent(extA.client, 'welcome');
    await nextEvent(extB.client, 'welcome');
    const dap = command(a, 'dap');

    // Display-name form, wrong case on purpose: presence resolves it, channel defaults to general.
    const joinedA = nextEvent<{ channel: string }>(extA.client, 'joined');
    assert.match(dap.handler('invite BoB'), /inviting BoB to #general…/);
    assert.equal((await joinedA).channel, 'general', 'A zero-config created + joined #general');
    await nextEvent(extB.client, 'inbound'); // chankey DM fully processed (deterministic)
    await nextEvent(extB.client, 'joined');
    assert.equal(loadChannelKeys(fileB).general?.pub, loadChannelKeys(fileA).general?.pub, 'B persisted the invited keypair');
    assert.ok(hub.channelMembers.get('general')?.has(extB.client.agentId), 'B auto-joined after the invite');
    assert.ok(b.sent.some((s) => s.msg.includes('[dap] invited to #general by ' + extA.client.agentId)), 'invite notice steered');
    const dmSend = hub.verifiedSends.find((f) => f.to === extB.client.agentId);
    assert.ok(dmSend && !dmSend.ciphertext.includes('chankey'), 'ciphertext only on the wire');

    // agentId form, explicit channel: same shared invite path.
    const joinedTeam = nextEvent<{ channel: string }>(extA.client, 'joined');
    assert.match(dap.handler(`invite ${extB.client.agentId} team`), /inviting/);
    assert.equal((await joinedTeam).channel, 'team');
    await nextEvent(extB.client, 'inbound');
    await nextEvent(extB.client, 'joined');
    assert.ok(hub.channelMembers.get('team')?.has(extB.client.agentId), 'B joined #team via agentId invite');
  } finally {
    extA.dispose();
    extB.dispose();
    await hub.close();
  }
});

test('/dap invite (no args) and bare /dap: print the paste-ready connect line (host from ws URL, <name> placeholder)', async () => {
  const hub = await new FakeHub().listen();
  const cap = fakeCtx();
  const cfgFile = path.join(KEYDIR, 'cfg-share-' + ++keySeq + '.json');
  const prevCfgEnv = process.env.DAP_CONFIG_FILE;
  process.env.DAP_CONFIG_FILE = cfgFile;
  const ext = dapExtension(cap.ctx, { url: hub.url, keyPath: nextKeyPath(), name: 'sharer' });
  try {
    await nextEvent(ext.client, 'welcome');
    const dap = command(cap, 'dap');
    const line =
      `send to other user:  /dap 127.0.0.1:${hub.port} <name>\n` + // ws://…/ws stripped to host:port
      'first connect needs DAP_MASTER_SECRET set (enrolls once, then stored)';
    assert.equal(dap.handler('invite'), line);
    // omp discards handler return values — the share line must arrive via cmdCtx.ui.notify.
    const notified: string[] = [];
    dap.handler('invite', { ui: { notify: (text: string) => void notified.push(text) }, hasUI: true });
    assert.deepEqual(notified, [line]);

    fs.writeFileSync(cfgFile, JSON.stringify({ channels: ['ops'] }));
    assert.equal(dap.handler('invite'), line, 'line carries no room — config channels do not change it');
  } finally {
    if (prevCfgEnv === undefined) delete process.env.DAP_CONFIG_FILE;
    else process.env.DAP_CONFIG_FILE = prevCfgEnv;
    ext.dispose();
    await hub.close();
  }
});

test('/dap invite <unknown name>: arms a pending invite, prints the connect line, persists to config (deduped)', async () => {
  const hub = await new FakeHub().listen();
  const cap = fakeCtx();
  const cfgFile = path.join(KEYDIR, 'cfg-pending-' + ++keySeq + '.json');
  const chFile = path.join(KEYDIR, 'ch-pending-' + keySeq + '.json');
  const prevCfgEnv = process.env.DAP_CONFIG_FILE;
  process.env.DAP_CONFIG_FILE = cfgFile;
  const ext = dapExtension(cap.ctx, { url: hub.url, keyPath: nextKeyPath(), channelsFile: chFile, name: 'inviter' });
  try {
    await nextEvent(ext.client, 'welcome');
    const dap = command(cap, 'dap');
    const notices: string[] = [];
    const cmdCtx = { ui: { notify: (t: string) => void notices.push(t) }, hasUI: true };
    // The arm settles via its side effects: the join (channel auto-created)
    // and the arm-time delivery check's presence round-trip.
    const joined = nextEvent<{ channel: string }>(ext.client, 'joined');
    const presenceBefore = ext.client.eventCount('presence');
    assert.match(dap.handler('invite carol', cmdCtx), /inviting carol to #general…/);
    assert.equal((await joined).channel, 'general', 'channel auto-created + inviter joined at arm time');
    await eventCountAtLeast(ext.client, 'presence', presenceBefore + 2); // lookup + arm-time check
    assert.ok(
      notices.includes(`send to carol:  /dap 127.0.0.1:${hub.port} carol`),
      'paste-ready line notified: ' + JSON.stringify(notices),
    );
    assert.deepEqual(
      readDapConfig(cfgFile).invites,
      [{ name: 'carol', channel: 'general' }],
      'pending invite persisted',
    );

    // Same (name, channel) again, different case: deduped, still one entry.
    const before2 = ext.client.eventCount('presence');
    dap.handler('invite CAROL general', cmdCtx);
    await eventCountAtLeast(ext.client, 'presence', before2 + 2);
    assert.deepEqual(readDapConfig(cfgFile).invites, [{ name: 'carol', channel: 'general' }], 'deduped');
  } finally {
    if (prevCfgEnv === undefined) delete process.env.DAP_CONFIG_FILE;
    else process.env.DAP_CONFIG_FILE = prevCfgEnv;
    ext.dispose();
    await hub.close();
  }
});

test('pending invite: invitee connects later under the armed name -> poller tick DMs the chankey, invitee joins, pending removed', async () => {
  const hub = await new FakeHub().listen();
  const cfgFile = path.join(KEYDIR, 'cfg-auto-' + ++keySeq + '.json');
  const fileA = path.join(KEYDIR, 'auto-inv-a-' + keySeq + '.json');
  const fileB = path.join(KEYDIR, 'auto-inv-b-' + ++keySeq + '.json');
  fs.writeFileSync(fileB, '{}');
  const prevCfgEnv = process.env.DAP_CONFIG_FILE;
  process.env.DAP_CONFIG_FILE = cfgFile;
  const a = fakeCtx();
  const b = fakeCtx();
  const extA = dapExtension(a.ctx, { url: hub.url, keyPath: nextKeyPath(), channelsFile: fileA, name: 'alice' });
  let extB: DapExtension | undefined;
  try {
    await nextEvent(extA.client, 'welcome');
    // Managed-timer session context: the poller registers into pollTasks,
    // the test fires it manually — no real waits.
    const pollTasks = new Map<number, () => void>();
    let pollSeq = 0;
    const notices: string[] = [];
    a.fire('session_start', {
      hasUI: true,
      isIdle: () => true,
      ui: { notify: (text: string) => void notices.push(text) },
      setInterval: (fn: () => void) => {
        const id = ++pollSeq;
        pollTasks.set(id, fn);
        return id;
      },
      clearTimer: (h: unknown) => void pollTasks.delete(h as number),
    });
    assert.equal(pollTasks.size, 1, 'poller armed on its managed timer');

    const cmdNotices: string[] = [];
    const cmdCtx = { ui: { notify: (t: string) => void cmdNotices.push(t) }, hasUI: true };
    const joined = nextEvent<{ channel: string }>(extA.client, 'joined');
    const presenceBefore = extA.client.eventCount('presence');
    assert.match(command(a, 'dap').handler('invite carol', cmdCtx), /inviting carol to #general…/);
    await joined; // arm() completed: channel created, pending persisted
    await eventCountAtLeast(extA.client, 'presence', presenceBefore + 2); // arm-time check settled
    // The invitee is a different user: it must not load the inviter's
    // pending config (DAP_CONFIG_FILE is read at factory time).
    delete process.env.DAP_CONFIG_FILE;
    extB = dapExtension(b.ctx, { url: hub.url, keyPath: nextKeyPath(), channelsFile: fileB, name: 'carol' });
    process.env.DAP_CONFIG_FILE = cfgFile;
    await nextEvent(extB.client, 'welcome');
    const carolId = extB.client.agentId;

    // Poller tick: presence now sees carol online -> automatic chankey DM.
    const tickPresence = nextEvent(extA.client, 'presence');
    await microtasksSettled(); // the arm-time pass finishes before the tick fires
    for (const fn of [...pollTasks.values()]) fn();
    await tickPresence;
    await nextEvent(extB.client, 'inbound'); // chankey DM fully processed (deterministic)
    await nextEvent(extB.client, 'joined');

    const dmSend = hub.verifiedSends.find((f) => f.to === carolId);
    assert.ok(dmSend && !dmSend.ciphertext.includes('chankey'), 'ciphertext only on the wire');
    assert.equal(loadChannelKeys(fileB).general?.pub, loadChannelKeys(fileA).general?.pub, 'invitee persisted the keypair');
    assert.ok(hub.channelMembers.get('general')?.has(carolId), 'invitee joined #general');
    assert.ok(notices.includes('invited carol to #general'), 'inviter notified: ' + JSON.stringify(notices));
    assert.deepEqual(readDapConfig(cfgFile).invites, [], 'pending removed after delivery');
  } finally {
    if (prevCfgEnv === undefined) delete process.env.DAP_CONFIG_FILE;
    else process.env.DAP_CONFIG_FILE = prevCfgEnv;
    extB?.dispose();
    extA.dispose();
    await hub.close();
  }
});

test('/dap invite <online name>: immediate chankey DM, nothing armed in config', async () => {
  const hub = await new FakeHub().listen();
  const cfgFile = path.join(KEYDIR, 'cfg-online-' + ++keySeq + '.json');
  const fileA = path.join(KEYDIR, 'online-inv-a-' + keySeq + '.json');
  const fileB = path.join(KEYDIR, 'online-inv-b-' + ++keySeq + '.json');
  fs.writeFileSync(fileB, '{}');
  const prevCfgEnv = process.env.DAP_CONFIG_FILE;
  process.env.DAP_CONFIG_FILE = cfgFile;
  const a = fakeCtx();
  const b = fakeCtx();
  const extA = dapExtension(a.ctx, { url: hub.url, keyPath: nextKeyPath(), channelsFile: fileA, name: 'alice' });
  const extB = dapExtension(b.ctx, { url: hub.url, keyPath: nextKeyPath(), channelsFile: fileB, name: 'bob' });
  try {
    await nextEvent(extA.client, 'welcome');
    await nextEvent(extB.client, 'welcome');
    const joined = nextEvent<{ channel: string }>(extA.client, 'joined');
    assert.match(command(a, 'dap').handler('invite bob'), /inviting bob to #general…/);
    await nextEvent(extB.client, 'inbound');
    await nextEvent(extB.client, 'joined');
    assert.equal((await joined).channel, 'general');
    assert.ok(hub.verifiedSends.some((f) => f.to === extB.client.agentId), 'immediate DM, no pending involved');
    assert.ok(!fs.existsSync(cfgFile), 'nothing armed or persisted for an online name');
  } finally {
    if (prevCfgEnv === undefined) delete process.env.DAP_CONFIG_FILE;
    else process.env.DAP_CONFIG_FILE = prevCfgEnv;
    extA.dispose();
    extB.dispose();
    await hub.close();
  }
});

test('config back-compat: file without invites key loads (invites defaults to []), persist keeps other keys', () => {
  const cfgFile = path.join(KEYDIR, 'cfg-legacy-' + ++keySeq + '.json');
  fs.writeFileSync(cfgFile, JSON.stringify({ url: 'ws://legacy:9/ws', name: 'legacy', channels: ['ops'] }));
  const cfg = readDapConfig(cfgFile);
  assert.deepEqual(cfg.invites, [], 'missing invites key defaults to []');
  assert.equal(cfg.url, 'ws://legacy:9/ws');
  persistDapConfig({ invites: [{ name: 'newbie', channel: 'general' }] }, cfgFile);
  const after = readDapConfig(cfgFile);
  assert.deepEqual(after.invites, [{ name: 'newbie', channel: 'general' }]);
  assert.equal(after.url, 'ws://legacy:9/ws', 'existing keys survive');
  assert.deepEqual(after.channels, ['ops']);
  fs.writeFileSync(cfgFile, JSON.stringify({ invites: 'corrupt' }));
  assert.deepEqual(readDapConfig(cfgFile).invites, [], 'non-array invites treated as absent');
});

test('pending invites survive a restart: welcome-time check delivers without waiting a tick', async () => {
  const hub = await new FakeHub().listen();
  const cfgFile = path.join(KEYDIR, 'cfg-restart-' + ++keySeq + '.json');
  const fileA = path.join(KEYDIR, 'restart-a-' + keySeq + '.json');
  const fileB = path.join(KEYDIR, 'restart-b-' + ++keySeq + '.json');
  fs.writeFileSync(fileB, '{}');
  const prevCfgEnv = process.env.DAP_CONFIG_FILE;
  process.env.DAP_CONFIG_FILE = cfgFile;
  const a = fakeCtx();
  const b = fakeCtx();
  const extA = dapExtension(a.ctx, { url: hub.url, keyPath: nextKeyPath(), channelsFile: fileA, name: 'alice' });
  let extB: DapExtension | undefined;
  let extA2: DapExtension | undefined;
  try {
    await nextEvent(extA.client, 'welcome');
    const joined = nextEvent<{ channel: string }>(extA.client, 'joined');
    const presenceBefore = extA.client.eventCount('presence');
    command(a, 'dap').handler('invite carol', { ui: { notify: () => {} }, hasUI: true });
    await joined; // arm() completed
    await eventCountAtLeast(extA.client, 'presence', presenceBefore + 2);
    extA.dispose(); // inviter goes away entirely
    delete process.env.DAP_CONFIG_FILE; // the invitee never loads the inviter's pendings
    extB = dapExtension(b.ctx, { url: hub.url, keyPath: nextKeyPath(), channelsFile: fileB, name: 'carol' });
    process.env.DAP_CONFIG_FILE = cfgFile;
    await nextEvent(extB.client, 'welcome');

    // Fresh inviter instance, same config: welcome-time check delivers.
    extA2 = dapExtension(a.ctx, { url: hub.url, keyPath: nextKeyPath(), channelsFile: fileA, name: 'alice2' });
    await nextEvent(extA2.client, 'welcome');
    await nextEvent(extB.client, 'inbound');
    await nextEvent(extB.client, 'joined');
    assert.equal(loadChannelKeys(fileB).general?.pub, loadChannelKeys(fileA).general?.pub, 'same channel key delivered');
    assert.ok(hub.channelMembers.get('general')?.has(extB.client.agentId), 'carol joined');
    assert.deepEqual(readDapConfig(cfgFile).invites, [], 'pending consumed after restart delivery');
  } finally {
    if (prevCfgEnv === undefined) delete process.env.DAP_CONFIG_FILE;
    else process.env.DAP_CONFIG_FILE = prevCfgEnv;
    extA2?.dispose();
    extB?.dispose();
    extA.dispose();
    await hub.close();
  }
});

test('/dap <bare host>: normalizes to …/ws; explicit path kept', async () => {
  const cfgFile = path.join(KEYDIR, 'cfg-hostnorm-' + ++keySeq + '.json');
  const prevCfgEnv = process.env.DAP_CONFIG_FILE;
  process.env.DAP_CONFIG_FILE = cfgFile;
  const cap = fakeCtx();
  const ext = dapExtension(cap.ctx, {
    url: 'ws://127.0.0.1:9/ws', // dead endpoint; we only read the normalized url
    keyPath: nextKeyPath(),
    backoff: { initial: 60_000, max: 60_000 }, // no reconnect storm
  });
  try {
    const dap = command(cap, 'dap');
    const bare = JSON.parse(dap.handler('127.0.0.1:8787 me')) as { url: string };
    assert.equal(bare.url, 'ws://127.0.0.1:8787/ws', 'bare host gains the /ws path');
    const explicit = JSON.parse(dap.handler('ws://127.0.0.1:8787/custom me')) as { url: string };
    assert.equal(explicit.url, 'ws://127.0.0.1:8787/custom', 'explicit path kept');
    assert.equal(readDapConfig(cfgFile).url, 'ws://127.0.0.1:8787/custom', 'normalized url persisted');
  } finally {
    if (prevCfgEnv === undefined) delete process.env.DAP_CONFIG_FILE;
    else process.env.DAP_CONFIG_FILE = prevCfgEnv;
    ext.dispose();
  }
});

test('idle agent: inbound wakes it via steer+triggerTurn; session_start notifies when hasUI', async () => {
  const hub = await new FakeHub().listen();
  const chan = newChannelKeypair();
  const a = fakeCtx();
  const b = fakeCtx();
  const extA = dapExtension(a.ctx, { url: hub.url, keyPath: nextKeyPath(), channels: { general: chan.pub }, name: 'alice' });
  const extB = dapExtension(b.ctx, { url: hub.url, keyPath: nextKeyPath(), channelPrivs: { general: chan.priv }, name: 'bob' });
  try {
    await nextEvent(extA.client, 'welcome');
    await nextEvent(extB.client, 'welcome');

    // Visible liveness: label set at load, notify on session_start when a UI exists.
    assert.deepEqual(b.labels, ['DAP — distributed agents']);
    const notifications: string[] = [];
    const timers = { setInterval: (): number => 0, clearTimer: (): void => {} };
    b.fire('session_start', {
      ui: { notify: (text: string) => void notifications.push(text) },
      hasUI: true,
      isIdle: () => true,
      ...timers,
    });
    assert.equal(notifications.length, 1);
    assert.ok(
      notifications[0] === `DAP connected as ${extB.client.agentId} (bob)`,
      'notify text: ' + notifications[0],
    );
    // Headless session: the hasUI guard suppresses the notify, no crash.
    b.fire('session_start', { hasUI: false, isIdle: () => false, ...timers });
    assert.equal(notifications.length, 1);

    // Inbound while idle: steer + triggerTurn — without it an idle agent shows nothing.
    const inbound = nextEvent<MsgFrame>(extB.client, 'inbound');
    await run(a, 'dap_send', { channel: 'general', text: 'wake up' });
    await inbound;
    assert.equal(b.sent.length, 1);
    assert.deepEqual(b.sent[0].opts, { deliverAs: 'steer', triggerTurn: true });
    assert.equal(b.entries.at(-1)!.type, 'io.dap.message');
  } finally {
    extA.dispose();
    extB.dispose();
    await hub.close();
  }
});

test('hub error frames surface to the session — steer + durable entry, never silent', async () => {
  const hub = await new FakeHub().listen();
  const cap = fakeCtx();
  const ext = dapExtension(cap.ctx, { url: hub.url, keyPath: nextKeyPath(), name: 'a' });
  try {
    await nextEvent(ext.client, 'welcome');
    const rejected = nextEvent(ext.client, 'error');
    hub.sendError(ext.client.agentId, 'unknown_agent', 'no such agent: deadbeef');
    await rejected;
    assert.ok(cap.sent.some((s) => s.msg.includes('unknown_agent')), 'steer mentions the code');
    assert.deepEqual(
      cap.sent.find((s) => s.msg.includes('unknown_agent'))!.opts,
      { deliverAs: 'steer', triggerTurn: true },
    );
    assert.equal(cap.entries.at(-1)!.type, 'io.dap.error');
  } finally {
    ext.dispose();
    await hub.close();
  }
});

test('tools fail honestly while disconnected: ok:false instead of a silent drop', async () => {
  const cap = fakeCtx();
  const ext = dapExtension(cap.ctx, {
    url: 'ws://127.0.0.1:9/ws', // nothing listens: connection down
    keyPath: nextKeyPath(),
    name: 'x',
    channels: { general: 'A'.repeat(43) + '=' }, // explicit keys: no file writes
    backoff: { initial: 60_000, max: 60_000 }, // no reconnect storm during the test
  });
  try {
    const r = await run<{ ok: boolean; error: string }>(cap, 'dap_send', {
      channel: 'general',
      text: 'must not claim success',
    });
    assert.equal(r.ok, false);
    assert.match(r.error, /not connected/);
    const dm = await run<{ ok: boolean }>(cap, 'dap_dm', { to: 'deadbeef', text: 'x' });
    assert.equal(dm.ok, false);
  } finally {
    ext.dispose();
  }
});

test('dap_status: identity + connection state the agent can read about itself', async () => {
  const hub = await new FakeHub().listen();
  const cap = fakeCtx();
  const ext = dapExtension(cap.ctx, {
    url: hub.url,
    keyPath: nextKeyPath(),
    name: 'statuscheck',
    channels: { general: 'A'.repeat(43) + '=' },
  });
  try {
    // Before the welcome lands: connected=false, identity still known.
    const cold = await run<{ connected: boolean; agentId: string; url: string }>(cap, "dap_status");
    assert.equal(cold.connected, false);
    assert.equal(cold.agentId, ext.client.agentId);
    assert.equal(typeof cold.url, 'string');

    await nextEvent(ext.client, 'welcome');
    const warm = await run<{ connected: boolean; name: string; channels: string[]; welcomes: number; hellos: number }>(cap, 'dap_status');
    assert.equal(warm.connected, true);
    assert.equal(warm.name, 'statuscheck');
    assert.deepEqual(warm.channels, ['general']);
    assert.equal(warm.welcomes, 1);
    assert.equal(warm.hellos, 1);
  } finally {
    ext.dispose();
    await hub.close();
  }
});

test('dap_peers: online only, own entry present and marked self', async () => {
  const hub = await new FakeHub().listen();
  const a = fakeCtx();
  const b = fakeCtx();
  const c = fakeCtx();
  const extA = dapExtension(a.ctx, { url: hub.url, keyPath: nextKeyPath(), name: 'peer-a' });
  const extB = dapExtension(b.ctx, { url: hub.url, keyPath: nextKeyPath(), name: 'peer-b' });
  const extC = dapExtension(c.ctx, { url: hub.url, keyPath: nextKeyPath(), name: 'gone-c' });
  try {
    await nextEvent(extA.client, 'welcome');
    await nextEvent(extB.client, 'welcome');
    await nextEvent(extC.client, 'welcome');
    hub.drop(extC.client.agentId);
    await hub.waitOffline(extC.client.agentId);

    const r = await run<{ agents: Array<{ agentId: string; online: boolean; self: boolean }> }>(a, 'dap_peers');
    const own = r.agents.find((x) => x.agentId === extA.client.agentId);
    assert.ok(own, 'own entry present');
    assert.equal(own!.self, true, 'own entry marked self');
    const other = r.agents.find((x) => x.agentId === extB.client.agentId);
    assert.ok(other, 'other online agent listed');
    assert.equal(other!.self, false, 'other entry not marked self');
    assert.ok(!r.agents.some((x) => x.agentId === extC.client.agentId), 'offline agent absent');
    assert.ok(r.agents.every((x) => x.online === true), 'all entries online');
  } finally {
    extA.dispose();
    extB.dispose();
    extC.dispose();
    await hub.close();
  }
});

test('dap_peers: an unsolicited stale presence frame never satisfies a pending query', async () => {
  const hub = await new FakeHub().listen();
  const a = fakeCtx();
  const b = fakeCtx();
  const extA = dapExtension(a.ctx, { url: hub.url, keyPath: nextKeyPath(), name: 'alice' });
  const extB = dapExtension(b.ctx, { url: hub.url, keyPath: nextKeyPath(), name: 'bob' });
  try {
    await nextEvent(extA.client, 'welcome');
    await nextEvent(extB.client, 'welcome');
    // Connect-time warm-up queries: each client fires one before any user
    // query; drain both so the capture below sees only the user's query.
    await hub.waitPresenceQuery();
    await hub.waitPresenceQuery();
    hub.holdPresence = true; // keep the real answer back until the frame is injected
    const pending = run<{ agents: Array<{ agentId: string; self: boolean }> }>(a, 'dap_peers');
    await hub.waitPresenceQuery(); // query is out; its answer is held
    // The live-race shape: an unsolicited one-agent presence frame (foreign
    // replyTo, ghost roster) lands before the real two-agent answer.
    hub.sendTo(extA.client.agentId, {
      op: 'presence',
      replyTo: 'stale-other-query',
      agents: [{ agentId: 'f'.repeat(16), name: 'ghost', online: true }],
    });
    hub.releasePresence(); // the real answer (replyTo echo) arrives second
    const r = await pending;
    assert.ok(r.agents.some((x) => x.agentId === extA.client.agentId && x.self), 'own entry present');
    assert.ok(r.agents.some((x) => x.agentId === extB.client.agentId), 'other agent of the answer present');
    assert.ok(!r.agents.some((x) => x.agentId === 'f'.repeat(16)), 'stale ghost roster never surfaced');
  } finally {
    extA.dispose();
    extB.dispose();
    await hub.close();
  }
});

test('presence: legacy id-less answer still completes (back-compat)', async () => {
  const hub = await new FakeHub().listen();
  hub.legacyAnswers = true; // pre-replyTo hub: never echoes, latch never arms
  const a = fakeCtx();
  const extA = dapExtension(a.ctx, { url: hub.url, keyPath: nextKeyPath(), name: 'solo' });
  try {
    await nextEvent(extA.client, 'welcome');
    // The welcome-time warm-up fires 1 try + 2 retries against a legacy hub
    // (never arms) — drain them, then hold the USER query's answer.
    for (let i = 0; i < 3; i++) await hub.waitPresenceQuery();
    hub.holdPresence = true;
    const pending = extA.client.presence();
    await hub.waitPresenceQuery(); // query out, answer held
    // A legacy hub answers without replyTo — indistinguishable from a
    // broadcast on that wire; it must still complete the waiter.
    hub.sendTo(extA.client.agentId, {
      op: 'presence',
      agents: [{ agentId: extA.client.agentId, name: 'solo', online: true }],
    });
    assert.deepEqual((await pending).map((x) => x.agentId), [extA.client.agentId]);
  } finally {
    extA.dispose();
    await hub.close();
  }
});

test('presence: echo latch — an id-less broadcast never completes a query on an echo-capable hub', async () => {
  const hub = await new FakeHub().listen();
  const a = fakeCtx();
  const extA = dapExtension(a.ctx, { url: hub.url, keyPath: nextKeyPath(), name: 'watcher' });
  try {
    await nextEvent(extA.client, 'welcome');
    await hub.waitPresenceQuery(); // connect-time warm-up query (its echo arms the latch)
    // Query A: the hub's real answer echoes replyTo — this arms the latch.
    hub.holdPresence = true;
    const qA = extA.client.presence();
    await hub.waitPresenceQuery();
    hub.releasePresence();
    await qA;
    // Query B pends; an unsolicited one-agent broadcast (NO replyTo) lands.
    hub.holdPresence = true; // hold B's real echo behind the broadcast
    const qB = extA.client.presence();
    await hub.waitPresenceQuery();
    hub.sendTo(extA.client.agentId, {
      op: 'presence',
      agents: [{ agentId: 'e'.repeat(16), name: 'ghost', online: true }],
    });
    await eventCountAtLeast(extA.client, 'presence', 2); // broadcast handled
    assert.equal(
      await Promise.race([qB, Promise.resolve('pending')]),
      'pending',
      'latch armed: the id-less broadcast must not complete the waiter',
    );
    // B's real answer (matching replyTo) completes it with the FULL roster.
    hub.releasePresence();
    const roster = await qB;
    const ids = roster.map((x) => x.agentId);
    assert.ok(ids.includes(extA.client.agentId), 'own entry present');
    assert.ok(!ids.includes('e'.repeat(16)), 'ghost broadcast roster never surfaced');
  } finally {
    extA.dispose();
    await hub.close();
  }
});

test('presence: concurrent callers each get their own answer', async () => {
  const hub = await new FakeHub().listen();
  const a = fakeCtx();
  const extA = dapExtension(a.ctx, { url: hub.url, keyPath: nextKeyPath(), name: 'caller' });
  try {
    await nextEvent(extA.client, 'welcome');
    await hub.waitPresenceQuery(); // connect-time warm-up query
    hub.holdPresence = true;
    const p1 = extA.client.presence();
    const p2 = extA.client.presence();
    const first = (await hub.waitPresenceQuery()).id as string;
    const second = (await hub.waitPresenceQuery()).id as string;
    assert.notEqual(first, second, 'each query carries a unique id');
    // Answers in REVERSE order with DISTINCT rosters: only per-id routing
    // delivers each caller its own roster.
    hub.sendTo(extA.client.agentId, {
      op: 'presence',
      replyTo: second,
      agents: [{ agentId: extA.client.agentId, online: true }, { agentId: 'b'.repeat(16), online: true }],
    });
    hub.sendTo(extA.client.agentId, {
      op: 'presence',
      replyTo: first,
      agents: [{ agentId: extA.client.agentId, online: true }, { agentId: 'a'.repeat(16), online: true }],
    });
    const [one, two] = await Promise.all([p1, p2]);
    assert.ok(one.some((x) => x.agentId === 'a'.repeat(16)), 'first caller got its own roster');
    assert.ok(two.some((x) => x.agentId === 'b'.repeat(16)), 'second caller got its own roster');
  } finally {
    extA.dispose();
    await hub.close();
  }
});

test('welcome warm-up: join echo / broadcast cannot steal the first user query', { timeout: 5000 }, async () => {
  // The per-test timeout guards the RED run only (warm-up disabled parks the
  // first waitPresenceQuery forever); GREEN never approaches it — every
  // wait below is a deterministic signal, no wall-clock sleeps.
  const hub = await new FakeHub().listen();
  hub.holdPresence = true; // warm-up answers held until the test releases them
  const a = fakeCtx();
  const ghost = 'd'.repeat(16);
  let extB: DapExtension | undefined;
  const extA = dapExtension(a.ctx, { url: hub.url, keyPath: nextKeyPath(), name: 'alice' });
  const b = fakeCtx();
  try {
    await nextEvent(extA.client, 'welcome');
    // The warm-up query went out before 'welcome' was even emitted.
    const warm = await hub.waitPresenceQuery();
    assert.notEqual(warm.id, undefined, 'warm-up query is id-carrying');
    // The steal-window frame: alice's own one-agent join echo, id-less,
    // landing while the latch is still unarmed. The warm-up absorbs it
    // (the broadcast consumes its waiter), so the chain re-fires once.
    hub.sendTo(extA.client.agentId, {
      op: 'presence',
      agents: [{ agentId: extA.client.agentId, name: 'alice', online: true }],
    });
    await hub.waitPresenceQuery(); // the retry query
    hub.releasePresence(); // warm-up echoes (replyTo) -> latch armed, chain stops
    await eventCountAtLeast(extA.client, 'presence', 3); // join echo + 2 echoes
    // Bob joins after the latch armed: the ANSWER roster is the full
    // registry {alice, bob} — distinguishable from any broadcast roster.
    extB = dapExtension(b.ctx, { url: hub.url, keyPath: nextKeyPath(), name: 'bob' });
    await nextEvent(extB.client, 'welcome');
    await hub.waitPresenceQuery(); // bob's own warm-up query
    // First USER query pends; an unsolicited one-agent broadcast (no
    // replyTo) lands while it waits: it must never complete it.
    const pending = run<{ agents: Array<{ agentId: string; self: boolean }> }>(a, 'dap_peers');
    await hub.waitPresenceQuery(); // the user query is out; its answer is held
    hub.sendTo(extA.client.agentId, {
      op: 'presence',
      agents: [{ agentId: ghost, name: 'ghost', online: true }],
    });
    hub.releasePresence(); // the real answer (replyTo echo, full roster) lands last
    const r = await pending;
    assert.ok(r.agents.some((x) => x.agentId === extA.client.agentId && x.self), 'own entry present');
    assert.ok(r.agents.some((x) => x.agentId === extB?.client.agentId), 'full ANSWER roster: bob present');
    assert.ok(!r.agents.some((x) => x.agentId === ghost), 'broadcast roster never satisfied the query');
  } finally {
    extA.dispose();
    extB?.dispose();
    await hub.close();
  }
});

test('dap_whois is fresh: an offline transition is not masked by the cache', async () => {
  const hub = await new FakeHub().listen();
  const a = fakeCtx();
  const b = fakeCtx();
  const extA = dapExtension(a.ctx, { url: hub.url, keyPath: nextKeyPath(), name: 'asker' });
  const extB = dapExtension(b.ctx, { url: hub.url, keyPath: nextKeyPath(), name: 'vanishing' });
  try {
    await nextEvent(extA.client, 'welcome');
    await nextEvent(extB.client, 'welcome');

    const first = await run<{ online: boolean }>(a, 'dap_whois', { agentId: extB.client.agentId });
    assert.equal(first.online, true);

    hub.drop(extB.client.agentId);
    await hub.waitOffline(extB.client.agentId);

    const second = await run<{ online: boolean }>(a, 'dap_whois', { agentId: extB.client.agentId });
    assert.equal(second.online, false, 'a cached online verdict must not survive the disconnect');
  } finally {
    extA.dispose();
    extB.dispose();
    await hub.close();
  }
});

test('/dap re-key stays live: status id, inbound AAD, outbound keys all follow the NEW identity', async () => {
  const hub = await new FakeHub().listen();
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'dap-rekey-'));
  const prevHome = process.env.HOME;
  const prevCfg = process.env.DAP_CONFIG_FILE;
  process.env.HOME = home; // defaultKeyPath(name) resolves under this home
  process.env.DAP_CONFIG_FILE = path.join(home, 'config.json');
  const a = fakeCtx();
  const b = fakeCtx();
  const extA = dapExtension(a.ctx, { url: hub.url, keyPath: nextKeyPath() });
  const extB = dapExtension(b.ctx, { url: hub.url, keyPath: nextKeyPath() });
  try {
    await nextEvent(extA.client, 'welcome');
    await nextEvent(extB.client, 'welcome');
    const oldId = extA.client.agentId;

    // The user's exact action: /dap <host> <new name> — runtime identity swap.
    const conn = await run<{ ok: boolean; agentId: string }>(a, 'dap_connect', {
      host: `127.0.0.1:${hub.port}`,
      name: 'swapped',
    });
    assert.equal(conn.ok, true);
    assert.notEqual(conn.agentId, oldId, 'a name-derived key is a new identity');
    await eventCountAtLeast(extA.client, 'welcome', 2);

    // dap_status must report the LIVE identity (a captured id kept the
    // pre-retarget agentId forever after a re-key).
    const st = await run<{ agentId: string; connected: boolean }>(a, 'dap_status');
    assert.equal(st.agentId, conn.agentId, 'status follows the retargeted identity');
    assert.equal(st.connected, true);
    // Inbound to the NEW id must decrypt (DM AAD = current id) and steer in.
    const aInboundBefore = extA.client.eventCount('inbound');
    await run(b, 'dap_dm', { to: conn.agentId, text: 'post-rekey inbound' });
    await extA.client.waitForAfter('inbound', aInboundBefore);
    assert.ok(a.sent.some((s) => /post-rekey inbound/.test(s.msg)), 'inbound DM steered in after re-key');
    const inbox = await run<{ entries: { text: string }[] }>(a, 'dap_inbox', { limit: 10 });
    assert.ok(inbox.entries.some((e) => /post-rekey inbound/.test(e.text)), 'durable inbox holds it');

    // Outbound post-re-key must decrypt at the peer (live key material).
    const bInboundBefore = extB.client.eventCount('inbound');
    await run(a, 'dap_dm', { to: extB.client.agentId, text: 'post-rekey outbound' });
    await extB.client.waitForAfter('inbound', bInboundBefore);

    assert.ok(b.sent.some((s) => /post-rekey outbound/.test(s.msg)), 'outbound DM decrypts at the peer after re-key');
  } finally {
    if (prevHome === undefined) delete process.env.HOME;
    else process.env.HOME = prevHome;
    if (prevCfg === undefined) delete process.env.DAP_CONFIG_FILE;
    else process.env.DAP_CONFIG_FILE = prevCfg;
    extA.dispose();
    extB.dispose();
    await hub.close();
  }
});

test('re-key then host-only retarget: a fresh session reuses the shared client (no second socket)', async () => {
  const hub = await new FakeHub().listen();
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'dap-share-'));
  const prevHome = process.env.HOME;
  const prevUrl = process.env.DAP_HUB_URL;
  // Production-faithful: no DAP_CONFIG_FILE — settings AND persistence both
  // use ~/.dap/config.json under the tmp HOME.
  process.env.HOME = home; // hostname-key and name-key both resolve under tmp
  process.env.DAP_HUB_URL = hub.url;
  const a = fakeCtx();
  const extA = dapExtension(a.ctx); // production path: shared client, no overrides
  let extB: DapExtension | undefined;
  try {
    await nextEvent(extA.client, 'welcome');
    const oldId = extA.client.agentId;

    await run(a, 'dap_connect', { host: `127.0.0.1:${hub.port}`, name: 'swapped' });
    await eventCountAtLeast(extA.client, 'welcome', 2);
    const newId = extA.client.agentId;

    // Host-only retarget on the re-keyed client: the shared-client key must
    // follow the NEW identity path, else a fresh session computes a
    // different shareKey and spawns a second socket under the OLD identity.
    await run(a, 'dap_connect', { host: `127.0.0.1:${hub.port}` });
    await microtasksSettled();
    await microtasksSettled();

    const b = fakeCtx();
    extB = dapExtension(b.ctx); // fresh session: resolves persisted name → swapped-key path
    await microtasksSettled();
    await microtasksSettled();
    assert.equal(extB.client, extA.client, 'fresh session reuses the retargeted shared client');
    const newIdHellos = hub.log.filter((l) => l === 'hello-verified:' + newId).length;
    assert.equal(newIdHellos, 1, 'exactly one connection under the new identity (got ' + newIdHellos + ')');
    const oldIdHellos = hub.log.filter((l) => l === 'hello-verified:' + oldId).length;
    assert.equal(oldIdHellos, 1, 'the old identity never reconnects');
  } finally {
    if (prevHome === undefined) delete process.env.HOME;
    else process.env.HOME = prevHome;
    if (prevUrl === undefined) delete process.env.DAP_HUB_URL;
    else process.env.DAP_HUB_URL = prevUrl;
    extB?.dispose();
    extA.dispose();
    await hub.close();
  }
});

test('footer status line: persistent connection info visible without asking', async () => {
  const hub = await new FakeHub().listen();
  const cap = fakeCtx();
  const status: string[] = [];
  const fire = (ev: string) =>
    cap.fire(ev, {
      hasUI: true,
      isIdle: () => false,
      ui: { notify: () => {}, setStatus: (_k: string, text: string | undefined) => void status.push(text ?? 'CLEARED') },
      setInterval: () => 0,
      clearTimer: () => {},
    });
  const ext = dapExtension(cap.ctx, {
    url: hub.url,
    keyPath: nextKeyPath(),
    name: 'footcheck',
    channels: { general: 'A'.repeat(43) + '=' },
  });
  try {
    fire('session_start'); // before welcome: connecting…
    assert.match(status.at(-1)!, /connecting/);
    await nextEvent(ext.client, 'welcome');
    const connected = status.at(-1)!;
    assert.match(connected, /connected/, 'footer shows connected');
    assert.match(connected, /footcheck/, 'footer shows name');
    assert.match(connected, /#general/, 'footer shows channels');
    assert.match(connected, new RegExp(hub.url.replace(/^ws:\/\/([^/]+)\/ws$/, '$1')), 'footer shows host');
    hub.drop(ext.client.agentId); // server drops us
    await nextEvent(ext.client, 'close');
    assert.match(status.at(-1)!, /reconnecting/);
  } finally {
    ext.dispose();
    await hub.close();
  }
});

test('dap_connect: retargets to another hub, renames identity, persists config + default room', async () => {
  const hub1 = await new FakeHub().listen();
  const hub2 = await new FakeHub().listen();
  const cap = fakeCtx();
  const cfgFile = path.join(KEYDIR, 'cfg-' + ++keySeq + '.json');
  const chFile = path.join(KEYDIR, 'ch-' + ++keySeq + '.json');
  const prevCfgEnv = process.env.DAP_CONFIG_FILE;
  process.env.DAP_CONFIG_FILE = cfgFile;
  const ext = dapExtension(cap.ctx, { url: hub1.url, keyPath: nextKeyPath(), channelsFile: chFile });
  try {
    await nextEvent(ext.client, 'welcome');
    const oldId = ext.client.agentId;
    const r = await run<{ ok: boolean; url: string; name: string; agentId: string; channels: string[] }>(
      cap, 'dap_connect', { host: hub2.url.replace(/^ws:\/\//, ''), name: 'renamed', channel: 'lobby' },
    );
    assert.equal(r.ok, true);
    assert.equal(r.url, hub2.url, 'host normalized to full ws URL');
    assert.equal(r.name, 'renamed');
    assert.notEqual(r.agentId, oldId, 'new name => new identity');
    assert.ok(r.channels.includes('lobby'), 'default room ensured');
    const saved = JSON.parse(fs.readFileSync(cfgFile, 'utf8')) as { url?: string; name?: string; channels?: string[] };
    assert.equal(saved.url, hub2.url, 'config persisted to DAP_CONFIG_FILE path, not ~/.dap');
    assert.equal(saved.name, 'renamed');
    assert.ok(saved.channels?.includes('lobby'), 'default room persisted');
    await nextEvent(ext.client, 'welcome'); // connected to the SECOND hub
    assert.equal(ext.client.welcomeCount, 2);
    // The lobby join is sent from the welcome handler; its reply lands one wire
    // round later. (The pre-guard suite passed here on a STALE 'joined' emitted
    // by the superseded hub1 socket — exactly the bug the socket guards fix.)
    await eventCountAtLeast(ext.client, 'joined', 1);
    assert.ok(ext.client.eventCount('joined') >= 1, 'lobby joined after connect');
  } finally {
    if (prevCfgEnv === undefined) delete process.env.DAP_CONFIG_FILE;
    else process.env.DAP_CONFIG_FILE = prevCfgEnv;
    ext.dispose();
    await hub1.close();
    await hub2.close();
  }
});

test('per-process singleton: second session reuses the client (no eviction war)', async () => {
  const hub = await new FakeHub().listen();
  const prevUrl = process.env.DAP_HUB_URL;
  const prevKeyEnv = process.env.DAP_KEY_PATH;
  process.env.DAP_HUB_URL = hub.url;
  process.env.DAP_KEY_PATH = path.join(KEYDIR, 'shared-' + ++keySeq + '.key');
  let ext1: DapExtension | undefined;
  let ext2: DapExtension | undefined;
  try {
    // No overrides: the production path — settings resolve from env, and two
    // sessions with one identity key + url must share ONE client/socket.
    ext1 = dapExtension(fakeCtx().ctx);
    await nextEvent(ext1.client, 'welcome');
    ext2 = dapExtension(fakeCtx().ctx);
    assert.equal(ext2.client, ext1.client, 'second session reuses the shared client');
    const agentId = ext1.client.agentId;
    assert.equal(hub.log.filter((l) => l === 'hello-verified:' + agentId).length, 1, 'exactly ONE connection helloed the hub');
    assert.ok(!hub.log.some((l) => l.startsWith('evict:')), 'no eviction war on the hub');

    ext1.dispose(); // first session gone — refs remain, socket stays usable
    assert.equal(ext1.client.connected, true, 'shared client survives one dispose');

    const closed = nextEvent(ext1.client, 'close');
    ext2.dispose(); // last ref out: the socket finally stops
    await closed;
    await hub.waitOffline(agentId);
    assert.equal(ext1.client.connected, false, 'socket stopped after the last dispose');
    assert.equal(hub.log.filter((l) => l === 'hello-verified:' + agentId).length, 1, 'still exactly one hello (no reconnect)');
  } finally {
    if (prevUrl === undefined) delete process.env.DAP_HUB_URL;
    else process.env.DAP_HUB_URL = prevUrl;
    if (prevKeyEnv === undefined) delete process.env.DAP_KEY_PATH;
    else process.env.DAP_KEY_PATH = prevKeyEnv;
    ext1?.dispose();
    ext2?.dispose();
    await hub.close();
  }
});

test('/dap_status and /dap_peers commands: status JSON mirrors the tool; peers notify rows (online only, own entry marked self)', async () => {
  const hub = await new FakeHub().listen();
  const a = fakeCtx();
  const b = fakeCtx();
  const c = fakeCtx();
  const extA = dapExtension(a.ctx, { url: hub.url, keyPath: nextKeyPath(), name: 'alice' });
  const extB = dapExtension(b.ctx, { url: hub.url, keyPath: nextKeyPath(), name: 'bob' });
  const extC = dapExtension(c.ctx, { url: hub.url, keyPath: nextKeyPath(), name: 'carol' });
  try {
    await nextEvent(extA.client, 'welcome');
    await nextEvent(extB.client, 'welcome');
    await nextEvent(extC.client, 'welcome');
    hub.drop(extB.client.agentId);
    await hub.waitOffline(extB.client.agentId);

    assert.ok(command(a, 'dap_status'), 'dap_status command registered');
    assert.ok(command(a, 'dap_peers'), 'dap_peers command registered');
    const notified: string[] = [];
    const cmdCtx = { ui: { notify: (t: string) => void notified.push(t) }, hasUI: true };

    const status = command(a, 'dap_status').handler('', cmdCtx) as string;
    const parsed = JSON.parse(status) as { agentId: string; connected: boolean };
    assert.equal(parsed.agentId, extA.client.agentId, 'status JSON carries the agentId');
    assert.equal(parsed.connected, true);

    const presenceA = nextEvent(extA.client, 'presence');
    assert.match(command(a, 'dap_peers').handler('', cmdCtx) as string, /listing online agents…/);
    await presenceA;
    await microtasksSettled(); // the notify rides a microtask after the presence emission
    assert.ok(notified.at(-1)!.includes('on ' + extC.client.agentId + ' carol'), 'other online row notified: ' + notified.at(-1));
    assert.ok(notified.at(-1)!.includes('on ' + extA.client.agentId + ' alice (self)'), 'own row notified and marked self: ' + notified.at(-1));
    assert.ok(!notified.at(-1)!.includes(extB.client.agentId), 'offline agent absent from notify');
  } finally {
    extA.dispose();
    extB.dispose();
    extC.dispose();
    await hub.close();
  }
});

test('live DM: a second session claiming the shared client must not steal delivery — dap_inbox still lists it', async () => {
  const hub = await new FakeHub().listen();
  const a = fakeCtx();
  const r = fakeCtx();
  const extA = dapExtension(a.ctx, { url: hub.url, keyPath: nextKeyPath(), name: 'sender' });
  const extR = dapExtension(r.ctx, { url: hub.url, keyPath: nextKeyPath(), name: 'receiver' });
  try {
    await nextEvent(extA.client, 'welcome');
    await nextEvent(extR.client, 'welcome');

    // Production condition: a second omp session (subagent) shares R's client
    // and subscribes its own delivery handler (per-session inbox + steer).
    // Delivery must fan out — the second session must not starve the first.
    const stolen: string[] = [];
    extR.client.onFrame((frame) => {
      stolen.push(frame.id);
      return Promise.resolve();
    });

    const inboundR = nextEvent<MsgFrame>(extR.client, 'inbound');
    await run(a, 'dap_dm', { to: extR.client.agentId, text: 'live ping' });
    const frame = await inboundR;
    assert.equal(frame.to, extR.client.agentId, 'hub DM frame carries `to` (deliverDM shape)');

    // The acceptance contract: the DM is in R's own durable inbox, readable
    // via dap_inbox with decrypted sender, text and ts — like flushed mail.
    const inbox = await run<{ count: number; entries: { id: string; from: string; text: string; ts: number; dm: boolean }[] }>(
      r,
      'dap_inbox',
      { limit: 10 },
    );
    assert.equal(inbox.count, 1, `live DM must land in the first session's inbox despite the second subscriber`);
    assert.equal(inbox.entries[0].id, frame.id);
    assert.equal(inbox.entries[0].from, extA.client.agentId, 'decrypted sender');
    assert.equal(inbox.entries[0].text, 'live ping');
    assert.equal(inbox.entries[0].ts, frame.ts, 'entry ts is the hub frame ts');
    assert.equal(inbox.entries[0].dm, true);
    assert.ok(stolen.includes(frame.id), 'the second session still receives the frame (fan-out, not exclusivity)');
  } finally {
    extA.dispose();
    extR.dispose();
    await hub.close();
  }
});
