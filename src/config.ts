import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { randomBytes, bytesToHex } from '@noble/hashes/utils';

/** A pending by-name invite: armed by `/dap invite <name>` for a user not
 *  yet on the hub; delivered automatically when that name comes online. */
export interface PendingInvite {
  name: string;
  channel: string;
}

/** Optional persisted settings: ~/.dap/config.json (all fields optional). */
export interface DapFileConfig {
  url?: string;
  name?: string;
  keyPath?: string;
  channelsFile?: string;
  /** Default rooms: ensured (keygen if unknown) and auto-joined after connect. */
  channels?: string[];
  /** LEGACY hub-issued client secret: one shared field for the whole host.
  *  Superseded by `clientSecrets` — kept so single-identity hosts upgrade
  *  without re-enrolling, and wiped once a per-identity entry replaces it. */
  clientSecret?: string;
  /** Hub-issued client secrets PER IDENTITY, keyed by the identity's key
  *  file path (one key file = one identity = one name). The hub binds each
  *  issued secret to the hello name it enrolled under, so two identities
  * sharing one field dial with a secret the hub rejects — this map gives
  * every identity on the host its own slot. The master secret is never
  *  persisted. */
  clientSecrets?: Record<string, string>;
  /** Armed invite-by-name entries; removed once delivered. */
  invites?: PendingInvite[];
}

export const DEFAULT_URL = 'ws://127.0.0.1:8787/ws';

export const optStr = (v: unknown): string | undefined => (typeof v === 'string' && v.length > 0 ? v : undefined);

/** Read ~/.dap/config.json; a missing or invalid file counts as absent.
 *  `invites` is normalized to [] (files written before the key lack it). */
export function readDapConfig(file = optStr(process.env.DAP_CONFIG_FILE) ?? path.join(os.homedir(), '.dap', 'config.json')): DapFileConfig {
  try {
    const cfg = JSON.parse(fs.readFileSync(file, 'utf8')) as DapFileConfig;
    return { ...cfg, invites: Array.isArray(cfg.invites) ? cfg.invites : [] };
  } catch {
    return { invites: [] };
  }
}

/** Merge `update` into ~/.dap/config.json (read-modify-write, mkdir on
 *  demand): dap_connect persists host/name/default-rooms so the next
 *  launch auto-connects with the same identity. `invites` is the
 *  authoritative list — delivered entries are removed by the caller.
 *  A `clientSecret` string with an `identityKey` upserts that identity's
 *  slot in `clientSecrets` (and retires the legacy shared field — a fresh
 *  enrollment supersedes any cached one); without an `identityKey` it
 *  writes the legacy top-level field (standalone DapClient back-compat).
 *  `null` deletes the identity's slot AND the legacy field: a stale wipe
 *  must clear every path a later dial could re-resolve the secret from. */
export function persistDapConfig(
  update: {
    url?: string;
    name?: string;
    channels?: string[];
    invites?: PendingInvite[];
    /** A string upserts; null deletes the key (stale-secret wipe). */
    clientSecret?: string | null;
    /** Which identity's clientSecrets slot the update targets (the resolved
     *  keyPath — one key file per identity). */
    identityKey?: string;
  },
  file = optStr(process.env.DAP_CONFIG_FILE) ?? path.join(os.homedir(), '.dap', 'config.json'),
): void {
  const cur = readDapConfig(file);
  const next: DapFileConfig = { ...cur };
  if (update.url) next.url = update.url;
  if (update.name) next.name = update.name;
  if (update.channels?.length) {
    next.channels = [...new Set([...(cur.channels ?? []), ...update.channels])];
  }
  if (update.invites) next.invites = update.invites;
  if (update.clientSecret) {
    if (update.identityKey) {
      next.clientSecrets = { ...(cur.clientSecrets ?? {}), [update.identityKey]: update.clientSecret };
      delete next.clientSecret; // per-identity storage supersedes the shared legacy field
    } else {
      next.clientSecret = update.clientSecret;
    }
  } else if (update.clientSecret === null) {
    if (update.identityKey && next.clientSecrets) {
      next.clientSecrets = { ...cur.clientSecrets };
      delete next.clientSecrets[update.identityKey];
      if (Object.keys(next.clientSecrets).length === 0) delete next.clientSecrets;
    }
    delete next.clientSecret; // the legacy fallback must not survive a stale wipe either
  }
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(next, null, 2) + '\n', { mode: 0o600 });
}

export interface SettingsOverrides {
  url?: string;
  keyPath?: string;
  name?: string;
  channelsFile?: string;
  clientSecret?: string;
}

export interface DapSettings {
  url: string;
  keyPath: string;
  name?: string;
  channelsFile: string;
  clientSecret?: string;
  /** Where clientSecret came from: 'env' (DAP_CLIENT_SECRET or explicit
   *  override — user intent) | 'config' (persisted cache) | undefined. */
  clientSecretSource?: ClientSecretSource;
}

/** Provenance of a resolved clientSecret: 'env' = DAP_CLIENT_SECRET or an
 *  explicit override (user intent — never eligible for the stale-cache
 *  wipe); 'config' = persisted ~/.dap/config.json cache (a hub 401 may
 *  recover it via one enroll-mode re-enroll). */
export type ClientSecretSource = 'env' | 'config';

/** Default identity file is derived from the agent name:
 *  ~/.dap/keys/<name>.key — auto-generated by loadOrCreateKeys, so a second
 *  agent on the same machine needs nothing but DAP_AGENT_NAME (or its own
 *  generated name) to get its own identity. */
export function defaultKeyPath(name: string | undefined): string {
  const who = (name ?? defaultAgentName()).replace(/[^a-zA-Z0-9._-]/g, '_');
  return path.join(os.homedir(), '.dap', 'keys', `${who}.key`);
}

/** Random, readable default agent name: <sanitized hostname>-<4 hex>.
 *  Pure — every call draws fresh (two draws never collide in tests). */
export function randomAgentName(): string {
  const host =
    os
      .hostname()
      .toLowerCase()
      .replace(/[^a-z0-9._-]/g, '-')
      .replace(/^[^a-z0-9]+|[^a-z0-9]+$/g, '')
      .slice(0, 24) || 'agent';
  return `${host}-${bytesToHex(randomBytes(2))}`;
}

/** Per-process default agent name (memoized). The bare hostname made every
 *  pi/omp process on a machine share ONE identity — the hub's
 *  one-connection-per-agent law turned a second local agent into an
 *  eviction war against the first. The memo keeps one identity per PROCESS
 *  (main + subagent sessions share one client/socket via the sharedClients
 *  map), while each new process draws its own name and key. Set
 *  DAP_AGENT_NAME (or persist a name via /dap <host> <name>) for a stable
 *  cross-launch identity. */
let processDefaultName: string | undefined;
export function defaultAgentName(): string {
  processDefaultName ??= randomAgentName();
  return processDefaultName;
}

/** Per-identity client secret lookup: the identity's own clientSecrets slot
 *  first, then the legacy shared field (single-identity hosts predating
 *  per-identity storage keep connecting without re-enrolling). */
export function clientSecretForKey(file: DapFileConfig, keyPath: string): string | undefined {
  return optStr(file.clientSecrets?.[keyPath]) ?? file.clientSecret;
}

/** Precedence: explicit override > env var > ~/.dap/config.json > defaults.
 *  channelsFile defaults to ~/.dap/channels.json so no env is needed at all. */
export function resolveDapSettings(overrides: SettingsOverrides = {}): DapSettings {
  const home = os.homedir();
  const file = readDapConfig();
  const name = overrides.name ?? optStr(process.env.DAP_AGENT_NAME) ?? file.name ?? defaultAgentName();
  const keyPath =
    overrides.keyPath ?? optStr(process.env.DAP_KEY_PATH) ?? file.keyPath ?? defaultKeyPath(name);
  // DAP_CLIENT_SECRET env beats the persisted clientSecret (same chain as url/name);
  // the winner's provenance drives stale-cache recovery on a hub 401. The
  // persisted cache is PER IDENTITY: the secret the hub issued for THIS key
  // file (one key file = one identity = one name) — a shared field made every
  // second identity on the host dial with a secret bound to another name,
  // and the hub rejected the hello.
  const explicitSecret = overrides.clientSecret ?? optStr(process.env.DAP_CLIENT_SECRET);
  const clientSecret = explicitSecret ?? clientSecretForKey(file, keyPath);
  return {
    url: overrides.url ?? optStr(process.env.DAP_HUB_URL) ?? file.url ?? DEFAULT_URL,
    name,
    keyPath,
    channelsFile:
      overrides.channelsFile ??
      optStr(process.env.DAP_CHANNELS_FILE) ??
      file.channelsFile ??
      path.join(home, '.dap', 'channels.json'),
    clientSecret,
    clientSecretSource:
      explicitSecret !== undefined ? 'env' : clientSecret === undefined ? undefined : 'config',
  };
}
