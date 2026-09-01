import fs from 'node:fs';
import { dirname } from 'node:path';
import { ed25519, x25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { hkdf } from '@noble/hashes/hkdf';
import { randomBytes, bytesToHex } from '@noble/hashes/utils';
import { chacha20poly1305 } from '@noble/ciphers/chacha';

export interface KeyPair {
  /** Ed25519 identity pair: signs hello + frames. */
  priv: Uint8Array;
  pub: Uint8Array;
  /** Separate X25519 pair for E2E payload ECDH (DAP/1 addendum). */
  xpriv: Uint8Array;
  xpub: Uint8Array;
}

// Shared encoding helpers (lockstep at many call sites).
export const b64 = (b: Uint8Array): string => Buffer.from(b).toString('base64');
export const unb64 = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'base64'));
export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
export const unutf8 = (b: Uint8Array): string => new TextDecoder().decode(b);

/** Canonical JSON: UTF-8, keys sorted recursively, no whitespace (DAP/1 spec).
 *  JSON.stringify never HTML-escapes `<>&` — matches the Go hub's
 *  SetEscapeHTML(false) canonicalizer byte for byte. */
export function canonicalJSON(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJSON).join(',') + ']';
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJSON(obj[k])).join(',') + '}';
}

/** sigPayload = "dap1|" + op + "|" + ts + "|" + hex(sha256(canonicalJSON(frame))) — DAP/1 spec. */
export function sigPayload(op: string, ts: number, frame: unknown): string {
  return 'dap1|' + op + '|' + ts + '|' + bytesToHex(sha256(utf8(canonicalJSON(frame))));
}

function frameWithoutSig(frame: Record<string, unknown>): Record<string, unknown> {
  const { sig: _sig, ...rest } = frame;
  return rest;
}

/** Ed25519-sign a frame; the `sig` field itself is excluded from the payload. */
export function signFrame(priv: Uint8Array, op: string, frame: Record<string, unknown>): string {
  const rest = frameWithoutSig(frame);
  return b64(ed25519.sign(utf8(sigPayload(op, rest.ts as number, rest)), priv));
}

export function verifyFrame(pub: Uint8Array, op: string, frame: Record<string, unknown>): boolean {
  const rest = frameWithoutSig(frame);
  const sig = unb64(frame.sig as string);
  return ed25519.verify(sig, utf8(sigPayload(op, rest.ts as number, rest)), pub);
}

/** agentId = hex(sha256(pubkey_raw))[:16] — DAP/1 spec. */
export const agentIdFor = (pub: Uint8Array): string => bytesToHex(sha256(pub)).slice(0, 16);

/** Load the agent keys from disk (0600), creating them on first run:
 *  one JSON file holds the Ed25519 identity pair and the X25519 E2E pair. */
export function loadOrCreateKeys(path: string): KeyPair {
  try {
    const j = JSON.parse(fs.readFileSync(path, 'utf8')) as Record<string, string>;
    const keys = {
      priv: unb64(j.priv),
      pub: unb64(j.pub),
      xpriv: unb64(j.xpriv),
      xpub: unb64(j.xpub),
    };
    const all32 = Object.values(keys).every((k) => k.length === 32);
    if (all32) return keys;
  } catch {
    // fall through: create new keypairs
  }
  const keys: KeyPair = {
    priv: ed25519.utils.randomPrivateKey(),
    pub: new Uint8Array(0),
    xpriv: x25519.utils.randomPrivateKey(),
    xpub: new Uint8Array(0),
  };
  keys.pub = ed25519.getPublicKey(keys.priv);
  keys.xpub = x25519.getPublicKey(keys.xpriv);
  fs.mkdirSync(dirname(path), { recursive: true }); // e.g. ~/.dap/keys/
  fs.writeFileSync(path, JSON.stringify({
    priv: b64(keys.priv),
    pub: b64(keys.pub),
    xpriv: b64(keys.xpriv),
    xpub: b64(keys.xpub),
  }), { mode: 0o600 });
  fs.chmodSync(path, 0o600); // umask-proof: spec requires 0600
  return keys;
}

// --- E2E payload crypto: X25519 ECDH -> HKDF-SHA256 -> ChaCha20-Poly1305 ---
// Uses the agent's dedicated X25519 keypair (DAP/1 addendum), NOT a
// conversion of the Ed25519 identity key.

/** Key = HKDF-SHA256(ikm = ecdh_secret, salt = frame_id, info = "dap1/v1") -> 32 bytes */
export function deriveKey(secret: Uint8Array, frameId: string): Uint8Array {
  return hkdf(sha256, secret, utf8(frameId), utf8('dap1/v1'), 32);
}

/** AAD = "dap1|" + frame_id + "|" + recipient agentId (DM) / channel name — DAP/1 spec. */
export const dmAAD = (frameId: string, recipient: string): string => 'dap1|' + frameId + '|' + recipient;
export const channelAAD = (frameId: string, channel: string): string => 'dap1|' + frameId + '|' + channel;

/** ciphertext = base64( nonce(12) || ct || tag(16) ) */
export function encryptPayload(plain: string, key: Uint8Array, aad: string): string {
  const nonce = randomBytes(12);
  const ct = chacha20poly1305(key, nonce, utf8(aad)).encrypt(utf8(plain));
  const out = new Uint8Array(nonce.length + ct.length);
  out.set(nonce);
  out.set(ct, nonce.length);
  return b64(out);
}

export function decryptPayload(blob: string, key: Uint8Array, aad: string): string {
  const raw = unb64(blob);
  return unutf8(chacha20poly1305(key, raw.slice(0, 12), utf8(aad)).decrypt(raw.slice(12)));
}

export { x25519 };
