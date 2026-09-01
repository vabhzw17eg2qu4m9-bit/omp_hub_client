import {
  x25519,
  unb64,
  deriveKey,
  dmAAD,
  channelAAD,
  encryptPayload,
  decryptPayload,
  type KeyPair,
} from './crypto.js';
import type { MsgFrame } from './conn.js';

export interface PayloadCryptoContext {
  keys: KeyPair;
  /** Own agentId — the DM AAD base on the receiving side. */
  selfAgentId: string;
  /** channel -> x25519 public key (b64) for encrypting outgoing channel sends. */
  channels: Record<string, string>;
  /** channel -> x25519 private key (b64) for decrypting; membership marker. */
  channelPrivs: Record<string, string>;
  /** whois lookup: agentId -> X25519 public key (b64, '' if absent). */
  peerXPub: (agentId: string) => Promise<string | undefined>;
}

export interface DecryptedPayload {
  channel?: string;
  dm: boolean;
  text: string;
}

/** Channel send: ECDH(sender x25519 priv, channel keypair pubkey). */
export async function encryptForChannel(
  text: string,
  channel: string,
  frameId: string,
  ctx: PayloadCryptoContext,
): Promise<string> {
  const channelPub = unb64(ctx.channels[channel]);
  if (channelPub.length !== 32) throw new Error('unknown_channel: ' + channel);
  const secret = x25519.getSharedSecret(ctx.keys.xpriv, channelPub);
  return encryptPayload(text, deriveKey(secret, frameId), channelAAD(frameId, channel));
}

/** DM (DAP/1 addendum): whois the peer, then ECDH(sender x25519 priv,
 *  recipient x25519 pub from agent_info). */
export async function encryptForDM(
  text: string,
  toAgentId: string,
  frameId: string,
  ctx: PayloadCryptoContext,
): Promise<string> {
  const peerXPub = await requirePeer(toAgentId, ctx);
  const secret = x25519.getSharedSecret(ctx.keys.xpriv, unb64(peerXPub));
  return encryptPayload(text, deriveKey(secret, frameId), dmAAD(frameId, toAgentId));
}

/** Inbound msg frame -> plaintext. Channel frames use the channel private key
 *  (membership); DM frames use our own x25519 private key + the sender's
 *  x25519 public key from agent_info. */
export async function decryptInbound(
  frame: MsgFrame,
  ctx: PayloadCryptoContext,
): Promise<DecryptedPayload> {
  if (frame.channel) {
    const channelPriv = unb64(ctx.channelPrivs[frame.channel]);
    if (channelPriv.length !== 32) throw new Error('not_a_member: ' + frame.channel);
    const secret = x25519.getSharedSecret(channelPriv, unb64(await requirePeer(frame.from, ctx)));
    const text = decryptPayload(frame.ciphertext, deriveKey(secret, frame.id), channelAAD(frame.id, frame.channel));
    return { channel: frame.channel, dm: false, text };
  }
  const secret = x25519.getSharedSecret(ctx.keys.xpriv, unb64(await requirePeer(frame.from, ctx)));
  const text = decryptPayload(frame.ciphertext, deriveKey(secret, frame.id), dmAAD(frame.id, ctx.selfAgentId));
  return { dm: true, text };
}

async function requirePeer(agentId: string, ctx: PayloadCryptoContext): Promise<string> {
  const xpub = await ctx.peerXPub(agentId);
  if (!xpub) throw new Error('unknown_agent: ' + agentId);
  if (xpub.length === 0) throw new Error('peer_has_no_x25519: ' + agentId);
  return xpub;
}
