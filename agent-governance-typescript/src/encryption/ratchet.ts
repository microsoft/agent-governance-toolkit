// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Double Ratchet algorithm for per-message forward secrecy.
 *
 * Spec: docs/specs/AGENTMESH-WIRE-1.0.md Section 8
 * Reference: https://signal.org/docs/specifications/doubleratchet/ (CC0)
 */

import { x25519 } from "@noble/curves/ed25519.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { timingSafeEqual, webcrypto } from "node:crypto";

const randomBytes = (n: number): Uint8Array => {
  const buf = new Uint8Array(n);
  webcrypto.getRandomValues(buf);
  return buf;
};

const KDF_INFO_RATCHET = new TextEncoder().encode("AgentMesh_Ratchet_v1");
const NONCE_LEN = 12;
const KEY_LEN = 32;
const MAX_SKIP = 100;
/**
 * Aggregate cap on cached skipped keys across all DH rotations.
 *
 * The per-call cap (`maxSkip`) bounds a single skip burst within one
 * receive chain; this cap bounds the lifetime accumulation. Without it,
 * a session that survives many DH ratchet steps with persistent out-of-
 * order tails grows `skippedKeys` without limit. Mirrors the Python
 * core implementation (`_MAX_SKIPPED_KEYS_TOTAL`).
 */
const MAX_SKIPPED_KEYS_TOTAL = 2000;

export interface MessageHeader {
  dhPublicKey: Uint8Array;
  previousChainLength: number;
  messageNumber: number;
}

export interface EncryptedMessage {
  header: MessageHeader;
  ciphertext: Uint8Array;
}

export interface RatchetState {
  dhSelfPrivate: Uint8Array;
  dhSelfPublic: Uint8Array;
  dhRemotePublic: Uint8Array | null;
  rootKey: Uint8Array;
  chainKeySend: Uint8Array | null;
  chainKeyRecv: Uint8Array | null;
  sendMessageNumber: number;
  recvMessageNumber: number;
  previousSendChainLength: number;
  skippedKeys: Map<string, Uint8Array>;
}

function generateDHPair(): { privateKey: Uint8Array; publicKey: Uint8Array } {
  const privateKey = randomBytes(KEY_LEN);
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

function kdfRoot(rootKey: Uint8Array, dhOutput: Uint8Array): [Uint8Array, Uint8Array] {
  const derived = hkdf(sha256, dhOutput, rootKey, KDF_INFO_RATCHET, 64);
  return [derived.slice(0, 32), derived.slice(32)];
}

function kdfChain(chainKey: Uint8Array): [Uint8Array, Uint8Array] {
  const messageKey = hmac(sha256, chainKey, new Uint8Array([0x01]));
  const nextChainKey = hmac(sha256, chainKey, new Uint8Array([0x02]));
  return [messageKey, nextChainKey];
}

function encrypt(key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Uint8Array {
  const nonce = randomBytes(NONCE_LEN);
  const cipher = chacha20poly1305(key, nonce, aad);
  const ct = cipher.encrypt(plaintext);
  const result = new Uint8Array(NONCE_LEN + ct.length);
  result.set(nonce, 0);
  result.set(ct, NONCE_LEN);
  return result;
}

function decrypt(key: Uint8Array, data: Uint8Array, aad: Uint8Array): Uint8Array {
  if (data.length < NONCE_LEN) throw new Error("Ciphertext too short");
  const nonce = data.slice(0, NONCE_LEN);
  const ct = data.slice(NONCE_LEN);
  const cipher = chacha20poly1305(key, nonce, aad);
  return cipher.decrypt(ct);
}

function serializeHeader(h: MessageHeader): Uint8Array {
  const buf = new Uint8Array(40);
  buf.set(h.dhPublicKey, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(32, h.previousChainLength, false);
  view.setUint32(36, h.messageNumber, false);
  return buf;
}

function skippedKeyId(dhPub: Uint8Array, n: number): string {
  return `${Buffer.from(dhPub).toString("hex")}:${n}`;
}

// Used to detect a DH ratchet step by comparing the locally-cached
// `dhRemotePublic` against the attacker-controlled header's `dhPublicKey`.
// The per-byte early-return loop leaked match-prefix length via timing; the
// X25519 public keys involved are exchanged in the clear over the wire so
// the leak yields no new information in the current protocol, but
// `crypto.timingSafeEqual` is the right primitive for key-shaped material
// and protects against the same comparison being lifted into a future caller
// that does treat the public key as sensitive (e.g. an unpublished one-time
// pre-key the recipient committed to but never broadcast).
function arraysEqual(a: Uint8Array | null, b: Uint8Array | null): boolean {
  if (a === null || b === null) return a === b;
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export class DoubleRatchet {
  private state: RatchetState;
  private maxSkip: number;

  private constructor(state: RatchetState, maxSkip: number) {
    this.state = state;
    this.maxSkip = maxSkip;
  }

  static initSender(
    sharedSecret: Uint8Array,
    remoteDHPublic: Uint8Array,
    maxSkip = MAX_SKIP,
  ): DoubleRatchet {
    const dhSelf = generateDHPair();
    const dhOutput = x25519.getSharedSecret(dhSelf.privateKey, remoteDHPublic);
    const [rootKey, chainKeySend] = kdfRoot(sharedSecret, dhOutput);

    return new DoubleRatchet(
      {
        dhSelfPrivate: dhSelf.privateKey,
        dhSelfPublic: dhSelf.publicKey,
        dhRemotePublic: remoteDHPublic,
        rootKey,
        chainKeySend,
        chainKeyRecv: null,
        sendMessageNumber: 0,
        recvMessageNumber: 0,
        previousSendChainLength: 0,
        skippedKeys: new Map(),
      },
      maxSkip,
    );
  }

  static initReceiver(
    sharedSecret: Uint8Array,
    dhKeyPair: { privateKey: Uint8Array; publicKey: Uint8Array },
    maxSkip = MAX_SKIP,
  ): DoubleRatchet {
    return new DoubleRatchet(
      {
        dhSelfPrivate: dhKeyPair.privateKey,
        dhSelfPublic: dhKeyPair.publicKey,
        dhRemotePublic: null,
        rootKey: sharedSecret,
        chainKeySend: null,
        chainKeyRecv: null,
        sendMessageNumber: 0,
        recvMessageNumber: 0,
        previousSendChainLength: 0,
        skippedKeys: new Map(),
      },
      maxSkip,
    );
  }

  encrypt(plaintext: Uint8Array, associatedData: Uint8Array = new Uint8Array()): EncryptedMessage {
    const s = this.state;
    if (!s.chainKeySend) throw new Error("Send chain not initialized. Receive a message first.");

    const [messageKey, nextChainKey] = kdfChain(s.chainKeySend);
    s.chainKeySend = nextChainKey;

    const header: MessageHeader = {
      dhPublicKey: s.dhSelfPublic,
      previousChainLength: s.previousSendChainLength,
      messageNumber: s.sendMessageNumber,
    };
    s.sendMessageNumber++;

    const headerBytes = serializeHeader(header);
    const aad = new Uint8Array(headerBytes.length + associatedData.length);
    aad.set(associatedData, 0);
    aad.set(headerBytes, associatedData.length);

    const ciphertext = encrypt(messageKey, plaintext, aad);
    return { header, ciphertext };
  }

  decrypt(message: EncryptedMessage, associatedData: Uint8Array = new Uint8Array()): Uint8Array {
    const s = this.state;
    const { header } = message;

    const headerBytes = serializeHeader(header);
    const aad = new Uint8Array(headerBytes.length + associatedData.length);
    aad.set(associatedData, 0);
    aad.set(headerBytes, associatedData.length);

    // Check skipped keys
    const skipId = skippedKeyId(header.dhPublicKey, header.messageNumber);
    const skippedKey = s.skippedKeys.get(skipId);
    if (skippedKey) {
      s.skippedKeys.delete(skipId);
      return decrypt(skippedKey, message.ciphertext, aad);
    }

    // DH ratchet step if sender's key changed
    if (!arraysEqual(s.dhRemotePublic, header.dhPublicKey)) {
      this.skipMessages(header.previousChainLength);
      this.dhRatchetStep(header.dhPublicKey);
    }

    this.skipMessages(header.messageNumber);

    const [messageKey, nextChainKey] = kdfChain(s.chainKeyRecv!);
    s.chainKeyRecv = nextChainKey;
    s.recvMessageNumber++;

    return decrypt(messageKey, message.ciphertext, aad);
  }

  private dhRatchetStep(remoteDHPublic: Uint8Array): void {
    const s = this.state;
    s.previousSendChainLength = s.sendMessageNumber;
    s.sendMessageNumber = 0;
    s.recvMessageNumber = 0;
    s.dhRemotePublic = remoteDHPublic;

    let dhOutput = x25519.getSharedSecret(s.dhSelfPrivate, s.dhRemotePublic);
    [s.rootKey, s.chainKeyRecv] = kdfRoot(s.rootKey, dhOutput);

    const newDH = generateDHPair();
    s.dhSelfPrivate = newDH.privateKey;
    s.dhSelfPublic = newDH.publicKey;

    dhOutput = x25519.getSharedSecret(s.dhSelfPrivate, s.dhRemotePublic);
    [s.rootKey, s.chainKeySend] = kdfRoot(s.rootKey, dhOutput);
  }

  private skipMessages(until: number): void {
    const s = this.state;
    if (!s.chainKeyRecv) return;
    if (until - s.recvMessageNumber > this.maxSkip) {
      throw new Error(
        `Too many skipped messages (${until - s.recvMessageNumber} > ${this.maxSkip})`,
      );
    }
    while (s.recvMessageNumber < until) {
      const [mk, next] = kdfChain(s.chainKeyRecv);
      s.skippedKeys.set(skippedKeyId(s.dhRemotePublic!, s.recvMessageNumber), mk);
      s.chainKeyRecv = next;
      s.recvMessageNumber++;
      // Evict the oldest skipped key once the aggregate cap is exceeded.
      // ES2015+ `Map` iteration order is insertion order, so the first
      // key returned is the oldest insertion that survived all prior
      // evictions. Mirrors the Python core implementation.
      while (s.skippedKeys.size > MAX_SKIPPED_KEYS_TOTAL) {
        const oldest = s.skippedKeys.keys().next();
        if (oldest.done) break;
        s.skippedKeys.delete(oldest.value);
      }
    }
  }

  getState(): RatchetState {
    return { ...this.state, skippedKeys: new Map(this.state.skippedKeys) };
  }

  static fromState(state: RatchetState, maxSkip = MAX_SKIP): DoubleRatchet {
    return new DoubleRatchet(
      { ...state, skippedKeys: new Map(state.skippedKeys) },
      maxSkip,
    );
  }
}
