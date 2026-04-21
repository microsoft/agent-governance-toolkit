// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * X3DH (Extended Triple Diffie-Hellman) key agreement.
 *
 * Implements the Signal X3DH specification for establishing shared secrets
 * between agents. Uses Ed25519 identity keys converted to X25519 for DH.
 *
 * Spec: docs/specs/AGENTMESH-WIRE-1.0.md Section 7
 * Reference: https://signal.org/docs/specifications/x3dh/ (CC0)
 */

import { x25519 } from "@noble/curves/ed25519";
import { edwardsToMontgomeryPriv, edwardsToMontgomeryPub } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes } from "@noble/ciphers/webcrypto";

const X3DH_INFO = new TextEncoder().encode("AgentMesh_X3DH_v1");
const KEY_LEN = 32;
const FF_SALT = new Uint8Array(32).fill(0xff);

export interface X25519KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

export interface PreKeyBundle {
  identityKey: Uint8Array;
  signedPreKey: Uint8Array;
  signedPreKeySignature: Uint8Array;
  signedPreKeyId: number;
  oneTimePreKey?: Uint8Array;
  oneTimePreKeyId?: number;
}

export interface X3DHResult {
  sharedSecret: Uint8Array;
  ephemeralPublicKey: Uint8Array;
  usedOneTimeKeyId?: number;
  associatedData: Uint8Array;
}

export function generateX25519KeyPair(): X25519KeyPair {
  const privateKey = randomBytes(KEY_LEN);
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

export function ed25519ToX25519(
  ed25519Private: Uint8Array,
  ed25519Public: Uint8Array,
): X25519KeyPair {
  if (ed25519Public.length !== 32) {
    throw new Error("ed25519Public must be 32 bytes");
  }
  if (ed25519Private.length !== 32 && ed25519Private.length !== 64) {
    throw new Error("ed25519Private must be 32 or 64 bytes");
  }
  const priv32 = ed25519Private.length === 64 ? ed25519Private.slice(0, 32) : ed25519Private;
  const privateKey = edwardsToMontgomeryPriv(priv32);
  const publicKey = edwardsToMontgomeryPub(ed25519Public);
  return { privateKey, publicKey };
}

function kdf(ikm: Uint8Array): Uint8Array {
  return hkdf(sha256, ikm, FF_SALT, X3DH_INFO, KEY_LEN);
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

export class X3DHKeyManager {
  public readonly identityKey: X25519KeyPair;
  private readonly ed25519Private: Uint8Array;
  private readonly ed25519Public: Uint8Array;
  private signedPreKeyPair: { keyPair: X25519KeyPair; signature: Uint8Array; keyId: number } | null = null;
  private oneTimePreKeys: Map<number, X25519KeyPair> = new Map();
  private nextSpkId = 0;
  private nextOtkId = 0;

  constructor(ed25519Private: Uint8Array, ed25519Public: Uint8Array) {
    this.ed25519Private = ed25519Private.length === 64 ? ed25519Private.slice(0, 32) : ed25519Private;
    this.ed25519Public = ed25519Public;
    this.identityKey = ed25519ToX25519(ed25519Private, ed25519Public);
  }

  generateSignedPreKey(): { keyId: number; publicKey: Uint8Array; signature: Uint8Array } {
    const keyPair = generateX25519KeyPair();
    const signature = ed25519.sign(keyPair.publicKey, this.ed25519Private);
    const keyId = this.nextSpkId++;
    this.signedPreKeyPair = { keyPair, signature, keyId };
    return { keyId, publicKey: keyPair.publicKey, signature };
  }

  generateOneTimePreKeys(count: number): Array<{ keyId: number; publicKey: Uint8Array }> {
    const keys: Array<{ keyId: number; publicKey: Uint8Array }> = [];
    for (let i = 0; i < count; i++) {
      const keyPair = generateX25519KeyPair();
      const keyId = this.nextOtkId++;
      this.oneTimePreKeys.set(keyId, keyPair);
      keys.push({ keyId, publicKey: keyPair.publicKey });
    }
    return keys;
  }

  getPublicBundle(otkId?: number): PreKeyBundle {
    if (!this.signedPreKeyPair) {
      throw new Error("No signed pre-key generated. Call generateSignedPreKey() first.");
    }
    const bundle: PreKeyBundle = {
      identityKey: this.identityKey.publicKey,
      signedPreKey: this.signedPreKeyPair.keyPair.publicKey,
      signedPreKeySignature: this.signedPreKeyPair.signature,
      signedPreKeyId: this.signedPreKeyPair.keyId,
    };
    if (otkId !== undefined) {
      const otk = this.oneTimePreKeys.get(otkId);
      if (otk) {
        bundle.oneTimePreKey = otk.publicKey;
        bundle.oneTimePreKeyId = otkId;
      }
    }
    return bundle;
  }

  initiate(peerBundle: PreKeyBundle): X3DHResult {
    verifyBundle(peerBundle);

    const ephemeral = generateX25519KeyPair();

    const dh1 = x25519.getSharedSecret(this.identityKey.privateKey, peerBundle.signedPreKey);
    const dh2 = x25519.getSharedSecret(ephemeral.privateKey, peerBundle.identityKey);
    const dh3 = x25519.getSharedSecret(ephemeral.privateKey, peerBundle.signedPreKey);

    let dhConcat = concat(dh1, dh2, dh3);
    let usedOtkId: number | undefined;

    if (peerBundle.oneTimePreKey) {
      const dh4 = x25519.getSharedSecret(ephemeral.privateKey, peerBundle.oneTimePreKey);
      dhConcat = concat(dhConcat, dh4);
      usedOtkId = peerBundle.oneTimePreKeyId;
    }

    const sharedSecret = kdf(dhConcat);
    const ad = concat(this.identityKey.publicKey, peerBundle.identityKey);

    return {
      sharedSecret,
      ephemeralPublicKey: ephemeral.publicKey,
      usedOneTimeKeyId: usedOtkId,
      associatedData: ad,
    };
  }

  respond(
    peerIdentityKey: Uint8Array,
    ephemeralPublicKey: Uint8Array,
    usedOneTimeKeyId?: number,
  ): X3DHResult {
    if (!this.signedPreKeyPair) {
      throw new Error("No signed pre-key available.");
    }

    const dh1 = x25519.getSharedSecret(this.signedPreKeyPair.keyPair.privateKey, peerIdentityKey);
    const dh2 = x25519.getSharedSecret(this.identityKey.privateKey, ephemeralPublicKey);
    const dh3 = x25519.getSharedSecret(this.signedPreKeyPair.keyPair.privateKey, ephemeralPublicKey);

    let dhConcat = concat(dh1, dh2, dh3);

    if (usedOneTimeKeyId !== undefined) {
      const otk = this.oneTimePreKeys.get(usedOneTimeKeyId);
      if (!otk) {
        throw new Error(`One-time pre-key ${usedOneTimeKeyId} not found or already consumed.`);
      }
      const dh4 = x25519.getSharedSecret(otk.privateKey, ephemeralPublicKey);
      dhConcat = concat(dhConcat, dh4);
      this.oneTimePreKeys.delete(usedOneTimeKeyId);
    }

    const sharedSecret = kdf(dhConcat);
    const ad = concat(peerIdentityKey, this.identityKey.publicKey);

    return {
      sharedSecret,
      ephemeralPublicKey,
      usedOneTimeKeyId,
      associatedData: ad,
    };
  }

  get signedPreKey() {
    return this.signedPreKeyPair;
  }
}

function verifyBundle(bundle: PreKeyBundle): void {
  if (bundle.signedPreKeySignature.length !== 64) {
    throw new Error("Invalid signed pre-key signature length.");
  }
  if (bundle.signedPreKey.length !== 32) {
    throw new Error("Invalid signed pre-key length.");
  }
  if (bundle.identityKey.length !== 32) {
    throw new Error("Invalid identity key length.");
  }
}
