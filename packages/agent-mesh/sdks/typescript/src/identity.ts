// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { AgentIdentityJSON } from './types';
import { createHash, randomBytes, sign, verify, generateKeyPairSync } from 'crypto';

/**
 * Agent identity built on Ed25519 key pairs and DID identifiers.
 */
export class AgentIdentity {
  readonly did: string;
  readonly publicKey: Uint8Array;
  private readonly _privateKey: Uint8Array;
  private readonly _capabilities: string[];

  private constructor(
    did: string,
    publicKey: Uint8Array,
    privateKey: Uint8Array,
    capabilities: string[],
  ) {
    this.did = did;
    this.publicKey = publicKey;
    this._privateKey = privateKey;
    this._capabilities = capabilities;
  }

  /** Generate a new agent identity with an Ed25519 key pair. */
  static generate(agentId: string, capabilities: string[] = []): AgentIdentity {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');

    const pubBytes = new Uint8Array(
      publicKey.export({ type: 'spki', format: 'der' }),
    );
    const privBytes = new Uint8Array(
      privateKey.export({ type: 'pkcs8', format: 'der' }),
    );

    const fingerprint = createHash('sha256')
      .update(pubBytes)
      .digest('hex')
      .slice(0, 16);

    const did = `did:agentmesh:${agentId}:${fingerprint}`;

    return new AgentIdentity(did, pubBytes, privBytes, capabilities);
  }

  /** Sign arbitrary data and return the signature bytes. */
  sign(data: Uint8Array): Uint8Array {
    const privateKeyObject = require('crypto').createPrivateKey({
      key: Buffer.from(this._privateKey),
      format: 'der',
      type: 'pkcs8',
    });
    const sig = sign(null, Buffer.from(data), privateKeyObject);
    return new Uint8Array(sig);
  }

  /** Verify a signature against this identity's public key. */
  verify(data: Uint8Array, signature: Uint8Array): boolean {
    try {
      const publicKeyObject = require('crypto').createPublicKey({
        key: Buffer.from(this.publicKey),
        format: 'der',
        type: 'spki',
      });
      return verify(null, Buffer.from(data), publicKeyObject, Buffer.from(signature));
    } catch {
      return false;
    }
  }

  /** Serialize to a plain JSON-safe object. */
  toJSON(): AgentIdentityJSON {
    return {
      did: this.did,
      publicKey: Buffer.from(this.publicKey).toString('base64'),
      privateKey: Buffer.from(this._privateKey).toString('base64'),
      capabilities: [...this._capabilities],
    };
  }

  /** Reconstruct an AgentIdentity from its JSON representation. */
  static fromJSON(json: AgentIdentityJSON): AgentIdentity {
    const pubKey = new Uint8Array(Buffer.from(json.publicKey, 'base64'));
    const privKey = json.privateKey
      ? new Uint8Array(Buffer.from(json.privateKey, 'base64'))
      : new Uint8Array(0);
    return new AgentIdentity(json.did, pubKey, privKey, json.capabilities ?? []);
  }

  get capabilities(): readonly string[] {
    return this._capabilities;
  }
}
