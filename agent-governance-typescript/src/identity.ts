// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { AgentIdentityJSON, IdentityStatus } from './types';
import { createHash, sign, verify, generateKeyPairSync, KeyObject } from 'crypto';

/**
 * Agent identity built on Ed25519 key pairs, DID identifiers,
 * lifecycle management, delegation chains, and JWK support.
 *
 * Full parity with the Python and .NET SDK AgentIdentity classes.
 */
export class AgentIdentity {
  readonly did: string;
  readonly publicKey: Uint8Array;
  private readonly _privateKey: Uint8Array;
  private readonly _capabilities: string[];

  // Metadata
  readonly name: string;
  readonly description: string;
  readonly sponsor: string;
  readonly organization: string;
  readonly createdAt: Date;
  readonly expiresAt: Date | null;

  // Lifecycle
  private _status: IdentityStatus;

  // Delegation
  private _parentDid: string | null;
  private _delegationDepth: number;

  private constructor(opts: {
    did: string;
    publicKey: Uint8Array;
    privateKey: Uint8Array;
    capabilities: string[];
    name?: string;
    description?: string;
    sponsor?: string;
    organization?: string;
    status?: IdentityStatus;
    parentDid?: string | null;
    delegationDepth?: number;
    createdAt?: Date;
    expiresAt?: Date | null;
  }) {
    this.did = opts.did;
    this.publicKey = opts.publicKey;
    this._privateKey = opts.privateKey;
    this._capabilities = opts.capabilities;
    this.name = opts.name ?? '';
    this.description = opts.description ?? '';
    this.sponsor = opts.sponsor ?? '';
    this.organization = opts.organization ?? '';
    this._status = opts.status ?? 'active';
    this._parentDid = opts.parentDid ?? null;
    this._delegationDepth = opts.delegationDepth ?? 0;
    this.createdAt = opts.createdAt ?? new Date();
    this.expiresAt = opts.expiresAt ?? null;
  }

  // ── Factory methods ──

  /** Generate a new agent identity with an Ed25519 key pair. */
  static generate(
    agentId: string,
    capabilities: string[] = [],
    opts?: {
      name?: string;
      description?: string;
      sponsor?: string;
      organization?: string;
      expiresAt?: Date;
    },
  ): AgentIdentity {
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

    return new AgentIdentity({
      did,
      publicKey: pubBytes,
      privateKey: privBytes,
      capabilities,
      name: opts?.name ?? agentId,
      description: opts?.description,
      sponsor: opts?.sponsor,
      organization: opts?.organization,
      expiresAt: opts?.expiresAt ?? null,
    });
  }

  // ── Cryptographic operations ──

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

  // ── Lifecycle management ──

  get status(): IdentityStatus {
    return this._status;
  }

  /** Check if the identity is active and not expired. */
  isActive(): boolean {
    if (this._status !== 'active') return false;
    if (this.expiresAt && new Date() > this.expiresAt) return false;
    return true;
  }

  /** Suspend this identity temporarily. */
  suspend(reason?: string): void {
    if (this._status === 'revoked') {
      throw new Error('Cannot suspend a revoked identity');
    }
    this._status = 'suspended';
  }

  /** Revoke this identity permanently. */
  revoke(reason?: string): void {
    this._status = 'revoked';
  }

  /** Reactivate a suspended identity. */
  reactivate(): void {
    if (this._status === 'revoked') {
      throw new Error('Cannot reactivate a revoked identity');
    }
    this._status = 'active';
  }

  // ── Capabilities ──

  get capabilities(): readonly string[] {
    return this._capabilities;
  }

  /** Check if this agent has a specific capability. Supports wildcard matching. */
  hasCapability(capability: string): boolean {
    for (const cap of this._capabilities) {
      if (cap === '*') return true;
      if (cap === capability) return true;
      // Prefix wildcard: "read:*" matches "read:data"
      if (cap.endsWith(':*')) {
        const prefix = cap.slice(0, -2);
        if (capability.startsWith(prefix + ':')) return true;
      }
    }
    return false;
  }

  // ── Delegation ──

  get parentDid(): string | null {
    return this._parentDid;
  }

  get delegationDepth(): number {
    return this._delegationDepth;
  }

  /**
   * Delegate to a child agent with narrowed capabilities.
   * Child capabilities MUST be a subset of the parent's.
   */
  delegate(
    name: string,
    capabilities: string[],
    opts?: { description?: string; sponsor?: string; organization?: string; expiresAt?: Date },
  ): AgentIdentity {
    // Validate capabilities are a subset
    for (const cap of capabilities) {
      if (!this.hasCapability(cap)) {
        throw new Error(
          `Cannot delegate capability '${cap}' — not in parent's capabilities`,
        );
      }
    }

    const child = AgentIdentity.generate(name, capabilities, {
      name,
      description: opts?.description,
      sponsor: opts?.sponsor ?? this.sponsor,
      organization: opts?.organization ?? this.organization,
      expiresAt: opts?.expiresAt,
    });

    // Set delegation metadata
    (child as unknown as { _parentDid: string | null })._parentDid = this.did;
    (child as unknown as { _delegationDepth: number })._delegationDepth = this._delegationDepth + 1;

    return child;
  }

  // ── JWK / JWKS ──

  /** Export this identity as a JWK (JSON Web Key, RFC 7517). */
  toJWK(includePrivate: boolean = false): Record<string, unknown> {
    // Ed25519 public key: strip the SPKI header to get raw 32 bytes
    const rawPub = this.getRawPublicKeyBytes();
    const jwk: Record<string, unknown> = {
      kty: 'OKP',
      crv: 'Ed25519',
      x: base64urlEncode(rawPub),
      kid: this.did,
      use: 'sig',
    };

    if (includePrivate && this._privateKey.length > 0) {
      const rawPriv = this.getRawPrivateKeyBytes();
      jwk.d = base64urlEncode(rawPriv);
    }

    return jwk;
  }

  /** Create an AgentIdentity from a JWK. */
  static fromJWK(jwk: Record<string, unknown>): AgentIdentity {
    if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') {
      throw new Error('JWK must be Ed25519 (kty: OKP, crv: Ed25519)');
    }

    const rawPub = base64urlDecode(jwk.x as string);
    const crypto = require('crypto');

    const publicKeyObject = crypto.createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, rawPub]),
      format: 'der',
      type: 'spki',
    }) as KeyObject;

    const pubBytes = new Uint8Array(
      publicKeyObject.export({ type: 'spki', format: 'der' }),
    );

    let privBytes = new Uint8Array(0);
    if (jwk.d) {
      const rawPriv = base64urlDecode(jwk.d as string);
      const privateKeyObject = crypto.createPrivateKey({
        key: Buffer.concat([ED25519_PKCS8_PREFIX, rawPriv]),
        format: 'der',
        type: 'pkcs8',
      }) as KeyObject;
      privBytes = new Uint8Array(
        privateKeyObject.export({ type: 'pkcs8', format: 'der' }),
      );
    }

    const did = (jwk.kid as string) ?? `did:agentmesh:imported:${createHash('sha256').update(pubBytes).digest('hex').slice(0, 16)}`;

    return new AgentIdentity({
      did,
      publicKey: pubBytes,
      privateKey: privBytes,
      capabilities: [],
    });
  }

  /** Export as a JWK Set. */
  toJWKS(includePrivate: boolean = false): { keys: Record<string, unknown>[] } {
    return { keys: [this.toJWK(includePrivate)] };
  }

  /** Import from a JWK Set. */
  static fromJWKS(
    jwks: { keys: Record<string, unknown>[] },
    kid?: string,
  ): AgentIdentity {
    const keys = jwks.keys;
    if (!keys || keys.length === 0) {
      throw new Error('JWKS contains no keys');
    }
    const match = kid ? keys.find((k) => k.kid === kid) : keys[0];
    if (!match) {
      throw new Error(`No key with kid '${kid}' found in JWKS`);
    }
    return AgentIdentity.fromJWK(match);
  }

  // ── DID Document ──

  /** Export as a W3C DID Document. */
  toDIDDocument(): Record<string, unknown> {
    const keyId = `${this.did}#key-${createHash('sha256').update(this.publicKey).digest('hex').slice(0, 16)}`;
    return {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: this.did,
      verificationMethod: [
        {
          id: keyId,
          type: 'Ed25519VerificationKey2020',
          controller: this.did,
          publicKeyBase64: Buffer.from(this.publicKey).toString('base64'),
        },
      ],
      authentication: [keyId],
      service: [
        {
          id: `${this.did}#agentmesh`,
          type: 'AgentMeshIdentity',
          serviceEndpoint: 'https://mesh.agentmesh.dev/v1',
        },
      ],
    };
  }

  // ── Serialization ──

  /** Serialize to a plain JSON-safe object. */
  toJSON(): AgentIdentityJSON {
    return {
      did: this.did,
      publicKey: Buffer.from(this.publicKey).toString('base64'),
      privateKey: Buffer.from(this._privateKey).toString('base64'),
      capabilities: [...this._capabilities],
      name: this.name || undefined,
      description: this.description || undefined,
      sponsor: this.sponsor || undefined,
      organization: this.organization || undefined,
      status: this._status !== 'active' ? this._status : undefined,
      parentDid: this._parentDid ?? undefined,
      delegationDepth: this._delegationDepth > 0 ? this._delegationDepth : undefined,
      createdAt: this.createdAt.toISOString(),
      expiresAt: this.expiresAt ? this.expiresAt.toISOString() : undefined,
    };
  }

  /** Reconstruct an AgentIdentity from its JSON representation. */
  static fromJSON(json: AgentIdentityJSON): AgentIdentity {
    const pubKey = new Uint8Array(safeBase64Decode(json.publicKey));
    const privKey = json.privateKey
      ? new Uint8Array(safeBase64Decode(json.privateKey))
      : new Uint8Array(0);
    return new AgentIdentity({
      did: json.did,
      publicKey: pubKey,
      privateKey: privKey,
      capabilities: json.capabilities ?? [],
      name: json.name,
      description: json.description,
      sponsor: json.sponsor,
      organization: json.organization,
      status: json.status ?? 'active',
      parentDid: json.parentDid ?? null,
      delegationDepth: json.delegationDepth ?? 0,
      createdAt: json.createdAt ? new Date(json.createdAt) : undefined,
      expiresAt: json.expiresAt ? new Date(json.expiresAt) : null,
    });
  }

  // ── Raw key extraction for JWK ──

  private getRawPublicKeyBytes(): Buffer {
    // SPKI DER for Ed25519 has a 12-byte prefix before the 32-byte raw key
    const derBuf = Buffer.from(this.publicKey);
    return derBuf.subarray(derBuf.length - 32);
  }

  private getRawPrivateKeyBytes(): Buffer {
    // PKCS8 DER for Ed25519 has a prefix before the raw 32-byte key seed
    // The last 32 bytes of the wrapped key are the seed
    const derBuf = Buffer.from(this._privateKey);
    return derBuf.subarray(derBuf.length - 32);
  }
}

// ── Identity Registry ──

/**
 * Registry for agent identities, matching Python IdentityRegistry.
 */
export class IdentityRegistry {
  private _identities: Map<string, AgentIdentity> = new Map();
  private _bySponsor: Map<string, string[]> = new Map();

  /** Register an identity. */
  register(identity: AgentIdentity): void {
    if (this._identities.has(identity.did)) {
      throw new Error(`Identity already registered: ${identity.did}`);
    }
    this._identities.set(identity.did, identity);

    if (identity.sponsor) {
      const existing = this._bySponsor.get(identity.sponsor) ?? [];
      existing.push(identity.did);
      this._bySponsor.set(identity.sponsor, existing);
    }
  }

  /** Get an identity by DID. */
  get(did: string): AgentIdentity | undefined {
    return this._identities.get(did);
  }

  /** Revoke an identity and all its delegates. */
  revoke(did: string, reason: string): boolean {
    return this.revokeRecursive(did, reason, new Set<string>());
  }

  /**
   * Recurse through the parent→child delegation graph, revoking each
   * reachable identity exactly once. `visited` is shared across the whole
   * traversal so a cycle in the `parentDid` relation (which should not
   * arise via the public `delegate()` API, but could be constructed from a
   * corrupted store, a custom builder, or a bug elsewhere) terminates
   * after each node is processed once instead of recursing forever and
   * eventually overflowing the JS call stack.
   */
  private revokeRecursive(did: string, reason: string, visited: Set<string>): boolean {
    if (visited.has(did)) return false;
    visited.add(did);

    const identity = this._identities.get(did);
    if (!identity) return false;
    identity.revoke(reason);

    for (const [childDid, child] of this._identities) {
      if (child.parentDid === did) {
        this.revokeRecursive(childDid, `Parent revoked: ${reason}`, visited);
      }
    }
    return true;
  }

  /** Get all identities for a sponsor. */
  getBySponsor(sponsor: string): AgentIdentity[] {
    const dids = this._bySponsor.get(sponsor) ?? [];
    return dids
      .map((did) => this._identities.get(did))
      .filter((id): id is AgentIdentity => id !== undefined);
  }

  /** List all active identities. */
  listActive(): AgentIdentity[] {
    return [...this._identities.values()].filter((id) => id.isActive());
  }

  /** Total number of registered identities. */
  get size(): number {
    return this._identities.size;
  }
}

// ── Key prefix stripping ──
// Ported from AzureClaw vendor SDK — keys serialized with type prefixes
// (e.g. "ed25519:<base64>") fail to decode without stripping the prefix first.

/**
 * Strip a key type prefix (e.g. "ed25519:", "x25519:") before base64 decoding.
 * Handles three cases:
 *   1. Key starts with the expected prefix → strips it.
 *   2. Key starts with a *different* known prefix → strips it with a warning.
 *   3. Key has no prefix → returns as-is with a warning.
 */
export function stripKeyPrefix(keyStr: string, expectedPrefix: string): string {
  if (keyStr.startsWith(expectedPrefix)) {
    return keyStr.slice(expectedPrefix.length);
  }
  const colonIdx = keyStr.indexOf(':');
  if (colonIdx !== -1) {
    console.warn(`Key has unexpected prefix, expected '${expectedPrefix}'`);
    return keyStr.slice(colonIdx + 1);
  }
  // No prefix at all — still valid, just not prefixed
  return keyStr;
}

/**
 * Safely decode a base64 key string that may carry a type prefix.
 * Strips "ed25519:" / "x25519:" before decoding.
 */
export function safeBase64Decode(b64: string): Buffer {
  let raw = b64;
  if (raw.startsWith('ed25519:')) raw = raw.slice(8);
  else if (raw.startsWith('x25519:')) raw = raw.slice(7);
  return Buffer.from(raw, 'base64');
}

// ── Ed25519 DER prefixes ──

// SPKI prefix for Ed25519 (12 bytes) — OID 1.3.101.112
const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

// PKCS8 prefix for Ed25519 (16 bytes)
const ED25519_PKCS8_PREFIX = Buffer.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
  0x04, 0x22, 0x04, 0x20,
]);

// ── Base64url helpers ──

function base64urlEncode(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlDecode(s: string): Buffer {
  let b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) b64 += '=';
  return Buffer.from(b64, 'base64');
}
