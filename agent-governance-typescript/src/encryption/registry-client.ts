// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * AgentMesh Registry HTTP client.
 *
 * Wraps the registry's REST surface (POST /v1/agents,
 * PUT/GET /v1/agents/{did}/prekeys, GET /v1/discover, GET/DELETE /v1/agents/{did})
 * with typed Uint8Array <-> base64url marshalling so callers stay in raw key
 * material on both sides of the wire.
 *
 * Spec: docs/specs/AGENTMESH-WIRE-1.0.md Section 13 (Registry)
 *
 * The optional `authSigner` lets callers attach an Ed25519-Timestamp
 * Authorization header when the registry is configured to require it
 * (verify_ed25519_timestamp_auth in agent-governance-python). Open
 * registries leave it unset.
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { type PreKeyBundle } from "./x3dh";

// ── base64url helpers (browser + node) ────────────────────────────

function toBase64Url(bytes: Uint8Array): string {
  // Node 18+ supports 'base64url' encoding. Fall back to btoa for browsers.
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64url");
  }
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(s: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(s, "base64url"));
  }
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ── Public types ─────────────────────────────────────────────────

export interface RegistryClientOptions {
  /** Base URL, e.g. "http://registry:8082" (no trailing /v1). */
  baseUrl: string;
  /**
   * Optional fetch implementation. Defaults to global fetch.
   * Override for proxy tunneling or test injection.
   */
  fetchImpl?: typeof fetch;
  /**
   * Optional Ed25519-Timestamp signer. When set, the client adds the
   * Authorization header to every request.
   */
  authSigner?: { did: string; sign: (msg: Uint8Array) => Uint8Array };
  /** Per-request timeout in ms (default 10_000). */
  timeoutMs?: number;
  /** Number of retry attempts for 5xx / network errors (default 2). */
  maxRetries?: number;
  /** Base retry delay in ms (default 250). */
  retryBaseDelayMs?: number;
}

export interface AgentRecord {
  did: string;
  capabilities: string[];
  metadata: Record<string, string>;
  registeredAt: Date;
  lastSeen: Date;
  reputationScore: number;
}

export interface DiscoverResult {
  did: string;
  capabilities: string[];
  reputationScore: number;
  lastSeen: Date;
}

export class RegistryError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly body: string,
  ) {
    super(message);
    this.name = "RegistryError";
  }
}

// ── Implementation ───────────────────────────────────────────────

export class RegistryClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly authSigner?: RegistryClientOptions["authSigner"];
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly retryBaseDelayMs: number;

  constructor(opts: RegistryClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/$/, "");
    this.fetchImpl = opts.fetchImpl ?? globalThis.fetch.bind(globalThis);
    this.authSigner = opts.authSigner;
    this.timeoutMs = opts.timeoutMs ?? 10_000;
    this.maxRetries = opts.maxRetries ?? 2;
    this.retryBaseDelayMs = opts.retryBaseDelayMs ?? 250;
  }

  // ── Registration ───────────────────────────────────────────────

  /**
   * Register the agent in the registry. Idempotent: a 409 response
   * (already registered) resolves successfully without throwing.
   *
   * @param identityKey   X25519 long-term identity public key (32 bytes)
   * @param capabilities  Capability strings the agent advertises. Include
   *                      friendly display name here so peers can find this
   *                      agent via `discover(name)`.
   * @param metadata      Arbitrary string metadata (e.g. {display_name}).
   */
  async register(
    did: string,
    identityKey: Uint8Array,
    capabilities: string[] = [],
    metadata: Record<string, string> = {},
  ): Promise<void> {
    if (identityKey.length !== 32) {
      throw new Error(
        `RegistryClient.register: identityKey must be 32 bytes, got ${identityKey.length}`,
      );
    }
    const body = JSON.stringify({
      did,
      public_key: toBase64Url(identityKey),
      capabilities,
      metadata,
    });
    const resp = await this.request("POST", "/v1/agents", body);
    if (resp.status === 201 || resp.status === 200) return;
    if (resp.status === 409) return; // already registered — idempotent
    throw new RegistryError(
      `register failed: ${resp.status}`,
      resp.status,
      resp.bodyText,
    );
  }

  /** Look up an agent record. Returns null on 404. */
  async getAgent(did: string): Promise<AgentRecord | null> {
    const resp = await this.request("GET", `/v1/agents/${encodeURIComponent(did)}`);
    if (resp.status === 404) return null;
    if (!resp.ok) {
      throw new RegistryError(`getAgent failed: ${resp.status}`, resp.status, resp.bodyText);
    }
    const j = JSON.parse(resp.bodyText) as {
      did: string;
      capabilities: string[];
      metadata: Record<string, string>;
      registered_at: string;
      last_seen: string;
      reputation_score: number;
    };
    return {
      did: j.did,
      capabilities: j.capabilities,
      metadata: j.metadata,
      registeredAt: new Date(j.registered_at),
      lastSeen: new Date(j.last_seen),
      reputationScore: j.reputation_score,
    };
  }

  /** Deregister an agent. */
  async deleteAgent(did: string): Promise<void> {
    const resp = await this.request("DELETE", `/v1/agents/${encodeURIComponent(did)}`);
    if (resp.status === 204 || resp.status === 404) return;
    if (!resp.ok) {
      throw new RegistryError(`deleteAgent failed: ${resp.status}`, resp.status, resp.bodyText);
    }
  }

  // ── Pre-Keys ───────────────────────────────────────────────────

  /**
   * Upload a pre-key bundle. Replaces any existing bundle for this DID.
   *
   * @param identityKey   X25519 long-term key (32 bytes).
   * @param identityKeyEd Ed25519 signing key (32 bytes) — REQUIRED for
   *                      receivers to verify the signed pre-key signature.
   *                      Pass `keyManager.identityKeyEd`.
   * @param signedPreKey  Output of X3DHKeyManager.generateSignedPreKey()
   * @param oneTimePreKeys Output of X3DHKeyManager.generateOneTimePreKeys(N)
   */
  async uploadPrekeys(
    did: string,
    identityKey: Uint8Array,
    identityKeyEd: Uint8Array,
    signedPreKey: { keyId: number; publicKey: Uint8Array; signature: Uint8Array },
    oneTimePreKeys: ReadonlyArray<{ keyId: number; publicKey: Uint8Array }>,
  ): Promise<void> {
    if (identityKey.length !== 32) {
      throw new Error(
        `RegistryClient.uploadPrekeys: identityKey must be 32 bytes, got ${identityKey.length}`,
      );
    }
    if (identityKeyEd.length !== 32) {
      throw new Error(
        `RegistryClient.uploadPrekeys: identityKeyEd must be 32 bytes, got ${identityKeyEd.length}`,
      );
    }
    const body = JSON.stringify({
      identity_key: toBase64Url(identityKey),
      identity_key_ed: toBase64Url(identityKeyEd),
      signed_pre_key: {
        key_id: signedPreKey.keyId,
        public_key: toBase64Url(signedPreKey.publicKey),
        signature: toBase64Url(signedPreKey.signature),
      },
      one_time_pre_keys: oneTimePreKeys.map((otk) => ({
        key_id: otk.keyId,
        public_key: toBase64Url(otk.publicKey),
      })),
    });
    const resp = await this.request(
      "PUT",
      `/v1/agents/${encodeURIComponent(did)}/prekeys`,
      body,
    );
    if (!resp.ok) {
      throw new RegistryError(
        `uploadPrekeys failed: ${resp.status}`,
        resp.status,
        resp.bodyText,
      );
    }
  }

  /**
   * Fetch a peer's pre-key bundle for X3DH initiation. Atomically
   * consumes one OPK on the registry side. Returns null on 404 (no
   * bundle published).
   *
   * The returned PreKeyBundle is shaped for direct use with
   * SecureChannel.createSender() / X3DHKeyManager.
   *
   * `identityKeyEd` (Ed25519, used to verify the signed pre-key
   * signature) is included when the publisher uploaded it via
   * `uploadPrekeys()`. Bundles that lack identity_key_ed (older clients)
   * will fail verifyBundle() — peers must upgrade.
   */
  async fetchPrekeys(did: string): Promise<PreKeyBundle | null> {
    const resp = await this.request(
      "GET",
      `/v1/agents/${encodeURIComponent(did)}/prekeys`,
    );
    if (resp.status === 404) return null;
    if (!resp.ok) {
      throw new RegistryError(
        `fetchPrekeys failed: ${resp.status}`,
        resp.status,
        resp.bodyText,
      );
    }
    const j = JSON.parse(resp.bodyText) as {
      identity_key: string;
      identity_key_ed?: string | null;
      signed_pre_key: { key_id: number; public_key: string; signature: string };
      one_time_pre_key: { key_id: number; public_key: string } | null;
    };
    const identityKey = fromBase64Url(j.identity_key);
    // Fall back to X25519 identity_key only when the publisher didn't
    // upload identity_key_ed. verifyBundle() will reject this case
    // (correctly) — it's preserved for forensic visibility, not to
    // silently bypass signature checks.
    const identityKeyEd = j.identity_key_ed
      ? fromBase64Url(j.identity_key_ed)
      : identityKey;
    const bundle: PreKeyBundle = {
      identityKey,
      identityKeyEd,
      signedPreKey: fromBase64Url(j.signed_pre_key.public_key),
      signedPreKeySignature: fromBase64Url(j.signed_pre_key.signature),
      signedPreKeyId: j.signed_pre_key.key_id,
    };
    if (j.one_time_pre_key) {
      bundle.oneTimePreKey = fromBase64Url(j.one_time_pre_key.public_key);
      bundle.oneTimePreKeyId = j.one_time_pre_key.key_id;
    }
    return bundle;
  }

  // ── Discovery ──────────────────────────────────────────────────

  /**
   * Search agents by capability. Capability matching on the registry
   * side is exact-string (no globs); to find a friendly name, the agent
   * must have published that name in its capabilities array at register
   * time.
   */
  async discover(capability: string, limit = 50): Promise<DiscoverResult[]> {
    const path = `/v1/discover?capability=${encodeURIComponent(capability)}&limit=${limit}`;
    const resp = await this.request("GET", path);
    if (!resp.ok) {
      throw new RegistryError(`discover failed: ${resp.status}`, resp.status, resp.bodyText);
    }
    const j = JSON.parse(resp.bodyText) as {
      results: Array<{
        did: string;
        capabilities: string[];
        reputation_score: number;
        last_seen: string;
      }>;
      total: number;
    };
    return j.results.map((r) => ({
      did: r.did,
      capabilities: r.capabilities,
      reputationScore: r.reputation_score,
      lastSeen: new Date(r.last_seen),
    }));
  }

  // ── Internal request plumbing ──────────────────────────────────

  private async request(
    method: string,
    path: string,
    body?: string,
  ): Promise<{ ok: boolean; status: number; bodyText: string }> {
    let lastErr: unknown;
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      try {
        const result = await this.requestOnce(method, path, body);
        // Retry on 5xx; succeed/return on 2xx and 4xx.
        if (result.status >= 500 && result.status < 600 && attempt < this.maxRetries) {
          await this.delay(this.retryBaseDelayMs * 2 ** attempt);
          continue;
        }
        return result;
      } catch (e) {
        lastErr = e;
        if (attempt < this.maxRetries) {
          await this.delay(this.retryBaseDelayMs * 2 ** attempt);
          continue;
        }
        throw e;
      }
    }
    // Unreachable, but keeps TS happy.
    throw lastErr ?? new Error("RegistryClient.request: exhausted retries");
  }

  private async requestOnce(
    method: string,
    path: string,
    body?: string,
  ): Promise<{ ok: boolean; status: number; bodyText: string }> {
    const headers: Record<string, string> = {};
    if (body !== undefined) headers["content-type"] = "application/json";
    if (this.authSigner) {
      const ts = new Date().toISOString();
      const sig = this.authSigner.sign(new TextEncoder().encode(ts));
      headers["authorization"] = `Ed25519-Timestamp ${this.authSigner.did} ${ts} ${toBase64Url(sig)}`;
    }
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), this.timeoutMs);
    try {
      const resp = await this.fetchImpl(`${this.baseUrl}${path}`, {
        method,
        headers,
        body,
        signal: ac.signal,
      });
      const bodyText = await resp.text();
      return { ok: resp.ok, status: resp.status, bodyText };
    } finally {
      clearTimeout(timer);
    }
  }

  private delay(ms: number): Promise<void> {
    return new Promise((r) => setTimeout(r, ms));
  }
}

// ── Convenience: build an authSigner from an Ed25519 private key ──

/**
 * Build an authSigner suitable for RegistryClientOptions.authSigner
 * from a 32-byte Ed25519 secret key. This is a thin wrapper around
 * @noble/curves so callers don't need to import noble themselves.
 */
export function ed25519AuthSigner(
  did: string,
  ed25519PrivateKey: Uint8Array,
): NonNullable<RegistryClientOptions["authSigner"]> {
  const sk = ed25519PrivateKey.length === 64 ? ed25519PrivateKey.slice(0, 32) : ed25519PrivateKey;
  return {
    did,
    sign: (msg: Uint8Array) => ed25519.sign(msg, sk),
  };
}
