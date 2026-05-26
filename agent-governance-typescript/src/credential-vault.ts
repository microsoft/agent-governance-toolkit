// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Credential vault, scoping, and injection for agent tool calls.
 *
 * TypeScript port of the Python `agent_os.credential_vault` primitive
 * (issue #2481, PR #2534). Tracking issue: #2535.
 *
 * Design goals (identical to the Python reference):
 *
 * 1. **Value boundary** — agents never receive resolved secret values. They
 *    reference credentials by opaque handle names; only the injector ever
 *    holds the resolved value, and only long enough to render a payload.
 * 2. **Authority boundary** — every resolution is gated by a per-agent
 *    {@link CredentialProfile} that binds an *action capability* (not just
 *    an agent identity) to a specific credential handle.
 * 3. **Policy-first** — placeholder substitution happens *after* the
 *    workflow policy callback returns `allow=true`.
 * 4. **Deterministic deny** — denied resolutions emit the same opaque
 *    {@link DenyReceipt} regardless of whether the handle is missing,
 *    bound to a different agent, or denied by policy.
 * 5. **Untrusted server metadata** — only placeholders whose names appear
 *    in the caller-supplied `allowedHandles` set are eligible for
 *    substitution. Anything else is treated as injection.
 * 6. **Rotation without rebinding** — credential values rotate in place;
 *    the handle name is stable so prompts, MCP descriptions, and saved
 *    plans never need to change.
 *
 * Encrypted-at-rest persistence uses AES-256-GCM (`@noble/ciphers`) with
 * a 12-byte random nonce prefixed to the ciphertext. If no persistence
 * path is configured the vault is memory-only.
 *
 * Wire-format note: this SDK uses AES-256-GCM; the Python SDK uses Fernet.
 * A cross-language interop spec is tracked in issue #2535 and the two
 * formats are not currently interchangeable.
 */

import { promises as fs } from 'node:fs';
import * as path from 'node:path';

import { gcm } from '@noble/ciphers/aes.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes, bytesToHex, randomBytes } from '@noble/hashes/utils.js';

// ---------------------------------------------------------------------------
// Public constants
// ---------------------------------------------------------------------------

/** Regex matching the credential placeholder syntax `{{cred:NAME}}`. */
export const PLACEHOLDER_RE = /\{\{\s*cred:([A-Za-z0-9_.\-]{1,128})\s*\}\}/g;

/** Stable string returned in audit/deny records when a request is refused. */
export const DENY_REASON = 'credential_denied';

/** Outcome of a credential resolution attempt. */
export type CredentialDecision = 'allow' | 'deny';

/** AES-GCM key length (bytes). */
const KEY_LENGTH = 32;
/** AES-GCM nonce length (bytes). */
const NONCE_LENGTH = 12;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class CredentialError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CredentialError';
  }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CredentialRecord {
  readonly name: string;
  readonly value: string;
  readonly credType: string;
  readonly version: number;
  readonly createdAt: number;
  readonly rotatedAt: number | null;
}

/**
 * Opaque handle an agent may reference. Holding a handle does **not** grant
 * access to the underlying value; resolution requires the vault, the
 * agent's DID, and an action capability binding.
 */
export class CredentialHandle {
  readonly name: string;
  constructor(name: string) {
    this.name = name;
  }
  /** Return the `{{cred:NAME}}` placeholder for this handle. */
  placeholder(): string {
    return `{{cred:${this.name}}}`;
  }
  toString(): string {
    return `<CredentialHandle ${this.name}>`;
  }
}

/**
 * Per-agent capability binding.
 *
 * A profile maps action capabilities (e.g. `github:read_issues`,
 * `github:push_code`) to the credential handle name that may be used to
 * fulfil that capability. Two capabilities that share an underlying
 * credential are still modelled as separate bindings so revoking one does
 * not implicitly revoke the other.
 */
export class CredentialProfile {
  readonly agentDid: string;
  private readonly _bindings: ReadonlyMap<string, string>;

  constructor(agentDid: string, bindings: Record<string, string> | Map<string, string>) {
    if (!agentDid) {
      throw new TypeError('agentDid must be a non-empty string');
    }
    this.agentDid = agentDid;
    const entries = bindings instanceof Map ? [...bindings.entries()] : Object.entries(bindings);
    this._bindings = new Map(entries);
  }

  /** Return the handle name bound to `actionClass`, or undefined. */
  capabilityFor(actionClass: string): string | undefined {
    return this._bindings.get(actionClass);
  }

  /** Snapshot of bindings (read-only). */
  get bindings(): ReadonlyMap<string, string> {
    return this._bindings;
  }
}

export interface VaultAuditEvent {
  readonly timestamp: number;
  readonly agentDid: string;
  readonly handleName: string;
  readonly targetService: string;
  readonly actionClass: string;
  readonly decision: CredentialDecision;
  readonly policyVersion: string;
  readonly reason: string;
}

/** Deterministic deny output returned in place of a rendered payload. */
export class DenyReceipt {
  readonly reason: string;
  readonly actionClass: string;
  readonly targetService: string;
  constructor(opts: { actionClass?: string; targetService?: string; reason?: string } = {}) {
    this.reason = opts.reason ?? DENY_REASON;
    this.actionClass = opts.actionClass ?? '';
    this.targetService = opts.targetService ?? '';
  }
  toJSON(): Record<string, string> {
    return {
      reason: this.reason,
      actionClass: this.actionClass,
      targetService: this.targetService,
    };
  }
  equals(other: DenyReceipt): boolean {
    return (
      this.reason === other.reason &&
      this.actionClass === other.actionClass &&
      this.targetService === other.targetService
    );
  }
}

// ---------------------------------------------------------------------------
// Vault
// ---------------------------------------------------------------------------

const NAME_RE = /^[A-Za-z0-9_.\-]{1,128}$/;

export interface CredentialVaultOptions {
  /** Optional filesystem path for encrypted persistence. */
  persistPath?: string;
  /** AES-256-GCM key (exactly 32 bytes). Required when `persistPath` is set. */
  encryptionKey?: Uint8Array;
}

/**
 * Encrypted-at-rest credential store and scoped resolver.
 *
 * Exposes two surfaces:
 *
 * - **Admin** (`put`, `rotate`, `delete`, `listHandles`, `registerProfile`)
 *   — for operators provisioning credentials.
 * - **Resolver** (`checkAccess`, `_resolveInternal`) — for the injector.
 *   Agents are never expected to call these directly.
 */
export class CredentialVault {
  private readonly records = new Map<string, CredentialRecord>();
  private readonly profiles = new Map<string, CredentialProfile>();
  private readonly _audit: VaultAuditEvent[] = [];
  private readonly persistPath: string | null;
  private readonly key: Uint8Array | null;
  private loaded = false;

  constructor(options: CredentialVaultOptions = {}) {
    this.persistPath = options.persistPath ?? null;
    this.key = options.encryptionKey ?? null;

    if (this.persistPath !== null) {
      if (this.key === null) {
        throw new TypeError('encryptionKey is required when persistPath is set');
      }
      if (this.key.length !== KEY_LENGTH) {
        throw new TypeError(`encryptionKey must be exactly ${KEY_LENGTH} bytes`);
      }
    }
  }

  /** Generate a fresh AES-256-GCM key (32 random bytes). */
  static generateKey(): Uint8Array {
    return randomBytes(KEY_LENGTH);
  }

  /** Load persisted records from disk. Idempotent. */
  async load(): Promise<void> {
    if (this.loaded || this.persistPath === null) {
      this.loaded = true;
      return;
    }
    try {
      const buf = await fs.readFile(this.persistPath);
      if (buf.length === 0) {
        this.loaded = true;
        return;
      }
      const decoded = this.decrypt(new Uint8Array(buf));
      const payload = JSON.parse(new TextDecoder().decode(decoded)) as {
        records?: CredentialRecord[];
      };
      for (const r of payload.records ?? []) {
        this.records.set(r.name, r);
      }
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
        throw err;
      }
    }
    this.loaded = true;
  }

  // -- Admin surface ------------------------------------------------------

  async put(name: string, value: string, credType = 'secret'): Promise<CredentialHandle> {
    if (!NAME_RE.test(name)) {
      throw new TypeError('Credential name must match [A-Za-z0-9_.-]{1,128}');
    }
    await this.load();
    const existing = this.records.get(name);
    const now = Date.now() / 1000;
    const record: CredentialRecord = {
      name,
      value,
      credType,
      version: existing ? existing.version + 1 : 1,
      createdAt: existing ? existing.createdAt : now,
      rotatedAt: existing ? now : null,
    };
    this.records.set(name, record);
    await this.flush();
    return new CredentialHandle(name);
  }

  async rotate(name: string, newValue: string): Promise<CredentialHandle> {
    await this.load();
    const old = this.records.get(name);
    if (!old) {
      throw new CredentialError(`unknown credential: ${name}`);
    }
    const updated: CredentialRecord = {
      ...old,
      value: newValue,
      version: old.version + 1,
      rotatedAt: Date.now() / 1000,
    };
    this.records.set(name, updated);
    await this.flush();
    return new CredentialHandle(name);
  }

  async delete(name: string): Promise<boolean> {
    await this.load();
    const present = this.records.delete(name);
    if (present) {
      await this.flush();
    }
    return present;
  }

  async listHandles(): Promise<string[]> {
    await this.load();
    return [...this.records.keys()].sort();
  }

  async getMetadata(name: string): Promise<Omit<CredentialRecord, 'value'> | null> {
    await this.load();
    const r = this.records.get(name);
    if (!r) return null;
    const { value: _ignored, ...meta } = r;
    return meta;
  }

  registerProfile(profile: CredentialProfile): void {
    this.profiles.set(profile.agentDid, profile);
  }

  revokeProfile(agentDid: string): boolean {
    return this.profiles.delete(agentDid);
  }

  // -- Resolver surface ---------------------------------------------------

  /** True iff `agentDid` may use `handleName` for `actionClass`. */
  checkAccess(agentDid: string, handleName: string, actionClass: string): boolean {
    const profile = this.profiles.get(agentDid);
    if (!profile) return false;
    const bound = profile.capabilityFor(actionClass);
    if (bound === undefined || bound !== handleName) return false;
    return this.records.has(handleName);
  }

  /**
   * Internal: resolve a credential value and emit an audit event.
   * Returns `[value, event]`; on deny `value` is null.
   *
   * Callers must ensure `value` never crosses the agent trust boundary.
   * Use {@link CredentialInjector} rather than calling this directly.
   */
  _resolveInternal(
    agentDid: string,
    handleName: string,
    actionClass: string,
    targetService: string,
    policyVersion: string,
  ): [string | null, VaultAuditEvent] {
    const allowed = this.checkAccess(agentDid, handleName, actionClass);
    if (allowed) {
      const value = this.records.get(handleName)!.value;
      const event: VaultAuditEvent = {
        timestamp: Date.now() / 1000,
        agentDid,
        handleName,
        targetService,
        actionClass,
        decision: 'allow',
        policyVersion,
        reason: '',
      };
      this._audit.push(event);
      return [value, event];
    }
    const event: VaultAuditEvent = {
      timestamp: Date.now() / 1000,
      agentDid,
      handleName,
      targetService,
      actionClass,
      decision: 'deny',
      policyVersion,
      reason: DENY_REASON,
    };
    this._audit.push(event);
    return [null, event];
  }

  /** Immutable snapshot of audit events. */
  auditLog(): readonly VaultAuditEvent[] {
    return [...this._audit];
  }

  clearAudit(): void {
    this._audit.length = 0;
  }

  // Internal helper for the injector to append an audit event when a
  // request is rejected before any vault read happens (out-of-scope
  // placeholder or policy deny).
  _recordReject(event: VaultAuditEvent): void {
    this._audit.push(event);
  }

  // -- Persistence --------------------------------------------------------

  private async flush(): Promise<void> {
    if (this.persistPath === null || this.key === null) return;
    const payload = JSON.stringify({ records: [...this.records.values()] });
    const ciphertext = this.encrypt(utf8ToBytes(payload));
    const tmp = `${this.persistPath}.tmp`;
    await fs.mkdir(path.dirname(this.persistPath) || '.', { recursive: true });
    await fs.writeFile(tmp, ciphertext);
    await fs.rename(tmp, this.persistPath);
  }

  private encrypt(plaintext: Uint8Array): Uint8Array {
    if (this.key === null) throw new CredentialError('no encryption key');
    const nonce = randomBytes(NONCE_LENGTH);
    const ct = gcm(this.key, nonce).encrypt(plaintext);
    const out = new Uint8Array(NONCE_LENGTH + ct.length);
    out.set(nonce, 0);
    out.set(ct, NONCE_LENGTH);
    return out;
  }

  private decrypt(blob: Uint8Array): Uint8Array {
    if (this.key === null) throw new CredentialError('no encryption key');
    if (blob.length < NONCE_LENGTH) {
      throw new CredentialError('persisted vault is corrupt (too short)');
    }
    const nonce = blob.slice(0, NONCE_LENGTH);
    const ct = blob.slice(NONCE_LENGTH);
    return gcm(this.key, nonce).decrypt(ct);
  }
}

// ---------------------------------------------------------------------------
// Injector
// ---------------------------------------------------------------------------

export interface InjectionContext {
  readonly agentDid: string;
  readonly actionClass: string;
  readonly targetService: string;
  readonly requestedHandles: readonly string[];
  readonly policyVersion: string;
}

export interface PolicyOutcome {
  readonly allow: boolean;
  readonly reason?: string;
}

export type PolicyCheck = (ctx: InjectionContext) => PolicyOutcome | Promise<PolicyOutcome>;

export interface InjectionResult<T> {
  readonly allowed: boolean;
  readonly payload: T | DenyReceipt;
  readonly denyReceipt: DenyReceipt | null;
  readonly auditEvents: readonly VaultAuditEvent[];
}

export interface InjectionOptions {
  actionClass: string;
  targetService: string;
  allowedHandles: Iterable<string>;
  policyVersion?: string;
  policyCheck?: PolicyCheck;
}

/**
 * Render `{{cred:NAME}}` placeholders into HTTP, MCP, and env payloads.
 *
 * The injector is the *only* component that ever holds resolved credential
 * values, and only long enough to render an outbound payload.
 *
 * For every injection call:
 *
 * - `allowedHandles` is the workflow-policy allowlist of handle names
 *   eligible for substitution on this call. A placeholder whose name is
 *   not in this set causes the entire call to be denied — this is the
 *   "MCP server metadata is untrusted" boundary.
 * - `policyCheck` is invoked *before* any value is read from the vault.
 * - On any deny, `payload` is a {@link DenyReceipt} (deterministic shape).
 */
export class CredentialInjector {
  constructor(private readonly vault: CredentialVault) {}

  async injectHeaders(
    agentDid: string,
    headers: Record<string, string>,
    opts: InjectionOptions,
  ): Promise<InjectionResult<Record<string, string>>> {
    return this._inject<Record<string, string>>(agentDid, { ...headers }, opts);
  }

  async injectToolArgs<T>(
    agentDid: string,
    args: T,
    opts: InjectionOptions,
  ): Promise<InjectionResult<T>> {
    return this._inject<T>(agentDid, args, opts);
  }

  async injectEnv(
    agentDid: string,
    env: Record<string, string>,
    opts: InjectionOptions,
  ): Promise<InjectionResult<Record<string, string>>> {
    return this._inject<Record<string, string>>(agentDid, { ...env }, opts);
  }

  private async _inject<T>(
    agentDid: string,
    payload: T,
    opts: InjectionOptions,
  ): Promise<InjectionResult<T>> {
    const allowlist = new Set(opts.allowedHandles);
    const requested = collectPlaceholders(payload);
    const policyVersion = opts.policyVersion ?? 'v0';

    // 1. Reject anything outside the workflow-supplied allowlist.
    const outside = [...requested].filter(n => !allowlist.has(n));
    if (outside.length > 0) {
      const event: VaultAuditEvent = {
        timestamp: Date.now() / 1000,
        agentDid,
        handleName: outside[0],
        targetService: opts.targetService,
        actionClass: opts.actionClass,
        decision: 'deny',
        policyVersion,
        reason: DENY_REASON,
      };
      this.vault._recordReject(event);
      const receipt = new DenyReceipt({
        actionClass: opts.actionClass,
        targetService: opts.targetService,
      });
      return { allowed: false, payload: receipt, denyReceipt: receipt, auditEvents: [event] };
    }

    // 2. Run policy *before* any vault read.
    if (opts.policyCheck) {
      const ctx: InjectionContext = {
        agentDid,
        actionClass: opts.actionClass,
        targetService: opts.targetService,
        requestedHandles: [...requested].sort(),
        policyVersion,
      };
      const outcome = await opts.policyCheck(ctx);
      if (!outcome.allow) {
        const event: VaultAuditEvent = {
          timestamp: Date.now() / 1000,
          agentDid,
          handleName: [...requested][0] ?? '',
          targetService: opts.targetService,
          actionClass: opts.actionClass,
          decision: 'deny',
          policyVersion,
          reason: DENY_REASON,
        };
        this.vault._recordReject(event);
        const receipt = new DenyReceipt({
          actionClass: opts.actionClass,
          targetService: opts.targetService,
        });
        return { allowed: false, payload: receipt, denyReceipt: receipt, auditEvents: [event] };
      }
    }

    // 3. Resolve. Any single deny aborts the whole call.
    const resolved = new Map<string, string>();
    const events: VaultAuditEvent[] = [];
    for (const name of requested) {
      const [value, ev] = this.vault._resolveInternal(
        agentDid,
        name,
        opts.actionClass,
        opts.targetService,
        policyVersion,
      );
      events.push(ev);
      if (value === null) {
        const receipt = new DenyReceipt({
          actionClass: opts.actionClass,
          targetService: opts.targetService,
        });
        return { allowed: false, payload: receipt, denyReceipt: receipt, auditEvents: events };
      }
      resolved.set(name, value);
    }

    const rendered = substitute(payload, resolved) as T;
    return { allowed: true, payload: rendered, denyReceipt: null, auditEvents: events };
  }
}

// ---------------------------------------------------------------------------
// Placeholder helpers
// ---------------------------------------------------------------------------

function collectPlaceholders(payload: unknown): Set<string> {
  const out = new Set<string>();
  walk(payload, s => {
    PLACEHOLDER_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = PLACEHOLDER_RE.exec(s)) !== null) {
      out.add(m[1]);
    }
  });
  return out;
}

function substitute(payload: unknown, resolved: ReadonlyMap<string, string>): unknown {
  return mapStrings(payload, s =>
    s.replace(PLACEHOLDER_RE, (match, name) => resolved.get(name) ?? match),
  );
}

function walk(payload: unknown, visit: (s: string) => void): void {
  if (typeof payload === 'string') {
    visit(payload);
  } else if (Array.isArray(payload)) {
    for (const item of payload) walk(item, visit);
  } else if (payload && typeof payload === 'object') {
    for (const [k, v] of Object.entries(payload)) {
      visit(k);
      walk(v, visit);
    }
  }
}

function mapStrings(payload: unknown, fn: (s: string) => string): unknown {
  if (typeof payload === 'string') return fn(payload);
  if (Array.isArray(payload)) return payload.map(v => mapStrings(v, fn));
  if (payload && typeof payload === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(payload)) {
      out[fn(k)] = mapStrings(v, fn);
    }
    return out;
  }
  return payload;
}

// ---------------------------------------------------------------------------
// Audit-log integrity helper
// ---------------------------------------------------------------------------

/**
 * Stable HMAC-SHA256 digest of an audit-event sequence.
 *
 * The digest covers handle names and decisions but never resolved
 * credential values (the vault never stores them in events).
 */
export function auditDigest(events: readonly VaultAuditEvent[], key: Uint8Array): string {
  const h = hmac.create(sha256, key);
  for (const ev of events) {
    const json = JSON.stringify({
      timestamp: ev.timestamp,
      agentDid: ev.agentDid,
      handleName: ev.handleName,
      targetService: ev.targetService,
      actionClass: ev.actionClass,
      decision: ev.decision,
      policyVersion: ev.policyVersion,
      reason: ev.reason,
    });
    h.update(utf8ToBytes(json));
    h.update(new Uint8Array([0x1f]));
  }
  return bytesToHex(h.digest());
}
