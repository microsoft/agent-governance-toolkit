// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import * as crypto from "crypto";
import { AuditEntry } from "../types";

const auditLog: AuditEntry[] = [];

function computeChainHash(entry: Omit<AuditEntry, "hash">): string {
  // SHA-256 is used here as a content-addressed *integrity* hash over a
  // hash-chained audit-log entry (Merkle-style tamper-evidence), NOT for
  // password storage or any authentication secret. The threat model is
  // "detect after-the-fact mutation of historical audit entries", for which
  // a fast cryptographic hash is the correct primitive. Do not replace with
  // bcrypt/scrypt/argon2 — those are password-KDFs with different goals
  // (slowdown vs. brute force) and would make every audit append O(100ms).
  // codeql[js/insufficient-password-hash] Not a password hash: SHA-256 here is a content-addressed Merkle-chain integrity hash for tamper-evident audit-log entries. Password-KDFs (bcrypt/argon2/scrypt) are wrong here — see comment above.
  const data = JSON.stringify({
    id: entry.id,
    timestamp: entry.timestamp,
    action: entry.action,
    agent_did: entry.agent_did,
    details: entry.details,
    previous_hash: entry.previous_hash,
  });
  return crypto.createHash("sha256").update(data).digest("hex");
}

/** Append an entry to the hash-chained audit log. */
export function appendAuditEntry(
  action: string,
  agentDid: string,
  details: Record<string, unknown> = {},
): AuditEntry {
  const previousHash =
    auditLog.length > 0 ? auditLog[auditLog.length - 1].hash : "genesis";

  const partial: Omit<AuditEntry, "hash"> = {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    action,
    agent_did: agentDid,
    details,
    previous_hash: previousHash,
  };

  const entry: AuditEntry = { ...partial, hash: computeChainHash(partial) };
  auditLog.push(entry);
  return entry;
}

/** Return the full audit log. */
export function getAuditLog(): ReadonlyArray<AuditEntry> {
  return auditLog;
}

/** Verify the integrity of the hash chain. */
export function verifyChain(): boolean {
  for (let i = 0; i < auditLog.length; i++) {
    const entry = auditLog[i];
    const expectedPrev = i > 0 ? auditLog[i - 1].hash : "genesis";
    if (entry.previous_hash !== expectedPrev) return false;

    const { hash, ...partial } = entry;
    if (hash !== computeChainHash(partial)) return false;
  }
  return true;
}

/** Reset audit log (for testing). */
export function resetAuditLog(): void {
  auditLog.length = 0;
}
