// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { createHash, timingSafeEqual } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

const GENESIS_HASH = "0".repeat(64);
const MAX_ENTRIES = 10000;

export async function appendAuditEntry(auditPath, entry) {
  const { seamHash, entries } = await loadAuditFile(auditPath);
  if (!verifyAuditEntries(entries, seamHash)) {
    throw new Error(`Audit log at ${auditPath} failed hash-chain verification.`);
  }
  const previousHash =
    entries.length > 0 ? entries[entries.length - 1].hash : seamHash ?? GENESIS_HASH;
  const timestamp = new Date().toISOString();
  const hash = computeHash({
    timestamp,
    agentId: entry.agentId,
    action: entry.action,
    decision: entry.decision,
    previousHash,
  });

  const nextEntry = {
    timestamp,
    agentId: entry.agentId,
    action: entry.action,
    decision: entry.decision,
    previousHash,
    hash,
  };

  const combined = [...entries, nextEntry];
  let nextSeam = seamHash;
  let nextEntries = combined;
  if (combined.length > MAX_ENTRIES) {
    // Evict the oldest entries, retaining the last evicted entry's hash as
    // the seam so verifyAuditEntries can re-anchor the surviving chain
    // instead of expecting GENESIS at its head. Without this, the previous
    // implementation truncated to a non-GENESIS-anchored head, which made
    // verification fail permanently and — because appends fail closed —
    // caused every subsequent governance decision to be denied.
    const overflow = combined.length - MAX_ENTRIES;
    nextSeam = combined[overflow - 1].hash;
    nextEntries = combined.slice(overflow);
  }

  await writeAuditFile(auditPath, nextSeam, nextEntries);
  return nextEntry;
}

export async function getAuditStatus(auditPath) {
  try {
    const { seamHash, entries } = await loadAuditFile(auditPath);
    const valid = verifyAuditEntries(entries, seamHash);
    return {
      count: entries.length,
      error: valid ? undefined : `Audit log at ${auditPath} failed hash-chain verification.`,
      valid,
    };
  } catch (error) {
    return {
      count: 0,
      error: error instanceof Error ? error.message : String(error),
      valid: false,
    };
  }
}

// Read the audit file, returning the surviving entries and the seam hash the
// chain is anchored to. Supports the legacy bare-array format and the
// { seamHash, entries } format written once the log has rolled over. A legacy
// array whose head is not GENESIS-anchored (i.e. it was already truncated by a
// prior version) adopts its head's previousHash as the seam so the surviving
// chain still verifies rather than remaining permanently broken.
export async function loadAuditFile(auditPath) {
  if (!auditPath || !existsSync(auditPath)) {
    return { seamHash: null, entries: [] };
  }

  try {
    const text = await readFile(auditPath, "utf8");
    const value = JSON.parse(text);
    if (Array.isArray(value)) {
      const head = value[0];
      const seamHash =
        head && typeof head.previousHash === "string" && head.previousHash !== GENESIS_HASH
          ? head.previousHash
          : null;
      return { seamHash, entries: value };
    }
    if (value && typeof value === "object" && Array.isArray(value.entries)) {
      return {
        seamHash: typeof value.seamHash === "string" ? value.seamHash : null,
        entries: value.entries,
      };
    }
    throw new Error(`Audit log at ${auditPath} is not a recognised audit format.`);
  } catch (error) {
    throw new Error(
      `Audit log at ${auditPath} is unreadable or corrupt: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

export async function loadAuditEntries(auditPath) {
  return (await loadAuditFile(auditPath)).entries;
}

export function verifyAuditEntries(entries, seamHash = null) {
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    const expectedPrev = index === 0 ? seamHash ?? GENESIS_HASH : entries[index - 1].hash;
    if (entry.previousHash !== expectedPrev) {
      return false;
    }

    const expectedHash = computeHash({
      timestamp: entry.timestamp,
      agentId: entry.agentId,
      action: entry.action,
      decision: entry.decision,
      previousHash: entry.previousHash,
    });

    const actualHash = String(entry.hash ?? "");
    if (Buffer.byteLength(actualHash, "utf8") !== Buffer.byteLength(expectedHash, "utf8")) {
      return false;
    }
    if (!timingSafeEqual(Buffer.from(actualHash, "utf8"), Buffer.from(expectedHash, "utf8"))) {
      return false;
    }
  }

  return true;
}

async function writeAuditFile(auditPath, seamHash, entries) {
  await mkdir(dirname(auditPath), { recursive: true });
  // Keep the legacy bare-array format until the log first rolls over, so logs
  // that never exceed MAX_ENTRIES stay byte-compatible with prior versions.
  // Once a seam exists it must be persisted alongside the entries.
  const payload = seamHash === null ? entries : { seamHash, entries };
  const tempPath = `${auditPath}.tmp-${process.pid}`;
  await writeFile(tempPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
  await rename(tempPath, auditPath);
}

function computeHash(payload) {
  return createHash("sha256").update(JSON.stringify(payload)).digest("hex");
}
