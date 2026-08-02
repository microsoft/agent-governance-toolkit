// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { createHash, timingSafeEqual } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

const GENESIS_HASH = "0".repeat(64);
export const MAX_ENTRIES = 10000;

export async function appendAuditEntry(auditPath, entry, options = {}) {
  const { limit = MAX_ENTRIES } = options ?? {};
  if (!Number.isInteger(limit) || limit < 1) {
    throw new TypeError(
      `Audit entry limit must be a positive integer, received ${String(limit)}.`,
    );
  }

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
  if (combined.length > limit) {
    // Retain the last evicted hash as a seam so the surviving head remains
    // verifiable instead of being incorrectly re-anchored to GENESIS.
    const overflow = combined.length - limit;
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

export async function loadAuditFile(auditPath) {
  if (!auditPath || !existsSync(auditPath)) {
    return { seamHash: null, entries: [] };
  }

  try {
    const text = await readFile(auditPath, "utf8");
    const value = JSON.parse(text);
    if (Array.isArray(value)) {
      // A legacy log may already have been front-truncated by the old
      // implementation. Recover its surviving chain while documenting that
      // the derived seam cannot authenticate the deleted prefix.
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
  // Preserve the legacy array format until the first rollover. Once a seam
  // exists, persist it with the surviving entries for future verification.
  const payload = seamHash === null ? entries : { seamHash, entries };
  const tempPath = `${auditPath}.tmp-${process.pid}`;
  await writeFile(tempPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
  await rename(tempPath, auditPath);
}

function computeHash(payload) {
  return createHash("sha256").update(JSON.stringify(payload)).digest("hex");
}
