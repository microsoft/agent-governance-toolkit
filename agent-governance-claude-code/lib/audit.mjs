// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { createHash, timingSafeEqual } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

const GENESIS_HASH = "0".repeat(64);
const MAX_ENTRIES = 10000;

export async function appendAuditEntry(auditPath, entry) {
  const entries = await loadAuditEntries(auditPath);
  if (!verifyAuditEntries(entries)) {
    throw new Error(`Audit log at ${auditPath} failed hash-chain verification.`);
  }
  const previousHash = entries.length > 0 ? entries[entries.length - 1].hash : GENESIS_HASH;
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

  const nextEntries = [...entries, nextEntry].slice(-MAX_ENTRIES);
  await writeAuditEntries(auditPath, nextEntries);
  return nextEntry;
}

export async function getAuditStatus(auditPath) {
  try {
    const entries = await loadAuditEntries(auditPath);
    const valid = verifyAuditEntries(entries);
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

export async function loadAuditEntries(auditPath) {
  if (!auditPath || !existsSync(auditPath)) {
    return [];
  }

  try {
    const text = await readFile(auditPath, "utf8");
    const value = JSON.parse(text);
    if (!Array.isArray(value)) {
      throw new Error(`Audit log at ${auditPath} is not a JSON array.`);
    }
    return value;
  } catch (error) {
    throw new Error(
      `Audit log at ${auditPath} is unreadable or corrupt: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

export function verifyAuditEntries(entries) {
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    const expectedPrev = index === 0 ? GENESIS_HASH : entries[index - 1].hash;
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

async function writeAuditEntries(auditPath, entries) {
  await mkdir(dirname(auditPath), { recursive: true });
  const tempPath = `${auditPath}.tmp-${process.pid}`;
  await writeFile(tempPath, `${JSON.stringify(entries, null, 2)}\n`, "utf8");
  await rename(tempPath, auditPath);
}

function computeHash(payload) {
  return createHash("sha256").update(JSON.stringify(payload)).digest("hex");
}
