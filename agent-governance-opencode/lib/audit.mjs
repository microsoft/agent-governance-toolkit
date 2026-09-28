// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

const GENESIS_HASH = "0".repeat(64);
const MAX_ENTRIES = 10000;

/**
 * Schema version stamped on every entry this module writes.
 *
 * Entries without a `v` key are version 1: the original five-field payload
 * hashed through `JSON.stringify`. They are still verified exactly as they were
 * written, byte for byte, so a log produced by an earlier release keeps
 * verifying after an upgrade. A naive widening of the hashed payload would
 * invalidate every historical entry, and because `appendAuditEntry` throws on a
 * failed chain and the plugin fails closed on audit errors, that would turn the
 * first write after an upgrade into a deny-everything outage.
 */
const AUDIT_ENTRY_VERSION = 2;

/** Largest argument payload digested before truncation kicks in. */
export const AUDIT_ARGS_DIGEST_MAX_BYTES = 1024 * 1024;

/** Recorded in place of a digest when arguments cannot be serialized at all. */
const UNSERIALIZABLE_SENTINEL = "[unserializable]";

/** Exactly the keys a version 1 entry may carry, sorted. */
const V1_KEYS = ["action", "agentId", "decision", "hash", "previousHash", "timestamp"];

/** Every key a version 2 entry may carry. */
const V2_ALLOWED_KEYS = new Set([
  "v",
  "timestamp",
  "agentId",
  "action",
  "decision",
  "previousHash",
  "hash",
  "policyVersion",
  "reason",
  "argsDigest",
  "argsDigestAlg",
  "argsTruncated",
  "argsUnserializable",
  "principal",
]);

/** Keys that must be present, and must be strings, on a version 2 entry. */
const V2_REQUIRED_STRINGS = ["timestamp", "agentId", "action", "decision", "previousHash", "hash"];

const V2_DIGEST_ALGORITHMS = new Set(["sha256", "hmac-sha256"]);
const PRINCIPAL_ALLOWED_KEYS = new Set(["sub", "iss"]);

export async function appendAuditEntry(auditPath, entry) {
  const entries = await loadAuditEntries(auditPath);
  if (!verifyAuditEntries(entries)) {
    throw new Error(`Audit log at ${auditPath} failed hash-chain verification.`);
  }
  const previousHash = entries.length > 0 ? entries[entries.length - 1].hash : GENESIS_HASH;
  const timestamp = new Date().toISOString();

  // Only known fields are copied across; spreading the caller's object would
  // let an unrecognized key into the hashed record and fail verification on the
  // next read.
  const record = stripUndefined({
    v: AUDIT_ENTRY_VERSION,
    timestamp,
    agentId: entry.agentId,
    action: entry.action,
    decision: entry.decision,
    previousHash,
    policyVersion: entry.policyVersion,
    reason: entry.reason,
    argsDigest: entry.argsDigest,
    argsDigestAlg: entry.argsDigestAlg,
    argsTruncated: entry.argsTruncated === true ? true : undefined,
    argsUnserializable: entry.argsUnserializable === true ? true : undefined,
    principal: entry.principal,
  });

  if (!isValidV2Shape({ ...record, hash: GENESIS_HASH })) {
    throw new TypeError("Refusing to write a malformed audit entry.");
  }

  const nextEntry = { ...record, hash: hashCanonicalRecord(record) };
  const nextEntries = [...entries, nextEntry].slice(-MAX_ENTRIES);
  await writeAuditEntries(auditPath, nextEntries);
  return nextEntry;
}

/**
 * Digest tool arguments so an entry can be joined against a target system's
 * record of the same call without storing the arguments themselves.
 *
 * A plain SHA-256 makes the entry joinable, not secret: tool arguments are
 * often low entropy (a path, a URL, a branch name) and a short one can be
 * recovered by guessing. Configure an HMAC key when that matters.
 *
 * Never throws. A digest failure must not be able to deny a request.
 *
 * @param {unknown} args
 * @param {{ hmacKey?: import("node:crypto").KeyObject | null }} [options]
 * @returns {{ argsDigest: string, argsDigestAlg: string, argsTruncated?: boolean, argsUnserializable?: boolean }}
 */
export function computeArgsDigest(args, { hmacKey = null } = {}) {
  const algorithm = hmacKey ? "hmac-sha256" : "sha256";
  let truncated = false;
  let unserializable = false;
  let payload;

  try {
    const serialized = canonicalJson(args, { lenient: true });
    let buffer = Buffer.from(serialized ?? "null", "utf8");
    if (buffer.byteLength > AUDIT_ARGS_DIGEST_MAX_BYTES) {
      buffer = buffer.subarray(0, AUDIT_ARGS_DIGEST_MAX_BYTES);
      truncated = true;
    }
    payload = buffer;
  } catch {
    // Every unserializable value digests to the same constant, so the entry
    // says so rather than implying the digest identifies these arguments.
    payload = Buffer.from(UNSERIALIZABLE_SENTINEL, "utf8");
    unserializable = true;
  }

  let argsDigest;
  try {
    argsDigest = hmacKey
      ? createHmac("sha256", hmacKey).update(payload).digest("hex")
      : createHash("sha256").update(payload).digest("hex");
  } catch {
    argsDigest = createHash("sha256").update(UNSERIALIZABLE_SENTINEL, "utf8").digest("hex");
    return { argsDigest, argsDigestAlg: "sha256", argsUnserializable: true };
  }

  return {
    argsDigest,
    argsDigestAlg: algorithm,
    ...(truncated ? { argsTruncated: true } : {}),
    ...(unserializable ? { argsUnserializable: true } : {}),
  };
}

/**
 * Serialize a value so that equal data always produces equal bytes.
 *
 * `JSON.stringify` depends on property insertion order, which makes a digest
 * irreproducible for anyone verifying a log from outside this package. Keys are
 * sorted by UTF-16 code unit, which is the ordering RFC 8785 (JCS) specifies.
 *
 * The output string is assembled directly rather than by rebuilding an object,
 * because JavaScript reorders integer-like keys: `{"10":1,"2":1}` would
 * re-serialize as `2` before `10`.
 *
 * Strict mode (used for audit records) refuses anything JSON cannot represent,
 * so a writer bug surfaces as a thrown error rather than a silently dropped
 * field. Lenient mode (used for tool arguments) follows `JSON.stringify`
 * semantics instead, since arguments are arbitrary caller data.
 *
 * @param {unknown} value
 * @param {{ lenient?: boolean, maxDepth?: number }} [options]
 * @returns {string|undefined} undefined only in lenient mode, for a value JSON drops
 */
export function canonicalJson(value, { lenient = false, maxDepth = 64 } = {}) {
  return serializeCanonical(value, lenient, maxDepth, 0, new Set());
}

function serializeCanonical(value, lenient, maxDepth, depth, ancestors) {
  if (depth > maxDepth) {
    throw new TypeError("canonicalJson: maximum depth exceeded");
  }

  if (value === null) {
    return "null";
  }

  const type = typeof value;

  if (type === "boolean") {
    return value ? "true" : "false";
  }

  if (type === "number") {
    if (!Number.isFinite(value)) {
      if (lenient) {
        return "null";
      }
      throw new TypeError("canonicalJson: non-finite number is not serializable");
    }
    // JSON.stringify uses the spec's shortest round-trip form and maps -0 to 0.
    return JSON.stringify(value);
  }

  if (type === "string") {
    return JSON.stringify(value);
  }

  if (type === "bigint") {
    throw new TypeError("canonicalJson: bigint is not serializable");
  }

  if (type === "undefined" || type === "function" || type === "symbol") {
    if (lenient) {
      return undefined;
    }
    throw new TypeError(`canonicalJson: ${type} is not serializable`);
  }

  if (typeof value.toJSON === "function") {
    return serializeCanonical(value.toJSON(), lenient, maxDepth, depth, ancestors);
  }

  if (ancestors.has(value)) {
    throw new TypeError("canonicalJson: circular reference");
  }
  ancestors.add(value);

  try {
    if (Array.isArray(value)) {
      const items = value.map((item) => {
        const serialized = serializeCanonical(item, lenient, maxDepth, depth + 1, ancestors);
        // JSON renders an unserializable array slot as null rather than dropping it.
        return serialized === undefined ? "null" : serialized;
      });
      return `[${items.join(",")}]`;
    }

    if (!lenient && !isPlainObject(value)) {
      throw new TypeError("canonicalJson: only plain objects are serializable");
    }

    const parts = [];
    for (const key of Object.keys(value).sort()) {
      const serialized = serializeCanonical(value[key], lenient, maxDepth, depth + 1, ancestors);
      if (serialized !== undefined) {
        parts.push(`${JSON.stringify(key)}:${serialized}`);
      }
    }
    return `{${parts.join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
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
  if (!Array.isArray(entries)) {
    return false;
  }

  let sawVersionedEntry = false;

  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    const expectedPrev = index === 0 ? GENESIS_HASH : entries[index - 1].hash;
    if (!isObject(entry) || entry.previousHash !== expectedPrev) {
      return false;
    }

    const versioned = Object.hasOwn(entry, "v");
    // Versions only ever go up. Without this an attacker could strip `v` from
    // the final entry and re-hash it under the v1 rules, since no later entry
    // exists to contradict it.
    if (sawVersionedEntry && !versioned) {
      return false;
    }
    sawVersionedEntry = sawVersionedEntry || versioned;

    const expectedHash = computeEntryHash(entry);
    if (expectedHash === null) {
      return false;
    }

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

/**
 * Expected hash for an entry, or null when the entry is not a shape this
 * module would ever have written. Returning null rather than throwing keeps
 * verification total: a malformed entry fails the chain instead of crashing a
 * caller that is already failing closed.
 */
function computeEntryHash(entry) {
  if (!isObject(entry)) {
    return null;
  }

  if (!Object.hasOwn(entry, "v")) {
    // A v1 entry carries exactly six keys. Anything extra is an enrichment
    // field forged onto an entry whose hash never covered it.
    const keys = Object.keys(entry).sort();
    if (keys.length !== V1_KEYS.length || keys.some((key, i) => key !== V1_KEYS[i])) {
      return null;
    }
    return computeV1Hash(entry);
  }

  if (entry.v !== AUDIT_ENTRY_VERSION || !isValidV2Shape(entry)) {
    return null;
  }

  const { hash: _ignored, ...record } = entry;
  try {
    return hashCanonicalRecord(record);
  } catch {
    return null;
  }
}

/**
 * The original hashed payload, preserved exactly. Field order matters because
 * v1 hashes were taken over `JSON.stringify` output.
 */
function computeV1Hash(entry) {
  return createHash("sha256")
    .update(
      JSON.stringify({
        timestamp: entry.timestamp,
        agentId: entry.agentId,
        action: entry.action,
        decision: entry.decision,
        previousHash: entry.previousHash,
      }),
    )
    .digest("hex");
}

function hashCanonicalRecord(record) {
  return createHash("sha256").update(canonicalJson(record), "utf8").digest("hex");
}

/**
 * Structural check applied before canonicalizing, so a hostile file cannot
 * reach the serializer with deeply nested or exotic values.
 */
function isValidV2Shape(entry) {
  for (const key of Object.keys(entry)) {
    if (!V2_ALLOWED_KEYS.has(key)) {
      return false;
    }
  }

  for (const key of V2_REQUIRED_STRINGS) {
    if (typeof entry[key] !== "string" || entry[key].length === 0) {
      return false;
    }
  }

  if (entry.v !== AUDIT_ENTRY_VERSION) {
    return false;
  }

  for (const key of ["policyVersion", "reason", "argsDigest", "argsDigestAlg"]) {
    if (Object.hasOwn(entry, key) && typeof entry[key] !== "string") {
      return false;
    }
  }

  // A digest and the algorithm that produced it are meaningless apart.
  const hasDigest = Object.hasOwn(entry, "argsDigest");
  const hasAlgorithm = Object.hasOwn(entry, "argsDigestAlg");
  if (hasDigest !== hasAlgorithm) {
    return false;
  }
  if (hasAlgorithm && !V2_DIGEST_ALGORITHMS.has(entry.argsDigestAlg)) {
    return false;
  }

  for (const key of ["argsTruncated", "argsUnserializable"]) {
    // Present only to mean true, so absence and false cannot both appear.
    if (Object.hasOwn(entry, key) && entry[key] !== true) {
      return false;
    }
  }

  if (Object.hasOwn(entry, "principal") && !isValidPrincipal(entry.principal)) {
    return false;
  }

  return true;
}

function isValidPrincipal(principal) {
  if (!isPlainObject(principal)) {
    return false;
  }
  for (const key of Object.keys(principal)) {
    if (!PRINCIPAL_ALLOWED_KEYS.has(key)) {
      return false;
    }
  }
  if (typeof principal.sub !== "string" || principal.sub.length === 0) {
    return false;
  }
  if (Object.hasOwn(principal, "iss") && typeof principal.iss !== "string") {
    return false;
  }
  return true;
}

function stripUndefined(record) {
  const result = {};
  for (const [key, value] of Object.entries(record)) {
    if (value !== undefined) {
      result[key] = value;
    }
  }
  return result;
}

function isObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isPlainObject(value) {
  if (!isObject(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

async function writeAuditEntries(auditPath, entries) {
  await mkdir(dirname(auditPath), { recursive: true });
  const tempPath = `${auditPath}.tmp-${process.pid}`;
  await writeFile(tempPath, `${JSON.stringify(entries, null, 2)}\n`, "utf8");
  await rename(tempPath, auditPath);
}
