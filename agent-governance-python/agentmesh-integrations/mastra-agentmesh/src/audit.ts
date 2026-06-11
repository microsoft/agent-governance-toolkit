// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Audit middleware for Mastra tool execution.
 *
 * Provides tamper-evident audit logging with SHA-256 hash chains.
 * Every tool invocation, completion, denial, and error is recorded
 * with a cryptographic link to the previous entry.
 */

import type { AuditConfig, AuditEntry, GovernanceResult, TrustVerification } from "./types";

const GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

/**
 * Creates an audit middleware that records all tool executions
 * with tamper-evident hash chains.
 *
 * Each call to auditMiddleware() owns an independent chain: its entries,
 * previousHash, and counter are private to the returned instance, so
 * clear() and maxEntries on one instance never affect another.
 *
 * @example
 * ```ts
 * const audit = auditMiddleware({
 *   captureData: true,
 *   maxEntries: 1000,
 *   sink: async (entry) => {
 *     await db.insert("audit_log", entry);
 *   },
 * });
 *
 * const entry = await audit.record({
 *   toolId: "search",
 *   agentId: "agent-1",
 *   action: "invoke",
 *   input: { query: "test" },
 * });
 * ```
 */
export function auditMiddleware(config: AuditConfig = {}) {
  const maxEntries = config.maxEntries ?? 10_000;

  // Per-instance state. Living in this closure means every auditMiddleware()
  // call gets its own isolated chain.
  let previousHash = GENESIS_HASH;
  const entries: AuditEntry[] = [];
  let entryCounter = 0;

  // Serializes record() so the read-compute-write of previousHash is atomic.
  // Each append chains off the prior one, so two concurrent record() calls can
  // never both read the same previousHash.
  let tail: Promise<unknown> = Promise.resolve();

  /** Build the canonical payload that an entry's hash covers. */
  function hashPayload(entry: Pick<AuditEntry, "id" | "timestamp" | "toolId" | "agentId" | "action" | "previousHash">): string {
    return JSON.stringify({
      id: entry.id,
      timestamp: entry.timestamp,
      toolId: entry.toolId,
      agentId: entry.agentId,
      action: entry.action,
      previousHash: entry.previousHash,
    });
  }

  async function append(params: {
    toolId: string;
    agentId: string;
    action: "invoke" | "complete" | "deny" | "error";
    input?: unknown;
    output?: unknown;
    duration_ms?: number;
    governance?: GovernanceResult;
    trust?: TrustVerification;
  }): Promise<AuditEntry> {
    const id = `audit-${++entryCounter}-${Date.now()}`;
    const timestamp = Date.now();
    const prev = previousHash;

    const hash = await computeHash(
      hashPayload({ id, timestamp, toolId: params.toolId, agentId: params.agentId, action: params.action, previousHash: prev }),
    );

    const entry: AuditEntry = {
      id,
      timestamp,
      toolId: params.toolId,
      agentId: params.agentId,
      action: params.action,
      input: config.captureData ? params.input : undefined,
      output: config.captureData ? params.output : undefined,
      duration_ms: params.duration_ms,
      governance: params.governance,
      trust: params.trust,
      hash,
      previousHash: prev,
    };

    previousHash = hash;
    entries.push(entry);

    // Trim old entries
    while (entries.length > maxEntries) {
      entries.shift();
    }

    // Send to custom sink
    if (config.sink) {
      await config.sink(entry);
    }

    return entry;
  }

  return {
    /**
     * Record an audit entry with hash chain integrity.
     *
     * Appends are serialized: the read-compute-write of previousHash is atomic
     * across concurrent calls, so the chain stays consistent under concurrency.
     */
    record(params: {
      toolId: string;
      agentId: string;
      action: "invoke" | "complete" | "deny" | "error";
      input?: unknown;
      output?: unknown;
      duration_ms?: number;
      governance?: GovernanceResult;
      trust?: TrustVerification;
    }): Promise<AuditEntry> {
      // Chain this append onto the previous one. We swallow prior rejections
      // for sequencing purposes only; the caller still sees its own result.
      const result = tail.then(
        () => append(params),
        () => append(params),
      );
      tail = result;
      return result;
    },

    /**
     * Get all audit entries (most recent first).
     */
    getEntries(limit?: number): AuditEntry[] {
      const result = [...entries].reverse().map((e) => ({ ...e }));
      return limit ? result.slice(0, limit) : result;
    },

    /**
     * Verify the integrity of the audit chain.
     *
     * Checks both the previousHash linkage between adjacent entries and that
     * each entry's stored hash still matches a hash recomputed from its fields,
     * so tampering with any covered field is detected.
     *
     * Returns true if no entries have been tampered with.
     */
    async verifyChain(): Promise<{ valid: boolean; brokenAt?: number }> {
      for (let i = 0; i < entries.length; i++) {
        const entry = entries[i];

        // Linkage check. We anchor on each entry's own recorded previousHash
        // for i === 0 because maxEntries trimming may have removed the
        // genesis-anchored head, so the surviving head can legitimately carry
        // an earlier entry's hash.
        if (i > 0 && entry.previousHash !== entries[i - 1].hash) {
          return { valid: false, brokenAt: i };
        }

        // Recompute the hash from the entry's fields so any tampering with a
        // covered field (toolId, agentId, action, id, timestamp, previousHash)
        // is detected even when the linkage still appears intact.
        const expectedHash = await computeHash(hashPayload(entry));
        if (entry.hash !== expectedHash) {
          return { valid: false, brokenAt: i };
        }
      }
      return { valid: true };
    },

    /**
     * Get entry count.
     */
    get length(): number {
      return entries.length;
    },

    /**
     * Clear all entries (for testing). Only affects this instance.
     */
    clear() {
      entries.length = 0;
      entryCounter = 0;
      previousHash = GENESIS_HASH;
      tail = Promise.resolve();
    },
  };
}

export type { AuditEntry };

/** Compute SHA-256 hash of a string. Uses the Web Crypto API (available in Node.js 18+ and all edge runtimes). */
async function computeHash(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const buf = await crypto.subtle.digest("SHA-256", encoder.encode(data));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
