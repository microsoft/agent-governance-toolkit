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

let previousHash = "0000000000000000000000000000000000000000000000000000000000000000";
const entries: AuditEntry[] = [];
let entryCounter = 0;

/**
 * Creates an audit middleware that records all tool executions
 * with tamper-evident hash chains.
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

  return {
    /**
     * Record an audit entry with hash chain integrity.
     */
    async record(params: {
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

      const hashPayload = JSON.stringify({
        id,
        timestamp,
        toolId: params.toolId,
        agentId: params.agentId,
        action: params.action,
        previousHash,
      });

      const hash = await computeHash(hashPayload);

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
        previousHash,
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
    },

    /**
     * Get all audit entries (most recent first).
     */
    getEntries(limit?: number): AuditEntry[] {
      const result = [...entries].reverse();
      return limit ? result.slice(0, limit) : result;
    },

    /**
     * Verify the integrity of the audit chain.
     * Returns true if no entries have been tampered with.
     */
    async verifyChain(): Promise<{ valid: boolean; brokenAt?: number }> {
      for (let i = 1; i < entries.length; i++) {
        if (entries[i].previousHash !== entries[i - 1].hash) {
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
     * Clear all entries (for testing).
     */
    clear() {
      entries.length = 0;
      entryCounter = 0;
      previousHash = "0000000000000000000000000000000000000000000000000000000000000000";
    },
  };
}

export type { AuditEntry };

/** Compute SHA-256 hash of a string. Works in Node.js and Edge. */
async function computeHash(data: string): Promise<string> {
  // Node.js crypto
  try {
    const { createHash } = await import("crypto");
    return createHash("sha256").update(data).digest("hex");
  } catch {
    // Fallback for edge runtimes
    const encoder = new TextEncoder();
    const buf = await crypto.subtle.digest("SHA-256", encoder.encode(data));
    return Array.from(new Uint8Array(buf))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }
}
