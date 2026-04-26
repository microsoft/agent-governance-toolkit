// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * createGovernedTool — wraps a Mastra tool with governance, trust, and audit.
 *
 * Combines all three middleware layers into a single wrapper that
 * intercepts tool execution with policy checks, trust verification,
 * and tamper-evident audit logging.
 *
 * @example
 * ```ts
 * import { createTool } from "@mastra/core";
 * import { createGovernedTool } from "@agentmesh/mastra";
 * import { z } from "zod";
 *
 * const searchTool = createTool({
 *   id: "web-search",
 *   description: "Search the web",
 *   inputSchema: z.object({ query: z.string() }),
 *   outputSchema: z.object({ results: z.array(z.string()) }),
 *   execute: async ({ query }) => ({ results: ["result1"] }),
 * });
 *
 * const governedSearch = createGovernedTool(searchTool, {
 *   governance: {
 *     rateLimitPerMinute: 30,
 *     blockedPatterns: ["(?i)ignore previous instructions"],
 *   },
 *   trust: {
 *     minTrustScore: 500,
 *     getTrustScore: async (agentId) => 750,
 *   },
 *   audit: { captureData: true },
 * });
 * ```
 */

import { governanceMiddleware } from "./governance";
import { trustGate } from "./trust";
import { auditMiddleware } from "./audit";
import type { GovernancePolicy, TrustConfig, AuditConfig } from "./types";

export interface GovernedToolOptions {
  governance?: GovernancePolicy;
  trust?: TrustConfig;
  audit?: AuditConfig;
  /** Agent ID for trust and audit (default: "default-agent"). */
  agentId?: string;
}

/**
 * Wraps a Mastra-compatible tool object with governance, trust, and audit.
 *
 * Returns a new object with the same shape but an instrumented `execute` function.
 * The original tool is not modified.
 */
export function createGovernedTool<T extends { id: string; execute: (...args: any[]) => any }>(
  tool: T,
  options: GovernedToolOptions
): T {
  const gov = options.governance
    ? governanceMiddleware(options.governance)
    : null;
  const trust = options.trust ? trustGate(options.trust) : null;
  const audit = options.audit ? auditMiddleware(options.audit) : null;
  const agentId = options.agentId ?? "default-agent";

  const originalExecute = tool.execute;

  const governedExecute = async function (this: unknown, ...args: unknown[]) {
    const input = args[0];
    const startTime = Date.now();

    // 1. Trust verification
    if (trust) {
      const verification = await trust.verify(agentId);
      if (!verification.verified) {
        if (audit) {
          await audit.record({
            toolId: tool.id,
            agentId,
            action: "deny",
            input,
            trust: verification,
          });
        }
        throw new Error(
          `Trust verification failed for agent '${agentId}': ` +
            `score ${verification.trustScore} < threshold ${verification.threshold}`
        );
      }
    }

    // 2. Governance policy check
    if (gov) {
      const result = await gov.check(input, tool.id, agentId);
      if (!result.allowed) {
        if (audit) {
          await audit.record({
            toolId: tool.id,
            agentId,
            action: "deny",
            input,
            governance: result,
          });
        }
        throw new Error(
          `Governance policy violation: ${result.violations.join("; ")}`
        );
      }
      // Use redacted input if PII was stripped
      if (result.redactedInput !== undefined) {
        args[0] = result.redactedInput;
      }
    }

    // 3. Record invocation
    if (audit) {
      await audit.record({
        toolId: tool.id,
        agentId,
        action: "invoke",
        input,
      });
    }

    // 4. Execute the original tool
    try {
      const output = await originalExecute.apply(this, args);
      const duration_ms = Date.now() - startTime;

      // 5. Record completion
      if (audit) {
        await audit.record({
          toolId: tool.id,
          agentId,
          action: "complete",
          output,
          duration_ms,
        });
      }

      return output;
    } catch (error) {
      const duration_ms = Date.now() - startTime;

      if (audit) {
        await audit.record({
          toolId: tool.id,
          agentId,
          action: "error",
          input,
          duration_ms,
        });
      }

      throw error;
    }
  };

  return { ...tool, execute: governedExecute } as T;
}
