// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * createGovernedTool wraps a Mastra tool with ACS, trust, and audit.
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
 *   control: AgentControl.fromPath("./manifest.yaml"),
 *   trust: {
 *     minTrustScore: 500,
 *     getTrustScore: async (agentId) => 750,
 *   },
 *   audit: { captureData: true },
 * });
 * ```
 */

import {
  AgentControlBlockedError,
  type AgentControl,
  type InterventionPointResult,
  type JsonValue,
} from "agent-control-specification";
import { trustGate } from "./trust";
import { auditMiddleware } from "./audit";
import type {
  AuditConfig,
  PolicyDecisionAudit,
  TrustConfig,
} from "./types";

export interface GovernedToolOptions {
  /** Native ACS runtime created from a manifest. */
  control: AgentControl;
  trust?: TrustConfig;
  audit?: AuditConfig;
  /** Agent ID for trust and audit (default: "default-agent"). */
  agentId?: string;
  /** Complete host snapshot fields merged into tool intervention points. */
  snapshot?: Record<string, JsonValue>;
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
  const control = options.control;
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

    // 2. ACS policy evaluation, transform application, and tool execution
    try {
      const result = await control.runTool(
        tool.id,
        input as JsonValue,
        async (effectiveInput) => {
          args[0] = effectiveInput;
          if (audit) {
            await audit.record({
              toolId: tool.id,
              agentId,
              action: "invoke",
              input: effectiveInput,
            });
          }
          return (await originalExecute.apply(this, args)) as JsonValue;
        },
        { snapshot: options.snapshot },
      );
      const duration_ms = Date.now() - startTime;

      if (audit) {
        await audit.record({
          toolId: tool.id,
          agentId,
          action: "complete",
          output: result.value,
          duration_ms,
          policy: toPolicyAudit(result.postToolCallResult),
        });
      }

      return result.value;
    } catch (error) {
      const duration_ms = Date.now() - startTime;

      if (audit) {
        if (error instanceof AgentControlBlockedError) {
          await audit.record({
            toolId: tool.id,
            agentId,
            action: "deny",
            input,
            duration_ms,
            policy: toPolicyAudit(error.result),
          });
        } else {
          await audit.record({
            toolId: tool.id,
            agentId,
            action: "error",
            input,
            duration_ms,
          });
        }
      }

      throw error;
    }
  };

  return { ...tool, execute: governedExecute } as T;
}

function toPolicyAudit(
  result: InterventionPointResult,
): PolicyDecisionAudit {
  return {
    verdict: result.verdict.decision,
    reason: result.verdict.reason ?? undefined,
    inputIdentity: result.inputIdentity ?? undefined,
    enforcedIdentity: result.enforcedIdentity ?? undefined,
  };
}
