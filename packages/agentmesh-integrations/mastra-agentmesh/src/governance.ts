// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Governance middleware for Mastra tool execution.
 *
 * Enforces rate limits, content filtering, PII redaction,
 * and tool allow/deny lists before tools execute.
 */

import type { GovernancePolicy, GovernanceResult } from "./types";

const callCounts = new Map<string, { count: number; windowStart: number }>();

/**
 * Creates a governance middleware that wraps a tool's execute function
 * with policy enforcement.
 *
 * @example
 * ```ts
 * const governed = governanceMiddleware({
 *   rateLimitPerMinute: 60,
 *   blockedPatterns: ["(?i)ignore previous", "(?i)system prompt"],
 *   piiFields: ["ssn", "credit_card"],
 * });
 *
 * const result = await governed.check(input, "my-tool", "agent-1");
 * if (!result.allowed) {
 *   console.log("Blocked:", result.violations);
 * }
 * ```
 */
export function governanceMiddleware(policy: GovernancePolicy) {
  return {
    /**
     * Check input against governance policies.
     * Returns a GovernanceResult indicating whether execution is allowed.
     */
    async check(
      input: unknown,
      toolId: string,
      agentId: string
    ): Promise<GovernanceResult> {
      const violations: string[] = [];
      let redactedInput = input;

      // Tool allowlist/denylist
      if (policy.blockedTools?.includes(toolId)) {
        violations.push(`Tool '${toolId}' is blocked by policy`);
      }
      if (
        policy.allowedTools &&
        policy.allowedTools.length > 0 &&
        !policy.allowedTools.includes(toolId)
      ) {
        violations.push(`Tool '${toolId}' is not in the allowed tools list`);
      }

      // Rate limiting
      if (policy.rateLimitPerMinute) {
        const key = `${agentId}:${toolId}`;
        const now = Date.now();
        const entry = callCounts.get(key);

        if (entry && now - entry.windowStart < 60_000) {
          entry.count++;
          if (entry.count > policy.rateLimitPerMinute) {
            violations.push(
              `Rate limit exceeded: ${entry.count}/${policy.rateLimitPerMinute} calls/min`
            );
          }
        } else {
          callCounts.set(key, { count: 1, windowStart: now });
        }
      }

      // Input length check
      if (policy.maxInputLength) {
        const inputStr =
          typeof input === "string" ? input : JSON.stringify(input);
        if (inputStr && inputStr.length > policy.maxInputLength) {
          violations.push(
            `Input length ${inputStr.length} exceeds maximum ${policy.maxInputLength}`
          );
        }
      }

      // Blocked patterns (content filtering)
      if (policy.blockedPatterns && policy.blockedPatterns.length > 0) {
        const inputStr =
          typeof input === "string" ? input : JSON.stringify(input);
        if (inputStr) {
          for (const pattern of policy.blockedPatterns) {
            const regex = new RegExp(pattern, "i");
            if (regex.test(inputStr)) {
              violations.push(`Input matches blocked pattern: ${pattern}`);
            }
          }
        }
      }

      // PII redaction
      if (policy.piiFields && policy.piiFields.length > 0) {
        redactedInput = redactPii(input, policy.piiFields);
      }

      // Custom policy check
      if (policy.customCheck) {
        const customResult = await policy.customCheck(input, toolId);
        if (!customResult.allowed) {
          violations.push(...customResult.violations);
        }
      }

      return {
        allowed: violations.length === 0,
        violations,
        redactedInput,
        reason:
          violations.length > 0
            ? `Blocked: ${violations.join("; ")}`
            : undefined,
      };
    },

    /** Reset rate limit counters (for testing). */
    resetRateLimits() {
      callCounts.clear();
    },
  };
}

/** Recursively redact PII fields from an object. */
function redactPii(data: unknown, piiFields: string[]): unknown {
  if (data === null || data === undefined) return data;
  if (typeof data === "string") return data;
  if (Array.isArray(data)) {
    return data.map((item) => redactPii(item, piiFields));
  }
  if (typeof data === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
      if (piiFields.some((f) => key.toLowerCase().includes(f.toLowerCase()))) {
        result[key] = "[REDACTED]";
      } else {
        result[key] = redactPii(value, piiFields);
      }
    }
    return result;
  }
  return data;
}
