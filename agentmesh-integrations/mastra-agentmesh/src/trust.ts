// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Trust gate for Mastra tool execution.
 *
 * Verifies agent trust scores before allowing tool execution.
 * Trust scores follow AgentMesh's 0-1000 scale:
 *   0-299: Untrusted
 *   300-499: Probationary
 *   500-699: Standard
 *   700-899: Trusted
 *   900-1000: Verified Partner
 */

import type { TrustConfig, TrustVerification } from "./types";

/**
 * Creates a trust gate that verifies agent trust scores
 * before allowing tool execution.
 *
 * @example
 * ```ts
 * const gate = trustGate({
 *   minTrustScore: 500,
 *   getTrustScore: async (agentId) => {
 *     // Query your trust registry
 *     return 750;
 *   },
 * });
 *
 * const result = await gate.verify("agent-1");
 * if (!result.verified) {
 *   console.log(`Agent ${result.agentId} denied: score ${result.trustScore}`);
 * }
 * ```
 */
export function trustGate(config: TrustConfig) {
  return {
    /**
     * Verify an agent's trust score against the configured threshold.
     */
    async verify(agentId: string): Promise<TrustVerification> {
      const score = await config.getTrustScore(agentId);
      const verified = score >= config.minTrustScore;

      if (!verified && config.onTrustFailure) {
        await config.onTrustFailure(agentId, score);
      }

      return {
        verified,
        agentId,
        trustScore: score,
        threshold: config.minTrustScore,
        timestamp: Date.now(),
      };
    },

    /**
     * Get the trust tier label for a score.
     */
    getTier(score: number): string {
      if (score >= 900) return "verified_partner";
      if (score >= 700) return "trusted";
      if (score >= 500) return "standard";
      if (score >= 300) return "probationary";
      return "untrusted";
    },
  };
}
