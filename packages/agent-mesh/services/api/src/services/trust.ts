// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { TrustScore, TrustDimensions, TrustEvent } from "../types";

const TIER_THRESHOLDS: [number, TrustScore["tier"]][] = [
  [900, "Highly Trusted"],
  [750, "Trusted"],
  [500, "Verified"],
  [250, "Basic"],
  [0, "Untrusted"],
];

function tierFromScore(score: number): TrustScore["tier"] {
  for (const [threshold, tier] of TIER_THRESHOLDS) {
    if (score >= threshold) return tier;
  }
  return "Untrusted";
}

/** Create a default trust score for a newly registered agent. */
export function createInitialTrustScore(): TrustScore {
  const dimensions: TrustDimensions = {
    policy_compliance: 50,
    interaction_success: 50,
    verification_depth: 30,
    community_vouching: 0,
    uptime_reliability: 50,
  };
  const total = computeTotal(dimensions);
  return {
    total,
    dimensions,
    tier: tierFromScore(total),
    history: [
      {
        timestamp: new Date().toISOString(),
        event: "initial_registration",
        score_delta: total,
      },
    ],
  };
}

/** Weighted sum of dimensions (each 0-100, weights sum to ~1000 max). */
export function computeTotal(d: TrustDimensions): number {
  return Math.round(
    d.policy_compliance * 2.5 +
      d.interaction_success * 2.5 +
      d.verification_depth * 2.0 +
      d.community_vouching * 1.5 +
      d.uptime_reliability * 1.5,
  );
}

/** Evaluate trust for a handshake: return granted capabilities. */
export function evaluateHandshake(
  agentCapabilities: string[],
  requestedCapabilities: string[],
  trustScore: TrustScore,
): string[] {
  const capSet = new Set(agentCapabilities);
  // Only grant capabilities the agent actually has
  const eligible = requestedCapabilities.filter((c) => capSet.has(c));

  // Require at least Basic tier to grant any capabilities
  if (trustScore.total < 250) return [];

  return eligible;
}

/** Apply a trust event and recompute totals. */
export function applyTrustEvent(
  score: TrustScore,
  event: string,
  dimensionKey: keyof TrustDimensions,
  delta: number,
): TrustScore {
  const newDimensions = { ...score.dimensions };
  newDimensions[dimensionKey] = Math.max(
    0,
    Math.min(100, newDimensions[dimensionKey] + delta),
  );
  const total = computeTotal(newDimensions);
  const entry: TrustEvent = {
    timestamp: new Date().toISOString(),
    event,
    score_delta: total - score.total,
  };
  return {
    total,
    dimensions: newDimensions,
    tier: tierFromScore(total),
    history: [...score.history, entry],
  };
}
