// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Raw Python API Response Types
 *
 * These interfaces describe the JSON shapes returned by the Python
 * Agent OS / Agent SRE / AgentMesh backend services. Used by
 * translators to map into TypeScript domain types.
 */

// ---------------------------------------------------------------------------
// SLO (agent-sre)
// ---------------------------------------------------------------------------

export interface RawSLI {
    value?: number;
    target?: number;
    compliance?: number;
    window?: string;
}

export interface RawLatency extends RawSLI {
    p50?: number;
    p95?: number;
    p99?: number;
}

export interface RawTrustScores {
    mean?: number;
    min?: number;
    below_threshold?: number;
    distribution?: number[];
}

export interface RawSLOPayload {
    task_success_rate?: RawSLI;
    response_latency?: RawLatency;
    policy_compliance?: RawSLI;
    trust_scores?: RawTrustScores;
}

// ---------------------------------------------------------------------------
// Topology (agentmesh)
// ---------------------------------------------------------------------------

export interface RawAgent {
    did?: string;
    trust_score?: number;
    status?: string;
    created_at?: string;
    last_activity?: string;
    capabilities?: string[];
}

export interface RawBridge {
    protocol?: string;
    connected?: boolean;
    peer_count?: number;
}

export interface RawDelegation {
    from_did?: string;
    to_did?: string;
    capability?: string;
    expires_in?: string;
}

// ---------------------------------------------------------------------------
// Policy (agent-os)
// ---------------------------------------------------------------------------

export interface RawPolicyRule {
    id?: string;
    name?: string;
    description?: string;
    action?: string;
    pattern?: string;
    scope?: string;
    enabled?: boolean;
    evaluations_today?: number;
    violations_today?: number;
}

export interface RawPolicyViolation {
    id?: string;
    rule_id?: string;
    rule_name?: string;
    timestamp?: string;
    agent_did?: string;
    file?: string;
    line?: number;
    context?: string;
    action?: string;
}

export interface RawPolicyPayload {
    rules?: RawPolicyRule[];
    recent_violations?: RawPolicyViolation[];
    total_evaluations_today?: number;
    total_violations_today?: number;
}
