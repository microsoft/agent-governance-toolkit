// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Backend Response Translators
 *
 * Pure functions that map Python API JSON shapes to TypeScript interfaces.
 * Every function handles missing/null fields with safe defaults.
 */

import type {
    SLOSnapshot, AvailabilitySLOData, LatencySLOData,
    PolicyComplianceSLOData, TrustScoreSLOData,
} from '../views/sloTypes';
import type { AgentNode, BridgeStatus, DelegationChain } from '../views/topologyTypes';
import { ExecutionRing } from '../views/topologyTypes';
import type { PolicySnapshot, PolicyRule, PolicyViolation, PolicyAction } from '../views/policyTypes';
import type {
    RawSLI, RawLatency, RawTrustScores, RawSLOPayload,
    RawAgent, RawBridge, RawDelegation,
    RawPolicyRule, RawPolicyViolation, RawPolicyPayload,
} from './rawApiTypes';

// Re-export raw types for client consumers
export type {
    RawSLOPayload, RawAgent, RawBridge, RawDelegation,
    RawPolicyRule, RawPolicyViolation, RawPolicyPayload,
} from './rawApiTypes';

// ---------------------------------------------------------------------------
// SLO translators
// ---------------------------------------------------------------------------

function errorBudget(current: number, target: number): number {
    if (target >= 1) { return 0; }
    const consumed = Math.max(0, target - current) / (1 - target);
    return Math.max(0, Math.round((1 - consumed) * 10000) / 100);
}

function burnRate(current: number, target: number): number {
    if (target >= 1 || current >= target) { return 0; }
    const consumed = (target - current) / (1 - target);
    return Math.round(consumed * 100) / 100;
}

export function translateAvailability(raw?: RawSLI): AvailabilitySLOData {
    const value = raw?.value ?? 0.999;
    const target = raw?.target ?? 0.995;
    return {
        currentPercent: Math.round(value * 10000) / 100,
        targetPercent: Math.round(target * 10000) / 100,
        errorBudgetRemainingPercent: errorBudget(value, target),
        burnRate: burnRate(value, target),
    };
}

export function translateLatency(raw?: RawLatency): LatencySLOData {
    const target = raw?.target ?? 5000;
    const p99 = raw?.p99 ?? 0;
    const budgetUsed = target > 0 ? Math.min(1, p99 / target) : 0;
    return {
        p50Ms: raw?.p50 ?? 0,
        p95Ms: raw?.p95 ?? 0,
        p99Ms: p99,
        targetMs: target,
        errorBudgetRemainingPercent: Math.round((1 - budgetUsed) * 10000) / 100,
    };
}

export function translateCompliance(raw?: RawSLI): PolicyComplianceSLOData {
    const value = raw?.value ?? 1;
    const compliance = raw?.compliance ?? value;
    const diff = value - compliance;
    let trend: 'up' | 'down' | 'stable' = 'stable';
    if (diff > 0.001) { trend = 'up'; }
    if (diff < -0.001) { trend = 'down'; }
    return {
        totalEvaluations: 0,
        violationsToday: 0,
        compliancePercent: Math.round(value * 10000) / 100,
        trend,
    };
}

export function translateTrustScore(raw?: RawTrustScores): TrustScoreSLOData {
    const dist = raw?.distribution ?? [0, 0, 0, 0];
    return {
        meanScore: raw?.mean ?? 0,
        minScore: raw?.min ?? 0,
        agentsBelowThreshold: raw?.below_threshold ?? 0,
        distribution: [dist[0] ?? 0, dist[1] ?? 0, dist[2] ?? 0, dist[3] ?? 0],
    };
}

export function translateSLOSnapshot(raw: RawSLOPayload | null | undefined): SLOSnapshot {
    const data = raw ?? {};
    return {
        availability: translateAvailability(data.task_success_rate),
        latency: translateLatency(data.response_latency),
        policyCompliance: translateCompliance(data.policy_compliance),
        trustScore: translateTrustScore(data.trust_scores),
    };
}

// ---------------------------------------------------------------------------
// Topology translators
// ---------------------------------------------------------------------------

/** Map a trust score (0-1000) to an execution ring. */
export function mapTrustToRing(score: number): ExecutionRing {
    if (score >= 900) { return ExecutionRing.Ring0Root; }
    if (score >= 700) { return ExecutionRing.Ring1Supervisor; }
    if (score >= 400) { return ExecutionRing.Ring2User; }
    return ExecutionRing.Ring3Sandbox;
}

export function translateAgent(raw: RawAgent | null | undefined): AgentNode {
    const data = raw ?? {};
    const trustScore = data.trust_score ?? 500;
    return {
        did: data.did ?? '',
        trustScore,
        ring: mapTrustToRing(trustScore),
        registeredAt: data.created_at ?? '',
        lastActivity: data.last_activity ?? '',
        capabilities: data.capabilities ?? [],
    };
}

export function translateBridge(raw: RawBridge | null | undefined): BridgeStatus {
    const data = raw ?? {};
    return {
        protocol: data.protocol ?? 'unknown',
        connected: data.connected ?? false,
        peerCount: data.peer_count ?? 0,
    };
}

export function translateDelegation(raw: RawDelegation | null | undefined): DelegationChain {
    const data = raw ?? {};
    return {
        fromDid: data.from_did ?? '',
        toDid: data.to_did ?? '',
        capability: data.capability ?? '',
        expiresIn: data.expires_in ?? '',
    };
}

// ---------------------------------------------------------------------------
// Policy translators
// ---------------------------------------------------------------------------

const VALID_ACTIONS = new Set<string>(['ALLOW', 'DENY', 'AUDIT', 'BLOCK']);

function normalizeAction(action?: string): PolicyAction {
    const upper = (action ?? 'DENY').toUpperCase();
    return VALID_ACTIONS.has(upper) ? (upper as PolicyAction) : 'DENY';
}

const VALID_SCOPES = new Set<string>(['file', 'tool', 'agent', 'global']);

function normalizeScope(scope?: string): PolicyRule['scope'] {
    const lower = (scope ?? 'global').toLowerCase();
    return VALID_SCOPES.has(lower) ? (lower as PolicyRule['scope']) : 'global';
}

export function translatePolicyRule(raw: RawPolicyRule | null | undefined): PolicyRule {
    const data = raw ?? {};
    return {
        id: data.id ?? '',
        name: data.name ?? '',
        description: data.description ?? '',
        action: normalizeAction(data.action),
        pattern: data.pattern ?? '',
        scope: normalizeScope(data.scope),
        enabled: data.enabled ?? true,
        evaluationsToday: data.evaluations_today ?? 0,
        violationsToday: data.violations_today ?? 0,
    };
}

export function translatePolicyViolation(
    raw: RawPolicyViolation | null | undefined,
): PolicyViolation {
    const data = raw ?? {};
    return {
        id: data.id ?? '',
        ruleId: data.rule_id ?? '',
        ruleName: data.rule_name ?? '',
        timestamp: data.timestamp ? new Date(data.timestamp) : new Date(0),
        agentDid: data.agent_did,
        file: data.file,
        line: data.line,
        context: data.context ?? '',
        action: normalizeAction(data.action),
    };
}

export function translatePolicySnapshot(
    raw: RawPolicyPayload | null | undefined,
): PolicySnapshot {
    const data = raw ?? {};
    const rules = (data.rules ?? []).map(translatePolicyRule);
    const violations = (data.recent_violations ?? []).map(translatePolicyViolation);
    return {
        rules,
        recentViolations: violations,
        totalEvaluationsToday: data.total_evaluations_today ?? 0,
        totalViolationsToday: data.total_violations_today ?? 0,
    };
}
