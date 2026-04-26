// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * REST Response Translators
 *
 * Pure functions that validate and map agent-failsafe REST responses
 * to the extension's typed provider interfaces. Each translator
 * rejects invalid input (returns null) rather than coercing.
 */

import { SLOSnapshot } from '../views/sloTypes';
import { AgentNode, ExecutionRing } from '../views/topologyTypes';
import { PolicyRule, PolicySnapshot, PolicyAction } from '../views/policyTypes';

// ---------------------------------------------------------------------------
// Validation constants
// ---------------------------------------------------------------------------

const MAX_FLEET_AGENTS = 1000;
const MAX_AUDIT_EVENTS = 500;
const MAX_POLICIES = 200;
const MAX_STRING_LENGTH = 500;

// ---------------------------------------------------------------------------
// Type guards
// ---------------------------------------------------------------------------

function isObject(v: unknown): v is Record<string, unknown> {
    return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function isFiniteNumber(v: unknown): v is number {
    return typeof v === 'number' && Number.isFinite(v);
}

function truncate(s: unknown, max: number = MAX_STRING_LENGTH): string {
    const str = typeof s === 'string' ? s : '';
    return str.length > max ? str.slice(0, max) : str;
}

function clampRate(v: unknown): number | null {
    if (!isFiniteNumber(v)) { return null; }
    if (v < 0 || v > 1) { return null; }
    return v;
}

function safeDate(v: unknown): Date {
    if (typeof v === 'string') {
        const d = new Date(v);
        if (!isNaN(d.getTime())) { return d; }
    }
    return new Date();
}

// ---------------------------------------------------------------------------
// SLO translator
// ---------------------------------------------------------------------------

/**
 * Translate a raw /sre/snapshot response into an SLOSnapshot.
 *
 * @param raw - Untyped JSON from the REST endpoint
 * @returns Typed SLOSnapshot or null if validation fails
 */
export function translateSLO(raw: unknown): SLOSnapshot | null {
    if (!isObject(raw)) { return null; }

    const sli = isObject(raw.sli) ? raw.sli : {};
    const rawRate = sli.pass_rate ?? sli.passRate;
    const hasRate = rawRate !== undefined && rawRate !== null;
    const passRate = hasRate ? clampRate(rawRate) : null;

    // If a rate was provided but invalid (negative, Infinity, NaN), reject
    if (hasRate && passRate === null) { return null; }

    const rawTotal = sli.total_decisions ?? sli.totalDecisions;
    const totalDecisions = isFiniteNumber(rawTotal) ? rawTotal : 0;

    // Only populate compliance from live data — zeros for fields not yet served by the REST endpoint
    const compliancePercent = passRate !== null ? passRate * 100 : 0;
    const violationsToday = passRate !== null
        ? Math.max(0, totalDecisions - Math.round(totalDecisions * passRate)) : 0;

    return {
        availability: { currentPercent: 0, targetPercent: 0, errorBudgetRemainingPercent: 0, burnRate: 0 },
        latency: { p50Ms: 0, p95Ms: 0, p99Ms: 0, targetMs: 0, errorBudgetRemainingPercent: 0 },
        policyCompliance: {
            totalEvaluations: totalDecisions,
            violationsToday,
            compliancePercent,
            trend: 'stable',
        },
        trustScore: { meanScore: 0, minScore: 0, agentsBelowThreshold: 0, distribution: [0, 0, 0, 0] },
        fetchedAt: new Date().toISOString(),
    };
}

// ---------------------------------------------------------------------------
// Topology translator
// ---------------------------------------------------------------------------

const CIRCUIT_STATES = new Set(['closed', 'open', 'half-open']);

function translateOneAgent(raw: unknown): AgentNode | null {
    if (!isObject(raw)) { return null; }
    const did = raw.agentId ?? raw.agent_id;
    if (typeof did !== 'string' || did.length === 0) { return null; }

    const successRate = clampRate(raw.successRate ?? raw.success_rate);
    const rawCircuit = raw.circuitState ?? raw.circuit_state;
    const circuitState = (typeof rawCircuit === 'string' && CIRCUIT_STATES.has(rawCircuit))
        ? rawCircuit as AgentNode['circuitState'] : 'closed';
    const lastActive = truncate(raw.lastActiveAt ?? raw.last_active_at ?? '', MAX_STRING_LENGTH);
    const rawTaskCount = raw.taskCount ?? raw.task_count;
    const rawAvgLatency = raw.avgLatencyMs ?? raw.avg_latency_ms;
    const rawTrustStage = raw.trustStage ?? raw.trust_stage;
    const taskCount = isFiniteNumber(rawTaskCount) ? rawTaskCount : undefined;
    const avgLatency = isFiniteNumber(rawAvgLatency) ? rawAvgLatency : undefined;
    const trustStage = typeof rawTrustStage === 'string' ? truncate(rawTrustStage, 10) : undefined;

    return {
        did: truncate(did),
        trustScore: Math.round((successRate ?? 0.5) * 1000),
        ring: ExecutionRing.Ring2User,
        registeredAt: lastActive,
        lastActivity: lastActive,
        capabilities: [],
        circuitState,
        taskCount,
        avgLatencyMs: avgLatency,
        trustStage,
    };
}

/**
 * Translate a raw /sre/fleet or /sre/snapshot fleet array into AgentNode[].
 *
 * @param raw - Untyped JSON (expects { fleet: [...] } or { agents: [...] })
 * @returns AgentNode array (empty on invalid input, never null)
 */
export function translateTopology(raw: unknown): AgentNode[] {
    if (!isObject(raw)) { return []; }
    const fleet = Array.isArray(raw.fleet) ? raw.fleet
        : Array.isArray(raw.agents) ? raw.agents : [];

    return fleet
        .slice(0, MAX_FLEET_AGENTS)
        .map(translateOneAgent)
        .filter((a): a is AgentNode => a !== null);
}

// ---------------------------------------------------------------------------
// Policy translator
// ---------------------------------------------------------------------------

const VALID_ACTIONS = new Set<PolicyAction>(['ALLOW', 'DENY', 'AUDIT', 'BLOCK']);

function translateOnePolicy(raw: unknown, index: number): PolicyRule | null {
    if (!isObject(raw)) { return null; }
    const name = typeof raw.name === 'string' ? truncate(raw.name) : `policy-${index}`;
    const action = VALID_ACTIONS.has(raw.action as PolicyAction)
        ? raw.action as PolicyAction : 'AUDIT';

    return {
        id: typeof raw.id === 'string' ? truncate(raw.id, 64) : `rule-${index}`,
        name,
        description: truncate(raw.description ?? ''),
        action,
        pattern: truncate(raw.pattern ?? '*'),
        scope: 'global',
        enabled: raw.enabled !== false,
        evaluationsToday: isFiniteNumber(raw.evaluationsToday) ? raw.evaluationsToday : 0,
        violationsToday: isFiniteNumber(raw.violationsToday) ? raw.violationsToday : 0,
    };
}

/** ASI coverage entry from agent-failsafe. */
export interface ASICoverageEntry {
    label: string;
    covered: boolean;
    feature: string;
}

/**
 * Translate a raw /sre/snapshot response into a PolicySnapshot.
 *
 * @param raw - Untyped JSON from the REST endpoint
 * @returns Typed PolicySnapshot (empty on invalid input, never null)
 */
export function translatePolicy(raw: unknown): PolicySnapshot {
    if (!isObject(raw)) {
        return { rules: [], recentViolations: [], totalEvaluationsToday: 0, totalViolationsToday: 0 };
    }

    const rawPolicies = Array.isArray(raw.policies) ? raw.policies : [];
    const rules = rawPolicies
        .slice(0, MAX_POLICIES)
        .map(translateOnePolicy)
        .filter((r): r is PolicyRule => r !== null);

    const rawEvents = Array.isArray(raw.auditEvents) ? raw.auditEvents : [];
    const violations = rawEvents.slice(0, MAX_AUDIT_EVENTS).map((e: unknown, i: number) => {
        if (!isObject(e)) { return null; }
        return {
            id: typeof e.id === 'string' ? truncate(e.id, 64) : `evt-${i}`,
            ruleId: truncate(e.ruleId ?? ''),
            ruleName: truncate(e.ruleName ?? e.type ?? ''),
            timestamp: safeDate(e.timestamp),
            context: truncate(e.context ?? e.details ?? ''),
            action: 'AUDIT' as PolicyAction,
        };
    }).filter((v): v is NonNullable<typeof v> => v !== null);

    const asiCoverage = isObject(raw.asiCoverage)
        ? raw.asiCoverage as Record<string, ASICoverageEntry> : undefined;

    return {
        rules,
        recentViolations: violations,
        totalEvaluationsToday: rules.reduce((sum, r) => sum + r.evaluationsToday, 0),
        totalViolationsToday: violations.length,
        asiCoverage,
        fetchedAt: new Date().toISOString(),
    };
}
