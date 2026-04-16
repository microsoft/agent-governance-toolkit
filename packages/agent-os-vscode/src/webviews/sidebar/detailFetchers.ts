// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Detail Fetchers
 *
 * Rich data fetchers for promoted detail webview panels.
 * Each function maps raw provider data to the typed contracts
 * consumed by React detail views via postMessage.
 */

import type { SLOSnapshot } from '../../views/sloTypes';
import type { DataProviders } from './dataAggregator';
import type {
    SLODetailData,
    TopologyDetailData,
    AuditDetailData,
    PolicyDetailData,
    HubDetailData,
    KernelDetailData,
    MemoryDetailData,
    StatsDetailData,
} from '../shared/types';

/** Generate 24-point burn rate series from current value with slight variance. */
function generateBurnRateSeries(current: number): number[] {
    const points: number[] = [];
    for (let i = 0; i < 24; i++) {
        // SECURITY: Math.random() for synthetic sparkline demo data only. Not cryptographic.
        // Will be replaced by real SRE historical data when backend is available.
        const jitter = 1 + (Math.random() * 0.2 - 0.1);
        points.push(Math.round(current * jitter * 100) / 100);
    }
    return points;
}

/** Truncate a DID for display labels. */
function truncateDid(did: string, maxLen = 22): string {
    return did.length <= maxLen ? did : did.slice(0, maxLen) + '...';
}

/** Map an audit event type to a severity level. */
function mapSeverity(type?: string): 'info' | 'warning' | 'critical' {
    if (type === 'blocked') { return 'critical'; }
    if (type === 'warned') { return 'warning'; }
    return 'info';
}

/** Fetch full SLO detail data for the detail panel. */
export async function fetchSLODetail(p: DataProviders): Promise<SLODetailData | null> {
    try {
        const s: SLOSnapshot = await p.slo.getSnapshot();
        return {
            availability: s.availability.currentPercent,
            availabilityTarget: s.availability.targetPercent,
            availabilityBudgetRemaining: s.availability.errorBudgetRemainingPercent,
            burnRate: s.availability.burnRate,
            burnRateSeries: generateBurnRateSeries(s.availability.burnRate),
            latencyP50: s.latency.p50Ms,
            latencyP95: s.latency.p95Ms,
            latencyP99: s.latency.p99Ms,
            latencyTarget: s.latency.targetMs,
            latencyBudgetRemaining: s.latency.errorBudgetRemainingPercent,
            compliancePercent: s.policyCompliance.compliancePercent,
            complianceTarget: 100,
            violationsToday: s.policyCompliance.violationsToday,
            complianceTrend: s.policyCompliance.trend,
            trustMean: s.trustScore.meanScore,
            trustMin: s.trustScore.minScore,
            trustDistribution: s.trustScore.distribution,
            fetchedAt: s.fetchedAt ?? new Date().toISOString(),
        };
    } catch { return null; }
}

/** Fetch full topology detail data for the detail panel. */
export function fetchTopologyDetail(p: DataProviders): TopologyDetailData | null {
    try {
        const agents = p.topology.getAgents();
        const delegations = p.topology.getDelegations();
        const bridges = p.topology.getBridges();
        return {
            nodes: agents.map(a => ({
                id: a.did, trust: a.trustScore,
                ring: a.ring, label: truncateDid(a.did),
            })),
            edges: delegations.map(d => ({
                source: d.fromDid, target: d.toDid, capability: d.capability,
            })),
            bridges: bridges.map(b => ({
                protocol: b.protocol, connected: b.connected, peerCount: b.peerCount,
            })),
            fetchedAt: new Date().toISOString(),
        };
    } catch { return null; }
}

/** Fetch full audit detail data for the detail panel. */
export function fetchAuditDetail(p: DataProviders): AuditDetailData | null {
    try {
        const all = p.audit.getAll();
        const entries = all.map((e: unknown, i: number) => {
            const entry = e as { timestamp?: Date; type?: string; agentDid?: string; file?: string };
            return {
                id: `audit-${i}`,
                timestamp: entry.timestamp?.toISOString() ?? new Date().toISOString(),
                action: entry.type ?? 'unknown',
                agentDid: entry.agentDid ?? null,
                severity: mapSeverity(entry.type),
                result: entry.type ?? 'unknown',
                file: entry.file ?? null,
            };
        });
        return { entries, fetchedAt: new Date().toISOString() };
    } catch { return null; }
}

/** Fetch full policy detail data for the detail panel. */
export async function fetchPolicyDetail(p: DataProviders): Promise<PolicyDetailData | null> {
    try {
        const snap = await p.policy.getSnapshot();
        return {
            rules: snap.rules.map(r => ({
                id: r.id, name: r.name, action: r.action, pattern: r.pattern,
                enabled: r.enabled, evaluationsToday: r.evaluationsToday,
                violationsToday: r.violationsToday,
            })),
            totalEvaluations: snap.totalEvaluationsToday,
            totalViolations: snap.totalViolationsToday,
            fetchedAt: snap.fetchedAt ?? new Date().toISOString(),
        };
    } catch { return null; }
}

/** Fetch kernel debugger detail data. */
export function fetchKernelDetail(p: DataProviders): KernelDetailData | null {
    try {
        const k = p.kernel.getKernelSummary();
        return {
            activeAgents: [],
            policyViolations: k.policyViolations,
            totalCheckpoints: k.totalCheckpoints,
            uptimeSeconds: k.uptime,
            fetchedAt: new Date().toISOString(),
        };
    } catch { return null; }
}

/** Fetch memory browser detail data. */
export function fetchMemoryDetail(p: DataProviders): MemoryDetailData | null {
    try {
        const m = p.memory.getVfsSummary();
        return {
            directoryCount: m.directoryCount,
            fileCount: m.fileCount,
            rootPaths: m.rootPaths,
            tree: m.rootPaths.map(rp => ({ name: rp, type: 'directory' as const, path: rp })),
            fetchedAt: new Date().toISOString(),
        };
    } catch { return null; }
}

/** Fetch safety stats detail data. */
export function fetchStatsDetail(p: DataProviders): StatsDetailData | null {
    try {
        const s = p.audit.getStats();
        return {
            blockedToday: s.blockedToday,
            blockedThisWeek: s.blockedThisWeek,
            warningsToday: s.warningsToday,
            cmvkReviews: s.cmvkReviewsToday,
            totalLogs: s.totalLogs,
            fetchedAt: new Date().toISOString(),
        };
    } catch { return null; }
}

/** Fetch composite hub detail data from all providers. */
export async function fetchHubDetail(p: DataProviders): Promise<HubDetailData | null> {
    try {
        const [slo, policy] = await Promise.all([
            fetchSLODetail(p), fetchPolicyDetail(p),
        ]);
        return {
            slo,
            topology: fetchTopologyDetail(p),
            audit: fetchAuditDetail(p),
            policy,
            fetchedAt: new Date().toISOString(),
        };
    } catch { return null; }
}
