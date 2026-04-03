// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Data Aggregator
 *
 * Fetches data from all providers and maps it into the compact
 * SidebarState shape. Extracted from SidebarProvider for Section 4 compliance.
 */

import { SLODataProvider, SLOSnapshot } from '../../views/sloTypes';
import { AgentTopologyDataProvider } from '../../views/topologyTypes';
import { PolicyDataProvider } from '../../views/policyTypes';
import type {
    SidebarState,
    SLOSummaryData,
    AuditSummaryData,
    TopologySummaryData,
    PolicySummaryData,
    StatsSummaryData,
    KernelSummaryData,
    MemorySummaryData,
    GovernanceHubData,
} from './types';
// Re-export detail fetchers from dedicated module (Section 4 file-size compliance)
export {
    fetchSLODetail, fetchTopologyDetail, fetchAuditDetail,
    fetchPolicyDetail, fetchHubDetail,
    fetchKernelDetail, fetchMemoryDetail, fetchStatsDetail,
} from './detailFetchers';

/** Providers bundle passed to the aggregator. */
export interface DataProviders {
    slo: SLODataProvider;
    topology: AgentTopologyDataProvider;
    audit: { getAll(): unknown[]; getStats(): { blockedToday: number; blockedThisWeek: number; warningsToday: number; cmvkReviewsToday: number; totalLogs: number } };
    policy: PolicyDataProvider;
    kernel: { getKernelSummary(): { activeAgents: number; policyViolations: number; totalCheckpoints: number; uptime: number } };
    memory: { getVfsSummary(): { directoryCount: number; fileCount: number; rootPaths: string[] } };
}

export async function fetchSLO(p: DataProviders): Promise<SLOSummaryData | null> {
    try {
        const s: SLOSnapshot = await p.slo.getSnapshot();
        return {
            availability: s.availability.currentPercent,
            availabilityTarget: s.availability.targetPercent,
            latencyP99: s.latency.p99Ms,
            latencyTarget: s.latency.targetMs,
            compliancePercent: s.policyCompliance.compliancePercent,
            violationsToday: s.policyCompliance.violationsToday,
            trustMean: s.trustScore.meanScore,
            agentsBelowThreshold: s.trustScore.agentsBelowThreshold,
        };
    } catch { return null; }
}

export function fetchTopology(p: DataProviders): TopologySummaryData | null {
    try {
        const agents = p.topology.getAgents();
        const bridges = p.topology.getBridges();
        const delegations = p.topology.getDelegations();
        const totalTrust = agents.reduce((sum, a) => sum + a.trustScore, 0);
        return {
            agentCount: agents.length,
            bridgeCount: bridges.filter(b => b.connected).length,
            meanTrust: agents.length > 0 ? Math.round(totalTrust / agents.length) : 0,
            delegationCount: delegations.length,
        };
    } catch { return null; }
}

export function fetchAudit(p: DataProviders): AuditSummaryData | null {
    try {
        const all = p.audit.getAll();
        const today = new Date().toISOString().slice(0, 10);
        const todayEntries = all.filter((e: unknown) => {
            const entry = e as { timestamp?: Date; type?: string };
            return entry.timestamp && entry.timestamp.toISOString().slice(0, 10) === today;
        });
        const violations = todayEntries.filter((e: unknown) => {
            return (e as { type?: string }).type === 'blocked';
        });
        const last = all.length > 0 ? all[all.length - 1] as { timestamp?: Date; type?: string } : null;
        return {
            totalToday: todayEntries.length,
            violationsToday: violations.length,
            lastEventTime: last?.timestamp ? last.timestamp.toISOString() : null,
            lastEventAction: last?.type ?? null,
        };
    } catch { return null; }
}

export async function fetchPolicy(p: DataProviders): Promise<PolicySummaryData | null> {
    try {
        const snap = await p.policy.getSnapshot();
        const enabled = snap.rules.filter(r => r.enabled);
        return {
            totalRules: snap.rules.length,
            enabledRules: enabled.length,
            denyRules: enabled.filter(r => r.action === 'DENY').length,
            blockRules: enabled.filter(r => r.action === 'BLOCK').length,
            evaluationsToday: snap.totalEvaluationsToday,
            violationsToday: snap.totalViolationsToday,
        };
    } catch { return null; }
}

export function fetchStats(p: DataProviders): StatsSummaryData | null {
    try {
        const s = p.audit.getStats();
        return {
            blockedToday: s.blockedToday,
            blockedThisWeek: s.blockedThisWeek,
            warningsToday: s.warningsToday,
            cmvkReviews: s.cmvkReviewsToday,
            totalLogs: s.totalLogs,
        };
    } catch { return null; }
}

export function fetchKernel(p: DataProviders): KernelSummaryData | null {
    try {
        const k = p.kernel.getKernelSummary();
        return {
            activeAgents: k.activeAgents,
            policyViolations: k.policyViolations,
            totalCheckpoints: k.totalCheckpoints,
            uptimeSeconds: k.uptime,
        };
    } catch { return null; }
}

export function fetchMemory(p: DataProviders): MemorySummaryData | null {
    try {
        const m = p.memory.getVfsSummary();
        return { directoryCount: m.directoryCount, fileCount: m.fileCount, rootPaths: m.rootPaths };
    } catch { return null; }
}

export function deriveHub(state: SidebarState): GovernanceHubData {
    const violations = state.audit?.violationsToday ?? 0;
    const policyViolations = state.kernel?.policyViolations ?? 0;
    const alerts = violations + policyViolations;
    const compliance = state.slo?.compliancePercent ?? 100;
    const agents = state.topology?.agentCount ?? 0;

    let health: 'healthy' | 'warning' | 'critical' = 'healthy';
    if (alerts > 0 || compliance < 95) { health = 'warning'; }
    if (alerts > 5 || compliance < 90) { health = 'critical'; }

    return { overallHealth: health, activeAlerts: alerts, policyCompliance: compliance, agentCount: agents };
}


