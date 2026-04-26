// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Shared Detail Panel Data Types
 *
 * Contracts for messages flowing from extension host to detail webviews.
 * Each panel receives its data type via postMessage with a typed payload.
 */

// ---------------------------------------------------------------------------
// SLO Detail
// ---------------------------------------------------------------------------

/** Full SLO snapshot data for the detail panel. */
export interface SLODetailData {
    availability: number;
    availabilityTarget: number;
    availabilityBudgetRemaining: number;
    burnRate: number;
    /** 24 data points for sparkline visualization. */
    burnRateSeries: number[];
    latencyP50: number;
    latencyP95: number;
    latencyP99: number;
    latencyTarget: number;
    latencyBudgetRemaining: number;
    compliancePercent: number;
    /** Always 100 for compliance. */
    complianceTarget: number;
    violationsToday: number;
    complianceTrend: 'up' | 'down' | 'stable';
    trustMean: number;
    trustMin: number;
    /** Distribution buckets: [0-250, 251-500, 501-750, 751-1000]. */
    trustDistribution: [number, number, number, number];
    fetchedAt: string | null;
}

// ---------------------------------------------------------------------------
// Topology Detail (Phase 2)
// ---------------------------------------------------------------------------

export interface TopologyNode {
    id: string;
    trust: number;
    ring: number;
    label: string;
}

export interface TopologyEdge {
    source: string;
    target: string;
    capability: string;
}

export interface TopologyBridge {
    protocol: string;
    connected: boolean;
    peerCount: number;
}

export interface TopologyDetailData {
    nodes: TopologyNode[];
    edges: TopologyEdge[];
    bridges: TopologyBridge[];
    fetchedAt: string | null;
}

// ---------------------------------------------------------------------------
// Audit Detail (Phase 3)
// ---------------------------------------------------------------------------

export interface AuditEntry {
    id: string;
    timestamp: string;
    action: string;
    agentDid: string | null;
    severity: 'info' | 'warning' | 'critical';
    result: string;
    file: string | null;
}

export interface AuditDetailData {
    entries: AuditEntry[];
    fetchedAt: string | null;
}

// ---------------------------------------------------------------------------
// Policy Detail (Phase 3)
// ---------------------------------------------------------------------------

export interface PolicyRuleDetail {
    id: string;
    name: string;
    action: 'ALLOW' | 'DENY' | 'AUDIT' | 'BLOCK';
    pattern: string;
    enabled: boolean;
    evaluationsToday: number;
    violationsToday: number;
}

export interface PolicyDetailData {
    rules: PolicyRuleDetail[];
    totalEvaluations: number;
    totalViolations: number;
    fetchedAt: string | null;
}

// ---------------------------------------------------------------------------
// Kernel Debugger Detail
// ---------------------------------------------------------------------------

export interface KernelAgent {
    id: string;
    name: string;
    status: 'running' | 'paused' | 'stopped' | 'error';
    currentTask: string | null;
    memoryUsage: number;
    checkpointCount: number;
    signalCount: number;
}

export interface KernelDetailData {
    activeAgents: KernelAgent[];
    policyViolations: number;
    totalCheckpoints: number;
    uptimeSeconds: number;
    fetchedAt: string | null;
}

// ---------------------------------------------------------------------------
// Memory Browser Detail
// ---------------------------------------------------------------------------

export interface MemoryNode {
    name: string;
    type: 'file' | 'directory';
    path: string;
    children?: MemoryNode[];
    size?: number;
}

export interface MemoryDetailData {
    directoryCount: number;
    fileCount: number;
    rootPaths: string[];
    tree: MemoryNode[];
    fetchedAt: string | null;
}

// ---------------------------------------------------------------------------
// Safety Stats Detail
// ---------------------------------------------------------------------------

export interface StatsDetailData {
    blockedToday: number;
    blockedThisWeek: number;
    warningsToday: number;
    cmvkReviews: number;
    totalLogs: number;
    fetchedAt: string | null;
}

// ---------------------------------------------------------------------------
// Hub Composite (Phase 3)
// ---------------------------------------------------------------------------

export interface HubDetailData {
    slo: SLODetailData | null;
    topology: TopologyDetailData | null;
    audit: AuditDetailData | null;
    policy: PolicyDetailData | null;
    fetchedAt: string | null;
}
