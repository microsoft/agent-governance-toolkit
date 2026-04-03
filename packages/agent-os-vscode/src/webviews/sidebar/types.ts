// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Sidebar Types
 *
 * Shared type definitions for the 3-slot sidebar system.
 * Used by both the extension host (SidebarProvider) and the React webview.
 */

/** All available panel identifiers. */
export type PanelId =
    | 'governance-hub'
    | 'slo-dashboard'
    | 'audit-log'
    | 'agent-topology'
    | 'active-policies'
    | 'safety-stats'
    | 'kernel-debugger'
    | 'memory-browser';

/** Human-readable labels for each panel. */
export const PANEL_LABELS: Record<PanelId, string> = {
    'governance-hub': 'Governance Hub',
    'slo-dashboard': 'SLO Dashboard',
    'audit-log': 'Audit Log',
    'agent-topology': 'Agent Topology',
    'active-policies': 'Active Policies',
    'safety-stats': 'Safety Stats',
    'kernel-debugger': 'Kernel Debugger',
    'memory-browser': 'Memory Browser',
};

/** Codicon identifiers for each panel. */
export const PANEL_ICONS: Record<PanelId, string> = {
    'governance-hub': 'shield',
    'slo-dashboard': 'graph-line',
    'audit-log': 'list-unordered',
    'agent-topology': 'type-hierarchy',
    'active-policies': 'law',
    'safety-stats': 'pie-chart',
    'kernel-debugger': 'debug-alt',
    'memory-browser': 'database',
};

/** Which panel is assigned to each slot. */
export interface SlotConfig {
    slotA: PanelId;
    slotB: PanelId;
    slotC: PanelId;
}

/** Default slot assignments. */
export const DEFAULT_SLOTS: SlotConfig = {
    slotA: 'slo-dashboard',
    slotB: 'audit-log',
    slotC: 'agent-topology',
};

/** Compact SLO data for the sidebar summary. */
export interface SLOSummaryData {
    availability: number;
    availabilityTarget: number;
    latencyP99: number;
    latencyTarget: number;
    compliancePercent: number;
    violationsToday: number;
    trustMean: number;
    agentsBelowThreshold: number;
}

/** Compact audit data for the sidebar summary. */
export interface AuditSummaryData {
    totalToday: number;
    violationsToday: number;
    lastEventTime: string | null;
    lastEventAction: string | null;
}

/** Compact topology data for the sidebar summary. */
export interface TopologySummaryData {
    agentCount: number;
    bridgeCount: number;
    meanTrust: number;
    delegationCount: number;
}

/** Compact policy data for the sidebar summary. */
export interface PolicySummaryData {
    totalRules: number;
    enabledRules: number;
    denyRules: number;
    blockRules: number;
    evaluationsToday: number;
    violationsToday: number;
}

/** Compact safety stats for the sidebar summary. */
export interface StatsSummaryData {
    blockedToday: number;
    blockedThisWeek: number;
    warningsToday: number;
    cmvkReviews: number;
    totalLogs: number;
}

/** Compact kernel state for the sidebar summary. */
export interface KernelSummaryData {
    activeAgents: number;
    policyViolations: number;
    totalCheckpoints: number;
    uptimeSeconds: number;
}

/** Compact VFS state for the sidebar summary. */
export interface MemorySummaryData {
    directoryCount: number;
    fileCount: number;
    rootPaths: string[];
}

/** Governance Hub composite summary. */
export interface GovernanceHubData {
    overallHealth: 'healthy' | 'warning' | 'critical';
    activeAlerts: number;
    policyCompliance: number;
    agentCount: number;
}

/** Full sidebar state pushed from extension host to webview. */
export interface SidebarState {
    slots: SlotConfig;
    slo: SLOSummaryData | null;
    audit: AuditSummaryData | null;
    topology: TopologySummaryData | null;
    policy: PolicySummaryData | null;
    stats: StatsSummaryData | null;
    kernel: KernelSummaryData | null;
    memory: MemorySummaryData | null;
    hub: GovernanceHubData | null;
    stalePanels: PanelId[];
    attentionMode: AttentionMode;
    userSlots: SlotConfig;
}

/** Attention mode: manual locks to user config, auto enables scanning + priority. */
export type AttentionMode = 'manual' | 'auto';

/** Valid panel types for detail subscriptions (rich data pushed to full panels). */
export type DetailPanelType = 'slo' | 'topology' | 'audit' | 'policy' | 'hub' | 'kernel' | 'memory' | 'stats';

/** Slot position keys for scan rotation. */
export type SlotKey = 'slotA' | 'slotB' | 'slotC';

/** Health urgency level for priority ranking. */
export type UrgencyLevel = 'critical' | 'warning' | 'healthy' | 'unknown';

/** Typed events for host-side coordination via GovernanceEventBus. */
export type GovernanceEvent =
    | { type: 'stateChanged'; state: SidebarState }
    | { type: 'slotConfigChanged'; slots: SlotConfig }
    | { type: 'refreshRequested' }
    | { type: 'visibilityChanged'; visible: boolean }
    | { type: 'panelIsolated'; panelId: PanelId }
    | { type: 'panelRejoined'; panelId: PanelId };

/** Messages from extension host to webview. */
export type HostMessage =
    | { type: 'stateUpdate'; state: SidebarState };

/** Messages from webview to extension host. */
export type WebviewMessage =
    | { type: 'ready' }
    | { type: 'setSlots'; slots: SlotConfig }
    | { type: 'promotePanelToWebview'; panelId: PanelId }
    | { type: 'refresh' }
    | { type: 'setAttentionMode'; mode: AttentionMode }
    | { type: 'openInBrowser' };
