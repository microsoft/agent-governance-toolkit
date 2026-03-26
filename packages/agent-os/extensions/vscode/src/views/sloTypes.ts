// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * SLO Dashboard Tree View Provider
 *
 * Displays real-time Service Level Objective monitoring in the sidebar.
 * Auto-refreshes every 10 seconds with color-coded health indicators.
 */

import * as vscode from 'vscode';

// ---------------------------------------------------------------------------
// Data contracts
// ---------------------------------------------------------------------------

/** Health status used for color-coding tree items. */
export type SLOHealth = 'healthy' | 'warning' | 'breached';

/** Snapshot of a single availability SLO window. */
export interface AvailabilitySLOData {
    /** Current compliance percentage (0-100). */
    currentPercent: number;
    /** Target compliance percentage (0-100). */
    targetPercent: number;
    /** Remaining error budget as a percentage (0-100). */
    errorBudgetRemainingPercent: number;
    /** Current burn rate multiplier (e.g. 1.0, 2.5). */
    burnRate: number;
}

/** Snapshot of a single latency SLO window. */
export interface LatencySLOData {
    /** P50 latency in milliseconds. */
    p50Ms: number;
    /** P95 latency in milliseconds. */
    p95Ms: number;
    /** P99 latency in milliseconds. */
    p99Ms: number;
    /** Target latency threshold in milliseconds. */
    targetMs: number;
    /** Remaining error budget as a percentage (0-100). */
    errorBudgetRemainingPercent: number;
}

/** Snapshot of policy-compliance SLO metrics. */
export interface PolicyComplianceSLOData {
    /** Total number of policy evaluations in the current window. */
    totalEvaluations: number;
    /** Number of violations recorded today. */
    violationsToday: number;
    /** Compliance rate as a percentage (0-100). */
    compliancePercent: number;
    /** Trend direction compared to the previous window. */
    trend: 'up' | 'down' | 'stable';
}

/** Snapshot of trust-score SLO metrics. */
export interface TrustScoreSLOData {
    /** Mean trust score across all agents (0-1000). */
    meanScore: number;
    /** Minimum observed trust score (0-1000). */
    minScore: number;
    /** Number of agents scoring below the acceptable threshold. */
    agentsBelowThreshold: number;
    /** Distribution buckets: [0-250, 251-500, 501-750, 751-1000]. */
    distribution: [number, number, number, number];
}

/** Complete SLO snapshot returned by a data provider. */
export interface SLOSnapshot {
    availability: AvailabilitySLOData;
    latency: LatencySLOData;
    policyCompliance: PolicyComplianceSLOData;
    trustScore: TrustScoreSLOData;
    /** ISO timestamp of when this snapshot was fetched from the REST endpoint. */
    fetchedAt?: string;
}

/**
 * Interface for fetching SLO data.
 *
 * Implementations may call a local Agent SRE bridge, an HTTP endpoint,
 * or return static mock data for development.
 */
export interface SLODataProvider {
    /** Fetch the latest SLO snapshot. */
    getSnapshot(): Promise<SLOSnapshot>;
}

// ---------------------------------------------------------------------------
// Tree item
// ---------------------------------------------------------------------------

/**
 * A tree item representing either an SLO category (collapsible) or a
 * detail metric (leaf).
 */
export class SLOItem extends vscode.TreeItem {
    /**
     * Construct a collapsible SLO category item.
     */
    static category(
        label: string,
        description: string,
        health: SLOHealth,
        icon: string,
        tooltip: string,
        children: SLOItem[]
    ): SLOItem {
        return new SLOItem(
            label,
            description,
            health,
            icon,
            tooltip,
            vscode.TreeItemCollapsibleState.Collapsed,
            children
        );
    }

    /**
     * Construct a leaf detail item.
     */
    static detail(
        label: string,
        description: string,
        health: SLOHealth,
        tooltip: string
    ): SLOItem {
        return new SLOItem(
            label,
            description,
            health,
            undefined,
            tooltip,
            vscode.TreeItemCollapsibleState.None,
            []
        );
    }

    /** Direct children of this item (empty for leaves). */
    readonly children: SLOItem[];

    private constructor(
        label: string,
        description: string,
        health: SLOHealth,
        icon: string | undefined,
        tip: string,
        collapsibleState: vscode.TreeItemCollapsibleState,
        children: SLOItem[]
    ) {
        super(label, collapsibleState);
        this.description = description;
        this.tooltip = new vscode.MarkdownString(tip);
        this.children = children;
        this.iconPath = icon
            ? new vscode.ThemeIcon(icon, SLOItem.colorForHealth(health))
            : SLOItem.iconForHealth(health);
        this.contextValue = collapsibleState === vscode.TreeItemCollapsibleState.None
            ? 'sloDetail'
            : 'sloCategory';
    }

    // -- visual helpers -----------------------------------------------------

    private static colorForHealth(health: SLOHealth): vscode.ThemeColor {
        switch (health) {
            case 'healthy':
                return new vscode.ThemeColor('testing.iconPassed');
            case 'warning':
                return new vscode.ThemeColor('list.warningForeground');
            case 'breached':
                return new vscode.ThemeColor('errorForeground');
        }
    }

    private static iconForHealth(health: SLOHealth): vscode.ThemeIcon {
        switch (health) {
            case 'healthy':
                return new vscode.ThemeIcon('pass', SLOItem.colorForHealth('healthy'));
            case 'warning':
                return new vscode.ThemeIcon('warning', SLOItem.colorForHealth('warning'));
            case 'breached':
                return new vscode.ThemeIcon('error', SLOItem.colorForHealth('breached'));
        }
    }
}
