// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * SLO Dashboard Tree View Provider
 *
 * Thin shell that wires the SLO data provider to the VS Code tree view.
 * Health helpers and category builders live in ./sloBuilders.
 * Type definitions and tree items live in ./sloTypes.
 */

import * as vscode from 'vscode';

import { SLOItem, SLOSnapshot, SLODataProvider } from './sloTypes';
import {
    buildAvailability,
    buildLatency,
    buildPolicyCompliance,
    buildTrustScore,
} from './sloBuilders';

export { SLOItem } from './sloTypes';
export type { SLOHealth, SLOSnapshot, SLODataProvider } from './sloTypes';

// ---------------------------------------------------------------------------
// Tree data provider
// ---------------------------------------------------------------------------

/** Auto-refresh interval in milliseconds (10 seconds). */
const REFRESH_INTERVAL_MS = 10_000;

/**
 * VS Code tree data provider for the SLO monitoring dashboard.
 *
 * Accepts any {@link SLODataProvider} for fetching data. During
 * development you can pass the result of
 * {@link SLODashboardProvider.createMockProvider} to get simulated values.
 */
export class SLODashboardProvider implements vscode.TreeDataProvider<SLOItem>, vscode.Disposable {
    private readonly _onDidChangeTreeData = new vscode.EventEmitter<SLOItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<SLOItem | undefined | null | void> = this._onDidChangeTreeData.event;

    private readonly _timer: ReturnType<typeof setInterval>;
    private _cachedSnapshot: SLOSnapshot | undefined;

    constructor(private readonly dataProvider: SLODataProvider) {
        this._timer = setInterval(() => this.refresh(), REFRESH_INTERVAL_MS);
    }

    /** Force a refresh of all SLO data. */
    refresh(): void {
        this._cachedSnapshot = undefined;
        this._onDidChangeTreeData.fire();
    }

    dispose(): void {
        clearInterval(this._timer);
        this._onDidChangeTreeData.dispose();
    }

    getTreeItem(element: SLOItem): vscode.TreeItem {
        return element;
    }

    async getChildren(element?: SLOItem): Promise<SLOItem[]> {
        if (element) {
            return element.children;
        }

        const snapshot = await this._getSnapshot();
        if (!snapshot) {
            return [
                SLOItem.detail(
                    'Unable to fetch SLO data',
                    '',
                    'warning',
                    'The SLO data provider returned no data. Check your Agent SRE connection.'
                )
            ];
        }

        return [
            buildAvailability(snapshot.availability),
            buildLatency(snapshot.latency),
            buildPolicyCompliance(snapshot.policyCompliance),
            buildTrustScore(snapshot.trustScore),
        ];
    }

    // -- mock provider ------------------------------------------------------

    /**
     * Returns an {@link SLODataProvider} that produces randomised but
     * realistic SLO data. Useful for UI development without a running
     * Agent SRE backend.
     */
    static createMockProvider(): SLODataProvider {
        return {
            async getSnapshot(): Promise<SLOSnapshot> {
                const jitter = (base: number, range: number): number =>
                    +(base + (Math.random() - 0.5) * range).toFixed(2);
                return {
                    availability: {
                        currentPercent: jitter(99.8, 0.4),
                        targetPercent: 99.5,
                        errorBudgetRemainingPercent: jitter(62, 20),
                        burnRate: jitter(1.1, 0.6),
                    },
                    latency: {
                        p50Ms: jitter(45, 20),
                        p95Ms: jitter(120, 40),
                        p99Ms: jitter(230, 80),
                        targetMs: 300,
                        errorBudgetRemainingPercent: jitter(78, 15),
                    },
                    policyCompliance: {
                        totalEvaluations: Math.round(jitter(1284, 200)),
                        violationsToday: Math.round(Math.max(0, jitter(3, 6))),
                        compliancePercent: jitter(99.6, 0.8),
                        trend: (['up', 'down', 'stable'] as const)[Math.floor(Math.random() * 3)],
                    },
                    trustScore: {
                        meanScore: Math.round(jitter(820, 60)),
                        minScore: Math.round(jitter(410, 100)),
                        agentsBelowThreshold: Math.round(Math.max(0, jitter(1, 4))),
                        distribution: [
                            Math.round(Math.max(0, jitter(2, 4))),
                            Math.round(Math.max(0, jitter(5, 6))),
                            Math.round(jitter(18, 8)),
                            Math.round(jitter(42, 10)),
                        ],
                    },
                };
            },
        };
    }

    // -- snapshot cache ------------------------------------------------------

    private async _getSnapshot(): Promise<SLOSnapshot | undefined> {
        if (this._cachedSnapshot) {
            return this._cachedSnapshot;
        }
        try {
            this._cachedSnapshot = await this.dataProvider.getSnapshot();
            return this._cachedSnapshot;
        } catch {
            return undefined;
        }
    }
}
