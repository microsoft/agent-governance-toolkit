// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Governance Status Bar Manager for Agent OS VS Code Extension
 *
 * Provides a rich, multi-indicator governance status bar showing policy
 * enforcement mode, SLO health, active agent count, and violation tracking.
 */

import * as vscode from 'vscode';
import {
    GovernanceMode,
    SLOBreakdown,
    AgentInfo,
    ViolationBreakdown,
    MODE_LABELS,
    buildModeTooltip,
    buildViolationTooltip,
    truncateAgentDid,
} from './governanceStatusBarTypes';

/**
 * Enhanced governance-aware status bar with multiple indicators.
 *
 * Displays four right-aligned status bar items:
 * 1. Governance Mode (priority 96)
 * 2. SLO Health (priority 95)
 * 3. Active Agents (priority 94)
 * 4. Violations Counter (priority 93)
 */
class GovernanceStatusBar implements vscode.Disposable {
    private readonly modeItem: vscode.StatusBarItem;
    private readonly sloItem: vscode.StatusBarItem;
    private readonly agentItem: vscode.StatusBarItem;
    private readonly violationItem: vscode.StatusBarItem;

    private violationCount: number = 0;
    private violationBreakdown: ViolationBreakdown = { errors: 0, warnings: 0 };
    private lastPolicyReload: Date = new Date();
    private currentMode: GovernanceMode = 'strict';

    constructor() {
        this.modeItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 96);
        this.modeItem.command = 'agent-os.configurePolicy';
        this.modeItem.text = `$(shield) Strict`;
        this.modeItem.tooltip = buildModeTooltip('strict', 0, this.lastPolicyReload);
        this.modeItem.show();

        this.sloItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 95);
        this.sloItem.command = 'agent-os.showMetrics';

        this.agentItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 94);
        this.agentItem.command = 'agent-os.showTopologyGraph';
        this.agentItem.text = `$(organization) 0 agents`;
        this.agentItem.tooltip = 'No agents registered';
        this.agentItem.show();

        this.violationItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 93);
        this.violationItem.command = 'agent-os.showAuditLog';
        this.violationItem.text = `$(check) Clean`;
        this.violationItem.tooltip = 'No violations today';
        this.violationItem.show();
    }

    /**
     * Update the governance mode indicator.
     *
     * @param mode - The active policy enforcement mode.
     * @param activePolicies - Number of currently loaded policy documents.
     */
    updateGovernanceMode(mode: GovernanceMode, activePolicies: number): void {
        this.currentMode = mode;
        this.lastPolicyReload = new Date();
        this.modeItem.text = `$(shield) ${MODE_LABELS[mode]}`;
        this.modeItem.tooltip = buildModeTooltip(mode, activePolicies, this.lastPolicyReload);
        const colors: Record<GovernanceMode, string> = {
            strict: 'statusBarItem.prominentBackground',
            permissive: 'statusBarItem.warningBackground',
            'audit-only': 'statusBarItem.errorBackground',
        };
        this.modeItem.backgroundColor = new vscode.ThemeColor(colors[mode]);
    }

    /**
     * Update the SLO health indicator.
     *
     * The item is shown on first call and remains visible thereafter.
     *
     * @param overall - Aggregate SLO percentage (0-100).
     * @param breakdown - Per-dimension SLO values.
     */
    updateSLOHealth(overall: number, breakdown: SLOBreakdown): void {
        const pct = overall.toFixed(1);
        const icon = overall < 99.5 ? 'warning' : 'pulse';
        this.sloItem.text = `$(${icon}) SLO: ${pct}%`;

        if (overall >= 99.5) {
            this.sloItem.color = new vscode.ThemeColor('testing.iconPassed');
            this.sloItem.backgroundColor = undefined;
        } else if (overall >= 99.0) {
            this.sloItem.color = new vscode.ThemeColor('editorWarning.foreground');
            this.sloItem.backgroundColor = undefined;
        } else {
            this.sloItem.color = undefined;
            this.sloItem.backgroundColor = new vscode.ThemeColor(
                'statusBarItem.errorBackground',
            );
        }

        const lines = [
            `Aggregate SLO: ${pct}%`,
            '',
            `  Availability: ${breakdown.availability.toFixed(1)}%`,
            `  Latency:      ${breakdown.latency.toFixed(1)}%`,
            `  Compliance:   ${breakdown.compliance.toFixed(1)}%`,
            '',
            'Click to view metrics dashboard',
        ];
        this.sloItem.tooltip = lines.join('\n');
        this.sloItem.show();
    }

    /**
     * Update the active agent count indicator.
     *
     * @param count - Number of currently registered agents.
     * @param agents - Optional list of agent DIDs and trust scores.
     */
    updateAgentCount(count: number, agents?: AgentInfo[]): void {
        const label = count === 1 ? 'agent' : 'agents';
        this.agentItem.text = `$(organization) ${count} ${label}`;

        const lines: string[] = [`${count} registered ${label}`];

        if (agents && agents.length > 0) {
            lines.push('');
            const display = agents.slice(0, 10);
            for (const agent of display) {
                const truncatedDid = truncateAgentDid(agent.did);
                lines.push(`  ${truncatedDid}  trust: ${agent.trust}`);
            }
            if (agents.length > 10) {
                lines.push(`  ... and ${agents.length - 10} more`);
            }

            const avgTrust =
                agents.reduce((sum, a) => sum + a.trust, 0) / agents.length;
            lines.push('');
            lines.push(`Overall trust: ${avgTrust.toFixed(0)}/1000`);
        }

        lines.push('');
        lines.push('Click to view agent topology');
        this.agentItem.tooltip = lines.join('\n');
    }

    /**
     * Update the violation counter with a full breakdown.
     *
     * @param count - Total violations today.
     * @param breakdown - Optional severity breakdown and last violation time.
     */
    updateViolations(count: number, breakdown?: ViolationBreakdown): void {
        this.violationCount = count;
        this.violationBreakdown = breakdown ?? { errors: 0, warnings: 0 };

        if (count === 0) {
            this.violationItem.text = `$(check) Clean`;
            this.violationItem.backgroundColor = undefined;
            this.violationItem.color = new vscode.ThemeColor('testing.iconPassed');
            this.violationItem.tooltip = 'No violations today';
        } else {
            const label = count === 1 ? 'violation' : 'violations';
            this.violationItem.text = `$(error) ${count} ${label}`;
            this.violationItem.backgroundColor = new vscode.ThemeColor(
                'statusBarItem.warningBackground',
            );
            this.violationItem.color = undefined;
            this.violationItem.tooltip = buildViolationTooltip(
                this.violationCount,
                this.violationBreakdown,
            );
        }
    }

    /**
     * Increment the violation counter by one.
     *
     * Updates the display immediately using the existing breakdown.
     */
    incrementViolations(): void {
        this.violationBreakdown.errors += 1;
        this.violationBreakdown.lastViolation = new Date();
        this.updateViolations(this.violationCount + 1, this.violationBreakdown);
    }

    /**
     * Update the connection state indicator on the mode item.
     *
     * @param state - 'live' | 'stale' | 'disconnected' | 'no-endpoint'
     * @param staleSecs - Seconds since last successful fetch (for stale state).
     */
    updateConnectionState(
        state: 'live' | 'stale' | 'disconnected' | 'no-endpoint',
        staleSecs?: number,
    ): void {
        switch (state) {
            case 'live':
                this.modeItem.text = `$(shield) ${MODE_LABELS[this.currentMode]}`;
                this.modeItem.color = new vscode.ThemeColor('testing.iconPassed');
                this.modeItem.backgroundColor = undefined;
                break;
            case 'stale':
                this.modeItem.text = `$(plug) Stale ${staleSecs ?? '?'}s`;
                this.modeItem.color = new vscode.ThemeColor('editorWarning.foreground');
                this.modeItem.backgroundColor = undefined;
                break;
            case 'disconnected':
                this.modeItem.text = `$(plug) Disconnected`;
                this.modeItem.color = undefined;
                this.modeItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
                break;
            case 'no-endpoint':
                this.modeItem.text = `$(circle-slash) No endpoint`;
                this.modeItem.color = new vscode.ThemeColor('disabledForeground');
                this.modeItem.backgroundColor = undefined;
                break;
        }
    }

    /** Reset all violation state. Intended to be called at the start of each day. */
    resetDaily(): void {
        this.updateViolations(0);
    }

    /** Dispose all status bar items. */
    dispose(): void {
        this.modeItem.dispose();
        this.sloItem.dispose();
        this.agentItem.dispose();
        this.violationItem.dispose();
    }
}

export { GovernanceStatusBar };
