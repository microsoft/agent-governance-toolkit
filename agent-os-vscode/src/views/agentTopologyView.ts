// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Agent Topology Tree View Provider
 *
 * Implements the VS Code TreeDataProvider for visualizing the agent mesh
 * network topology including registered agents, trust scores, protocol
 * bridges, and delegation chains.
 */

import * as vscode from 'vscode';

import {
    AgentNode,
    AgentTopologyDataProvider,
    RING_LABELS,
    TopologyItem,
    truncateDid,
    trustIcon,
} from './topologyTypes';

// Re-exports for backward compatibility
export { AgentTopologyProvider };
export type { AgentNode, BridgeStatus, DelegationChain, AgentTopologyDataProvider } from './topologyTypes';
export { createMockTopologyProvider } from './topologyTypes';

// ---------------------------------------------------------------------------
// Tree data provider
// ---------------------------------------------------------------------------

class AgentTopologyProvider implements vscode.TreeDataProvider<TopologyItem>, vscode.Disposable {
    private _onDidChangeTreeData: vscode.EventEmitter<TopologyItem | undefined | null | void> =
        new vscode.EventEmitter<TopologyItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<TopologyItem | undefined | null | void> =
        this._onDidChangeTreeData.event;

    private refreshTimer: ReturnType<typeof setInterval>;

    constructor(private dataProvider: AgentTopologyDataProvider) {
        // Auto-refresh every 15 seconds.
        this.refreshTimer = setInterval(() => this.refresh(), 15_000);
    }

    /** Force a tree refresh. */
    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    /** Dispose the auto-refresh timer. */
    dispose(): void {
        clearInterval(this.refreshTimer);
        this._onDidChangeTreeData.dispose();
    }

    getTreeItem(element: TopologyItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: TopologyItem): Thenable<TopologyItem[]> {
        if (!element) {
            return Promise.resolve(this.getRootItems());
        }

        switch (element.kind) {
            case 'root-agents':
                return Promise.resolve(this.getAgentItems());
            case 'root-bridges':
                return Promise.resolve(this.getBridgeItems());
            case 'root-delegations':
                return Promise.resolve(this.getDelegationItems());
            case 'agent':
                if (element.data && typeof element.data === 'object' && 'did' in element.data) {
                    return Promise.resolve(this.getAgentDetails(element.data as AgentNode));
                }
                return Promise.resolve([]);
            default:
                return Promise.resolve([]);
        }
    }

    // -- Root level ----------------------------------------------------------

    private getRootItems(): TopologyItem[] {
        const agents = this.dataProvider.getAgents();
        const bridges = this.dataProvider.getBridges();
        const delegations = this.dataProvider.getDelegations();

        const agentsRoot = new TopologyItem(
            'Agents',
            vscode.TreeItemCollapsibleState.Expanded,
            'root-agents',
        );
        agentsRoot.description = `${agents.length} registered`;
        agentsRoot.iconPath = new vscode.ThemeIcon('organization');

        const bridgesRoot = new TopologyItem(
            'Trust Bridges',
            vscode.TreeItemCollapsibleState.Collapsed,
            'root-bridges',
        );
        bridgesRoot.description = `${bridges.length} protocols`;
        bridgesRoot.iconPath = new vscode.ThemeIcon('link');

        const delegationsRoot = new TopologyItem(
            'Delegation Chains',
            vscode.TreeItemCollapsibleState.Collapsed,
            'root-delegations',
        );
        delegationsRoot.description = `${delegations.length} active`;
        delegationsRoot.iconPath = new vscode.ThemeIcon('git-merge');

        return [agentsRoot, bridgesRoot, delegationsRoot];
    }

    // -- Agents --------------------------------------------------------------

    private getAgentItems(): TopologyItem[] {
        return this.dataProvider.getAgents().map((agent) => {
            const item = new TopologyItem(
                truncateDid(agent.did),
                vscode.TreeItemCollapsibleState.Collapsed,
                'agent',
                agent,
            );
            item.description = `Trust: ${agent.trustScore}/1000`;
            item.iconPath = trustIcon(agent.trustScore);
            item.tooltip = new vscode.MarkdownString(
                [
                    `**DID:** \`${agent.did}\``,
                    `**Trust Score:** ${agent.trustScore}/1000`,
                    `**Execution Ring:** ${RING_LABELS[agent.ring]}`,
                    `**Registered:** ${agent.registeredAt}`,
                    `**Last Activity:** ${agent.lastActivity}`,
                ].join('\n\n'),
            );
            return item;
        });
    }

    private getAgentDetails(agent: AgentNode): TopologyItem[] {
        const ringItem = new TopologyItem(
            RING_LABELS[agent.ring],
            vscode.TreeItemCollapsibleState.None,
            'agent-detail',
            'ring',
        );
        ringItem.iconPath = new vscode.ThemeIcon('shield');

        const activityItem = new TopologyItem(
            `Last Active: ${agent.lastActivity}`,
            vscode.TreeItemCollapsibleState.None,
            'agent-detail',
            'activity',
        );
        activityItem.iconPath = new vscode.ThemeIcon('clock');

        return [ringItem, activityItem, ...this.getCapabilityItems(agent.capabilities)];
    }

    private getCapabilityItems(capabilities: string[]): TopologyItem[] {
        if (capabilities.length === 0) {
            const noCap = new TopologyItem(
                'No delegated capabilities',
                vscode.TreeItemCollapsibleState.None,
                'agent-detail',
                'capability',
            );
            noCap.iconPath = new vscode.ThemeIcon(
                'circle-slash',
                new vscode.ThemeColor('disabledForeground'),
            );
            return [noCap];
        }

        return capabilities.map((cap) => {
            const capItem = new TopologyItem(
                cap,
                vscode.TreeItemCollapsibleState.None,
                'agent-detail',
                'capability',
            );
            capItem.iconPath = new vscode.ThemeIcon('key');
            return capItem;
        });
    }

    // -- Bridges -------------------------------------------------------------

    private getBridgeItems(): TopologyItem[] {
        return this.dataProvider.getBridges().map((bridge) => {
            const item = new TopologyItem(
                bridge.protocol,
                vscode.TreeItemCollapsibleState.None,
                'bridge',
                bridge,
            );

            if (bridge.connected) {
                const suffix = bridge.peerCount !== 1 ? 's' : '';
                item.description = `${bridge.peerCount} peer${suffix}`;
                item.iconPath = new vscode.ThemeIcon('plug', new vscode.ThemeColor('testing.iconPassed'));
            } else {
                item.description = 'disconnected';
                item.iconPath = new vscode.ThemeIcon('debug-disconnect', new vscode.ThemeColor('errorForeground'));
            }

            const status = bridge.connected ? 'connected' : 'disconnected';
            item.tooltip = `${bridge.protocol} bridge: ${status}, ${bridge.peerCount} peer(s)`;
            return item;
        });
    }

    // -- Delegations ---------------------------------------------------------

    private getDelegationItems(): TopologyItem[] {
        return this.dataProvider.getDelegations().map((del) => {
            const label = `${truncateDid(del.fromDid)} \u2192 ${truncateDid(del.toDid)}`;
            const item = new TopologyItem(
                label,
                vscode.TreeItemCollapsibleState.None,
                'delegation',
                del,
            );
            item.description = `capability: ${del.capability}, expires: ${del.expiresIn}`;
            item.iconPath = new vscode.ThemeIcon('arrow-right');
            item.tooltip = new vscode.MarkdownString(
                [
                    `**From:** \`${del.fromDid}\``,
                    `**To:** \`${del.toDid}\``,
                    `**Capability:** ${del.capability}`,
                    `**Expires In:** ${del.expiresIn}`,
                ].join('\n\n'),
            );
            return item;
        });
    }
}
