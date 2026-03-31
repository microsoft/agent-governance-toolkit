// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Policies Tree View Provider
 * 
 * Displays active policies in the sidebar.
 */

import * as vscode from 'vscode';
import { PolicyEngine } from '../policyEngine';

export class PoliciesProvider implements vscode.TreeDataProvider<PolicyItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<PolicyItem | undefined | null | void> = new vscode.EventEmitter<PolicyItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<PolicyItem | undefined | null | void> = this._onDidChangeTreeData.event;

    constructor(private policyEngine: PolicyEngine) {}

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element: PolicyItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: PolicyItem): Thenable<PolicyItem[]> {
        if (!element) {
            const policies = this.policyEngine.getActivePolicies();
            return Promise.resolve(policies.map(p => new PolicyItem(p.name, p.enabled, p.severity)));
        }
        return Promise.resolve([]);
    }
}

class PolicyItem extends vscode.TreeItem {
    constructor(
        public readonly name: string,
        public readonly enabled: boolean,
        public readonly severity: string
    ) {
        super(name, vscode.TreeItemCollapsibleState.None);

        this.description = enabled ? `${severity}` : 'disabled';
        this.tooltip = `${name}\nSeverity: ${severity}\nStatus: ${enabled ? 'Enabled' : 'Disabled'}`;
        this.accessibilityInformation = {
            label: `${name}. Severity ${severity}. ${enabled ? 'Enabled' : 'Disabled'}.`,
            role: 'treeitem'
        };
        
        if (enabled) {
            this.iconPath = this.getSeverityIcon(severity);
        } else {
            this.iconPath = new vscode.ThemeIcon('circle-slash', new vscode.ThemeColor('disabledForeground'));
        }

        this.command = {
            command: 'workbench.action.openSettings',
            title: 'Configure',
            arguments: [`agentOS.policies`]
        };
    }

    private getSeverityIcon(severity: string): vscode.ThemeIcon {
        switch (severity) {
            case 'critical':
                return new vscode.ThemeIcon('shield', new vscode.ThemeColor('errorForeground'));
            case 'high':
                return new vscode.ThemeIcon('shield', new vscode.ThemeColor('list.warningForeground'));
            case 'medium':
                return new vscode.ThemeIcon('shield', new vscode.ThemeColor('editorInfo.foreground'));
            default:
                return new vscode.ThemeIcon('shield');
        }
    }
}
