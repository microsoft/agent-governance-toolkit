// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Stats Tree View Provider
 * 
 * Displays safety statistics in the sidebar.
 */

import * as vscode from 'vscode';
import { AuditLogger } from '../auditLogger';

export class StatsProvider implements vscode.TreeDataProvider<StatsItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<StatsItem | undefined | null | void> = new vscode.EventEmitter<StatsItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<StatsItem | undefined | null | void> = this._onDidChangeTreeData.event;

    constructor(private auditLogger: AuditLogger) {
        // Refresh periodically
        setInterval(() => this.refresh(), 60000);
    }

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element: StatsItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: StatsItem): Thenable<StatsItem[]> {
        if (!element) {
            const stats = this.auditLogger.getStats();
            return Promise.resolve([
                new StatsItem('Blocked Today', stats.blockedToday.toString(), 'error'),
                new StatsItem('Blocked This Week', stats.blockedThisWeek.toString(), 'warning'),
                new StatsItem('Warnings Today', stats.warningsToday.toString(), 'info'),
                new StatsItem('CMVK Reviews', stats.cmvkReviewsToday.toString(), 'success'),
                new StatsItem('Total Logged', stats.totalLogs.toString(), 'default')
            ]);
        }
        return Promise.resolve([]);
    }
}

class StatsItem extends vscode.TreeItem {
    constructor(
        public readonly label: string,
        public readonly value: string,
        public readonly type: 'error' | 'warning' | 'info' | 'success' | 'default'
    ) {
        super(label, vscode.TreeItemCollapsibleState.None);
        this.description = value;
        this.tooltip = `${label}: ${value}`;
        this.iconPath = this.getIcon(type);
        this.accessibilityInformation = {
            label: `${label}: ${value}`,
            role: 'treeitem'
        };
    }

    private getIcon(type: string): vscode.ThemeIcon {
        switch (type) {
            case 'error':
                return new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
            case 'warning':
                return new vscode.ThemeIcon('warning', new vscode.ThemeColor('list.warningForeground'));
            case 'info':
                return new vscode.ThemeIcon('info', new vscode.ThemeColor('editorInfo.foreground'));
            case 'success':
                return new vscode.ThemeIcon('check', new vscode.ThemeColor('testing.iconPassed'));
            default:
                return new vscode.ThemeIcon('graph');
        }
    }
}
