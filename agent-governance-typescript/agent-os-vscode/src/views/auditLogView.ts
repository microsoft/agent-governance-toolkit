// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Audit Log Tree View Provider
 * 
 * Displays audit log entries in the sidebar.
 */

import * as vscode from 'vscode';
import { AuditLogger, AuditEntry } from '../auditLogger';

export class AuditLogProvider implements vscode.TreeDataProvider<AuditLogItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<AuditLogItem | undefined | null | void> = new vscode.EventEmitter<AuditLogItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<AuditLogItem | undefined | null | void> = this._onDidChangeTreeData.event;

    constructor(private auditLogger: AuditLogger) {
        // Refresh periodically
        setInterval(() => this.refresh(), 30000);
    }

    refresh(): void {
        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element: AuditLogItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: AuditLogItem): Thenable<AuditLogItem[]> {
        if (!element) {
            // Root level - show recent entries
            const logs = this.auditLogger.getRecent(20);
            return Promise.resolve(logs.map(log => new AuditLogItem(log)));
        }
        return Promise.resolve([]);
    }
}

class AuditLogItem extends vscode.TreeItem {
    constructor(private entry: AuditEntry) {
        const label = AuditLogItem.formatLabel(entry);
        super(label, vscode.TreeItemCollapsibleState.None);

        this.tooltip = AuditLogItem.formatTooltip(entry);
        this.description = AuditLogItem.formatTime(entry.timestamp);
        this.iconPath = AuditLogItem.getIcon(entry.type);
        this.accessibilityInformation = {
            label: AuditLogItem.formatAccessibilityLabel(entry),
            role: 'treeitem'
        };
        
        if (entry.file) {
            this.command = {
                command: 'vscode.open',
                title: 'Open File',
                arguments: [vscode.Uri.file(entry.file)]
            };
        }
    }

    private static formatLabel(entry: AuditEntry): string {
        switch (entry.type) {
            case 'blocked':
                return `Blocked: ${entry.violation || 'Unknown'}`;
            case 'warning':
                return `Warning: ${entry.reason || 'Unknown'}`;
            case 'cmvk_review':
                return `CMVK Review: ${(entry.result?.consensus * 100).toFixed(0)}% consensus`;
            case 'allowed':
                return `Allowed: ${entry.violation || 'Unknown'}`;
            default:
                return entry.type;
        }
    }

    private static formatTooltip(entry: AuditEntry): string {
        let tooltip = `Type: ${entry.type}\n`;
        tooltip += `Time: ${entry.timestamp.toLocaleString()}\n`;
        if (entry.file) {
            tooltip += `File: ${entry.file}\n`;
        }
        if (entry.language) {
            tooltip += `Language: ${entry.language}\n`;
        }
        if (entry.reason) {
            tooltip += `Reason: ${entry.reason}\n`;
        }
        if (entry.code) {
            tooltip += `\nCode:\n${entry.code.substring(0, 100)}...`;
        }
        return tooltip;
    }

    private static formatTime(timestamp: Date): string {
        const now = new Date();
        const diff = now.getTime() - timestamp.getTime();
        const minutes = Math.floor(diff / 60000);
        const hours = Math.floor(diff / 3600000);
        const days = Math.floor(diff / 86400000);

        if (minutes < 1) {
            return 'just now';
        }
        if (minutes < 60) {
            return `${minutes}m ago`;
        }
        if (hours < 24) {
            return `${hours}h ago`;
        }
        return `${days}d ago`;
    }

    private static formatAccessibilityLabel(entry: AuditEntry): string {
        const parts = [AuditLogItem.formatLabel(entry)];
        parts.push(`Recorded ${entry.timestamp.toLocaleString()}`);
        if (entry.file) {
            parts.push(`File ${entry.file}`);
        }
        if (entry.reason) {
            parts.push(`Reason ${entry.reason}`);
        }
        return parts.join('. ');
    }

    private static getIcon(type: AuditEntry['type']): vscode.ThemeIcon {
        switch (type) {
            case 'blocked':
                return new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
            case 'warning':
                return new vscode.ThemeIcon('warning', new vscode.ThemeColor('list.warningForeground'));
            case 'cmvk_review':
                return new vscode.ThemeIcon('beaker');
            case 'allowed':
                return new vscode.ThemeIcon('check', new vscode.ThemeColor('testing.iconPassed'));
            default:
                return new vscode.ThemeIcon('info');
        }
    }
}
