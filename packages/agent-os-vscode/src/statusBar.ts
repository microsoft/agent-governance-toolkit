// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Status Bar Manager for Agent OS VS Code Extension
 * 
 * Shows current safety status in the VS Code status bar.
 */

import * as vscode from 'vscode';

export class StatusBarManager implements vscode.Disposable {
    private statusBarItem: vscode.StatusBarItem;
    private blockedCount: number = 0;

    constructor() {
        this.statusBarItem = vscode.window.createStatusBarItem(
            vscode.StatusBarAlignment.Right,
            100
        );
        this.statusBarItem.command = 'agent-os.showAuditLog';
        this.statusBarItem.show();
    }

    /**
     * Update status bar based on enabled state
     */
    update(enabled: boolean): void {
        if (enabled) {
            this.statusBarItem.text = `$(shield) Agent OS: Active`;
            this.statusBarItem.tooltip = `Agent OS Safety Active\n${this.blockedCount} blocked today\nClick to view audit log`;
            this.statusBarItem.backgroundColor = undefined;
        } else {
            this.statusBarItem.text = `$(shield) Agent OS: Disabled`;
            this.statusBarItem.tooltip = 'Agent OS Safety Disabled\nClick to enable';
            this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
        }
    }

    /**
     * Increment blocked count and update display
     */
    incrementBlocked(): void {
        this.blockedCount++;
        const config = vscode.workspace.getConfiguration('agentOS');
        if (config.get<boolean>('enabled', true)) {
            this.statusBarItem.text = `$(shield) Agent OS: ${this.blockedCount} blocked`;
            this.statusBarItem.tooltip = `Agent OS Safety Active\n${this.blockedCount} blocked today\nClick to view audit log`;
        }
    }

    /**
     * Reset blocked count (called at start of day)
     */
    resetCount(): void {
        this.blockedCount = 0;
        this.update(true);
    }

    /**
     * Show temporary warning state
     */
    showWarning(message: string): void {
        const originalText = this.statusBarItem.text;
        this.statusBarItem.text = `$(warning) ${message}`;
        this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');

        setTimeout(() => {
            this.update(vscode.workspace.getConfiguration('agentOS').get<boolean>('enabled', true));
        }, 3000);
    }

    dispose(): void {
        this.statusBarItem.dispose();
    }
}
