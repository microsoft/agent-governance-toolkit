// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Audit Logger for Agent OS VS Code Extension
 * 
 * Logs all policy enforcement actions, blocked code, and CMVK reviews.
 */

import * as vscode from 'vscode';

export interface AuditEntry {
    type: 'blocked' | 'warning' | 'allowed' | 'cmvk_review';
    timestamp: Date;
    file?: string;
    language?: string;
    code?: string;
    violation?: string;
    reason?: string;
    result?: any;
}

export class AuditLogger {
    private logs: AuditEntry[] = [];
    private storageKey = 'agent-os.auditLogs';
    private context: vscode.ExtensionContext;
    private maxLogs = 1000;

    constructor(context: vscode.ExtensionContext) {
        this.context = context;
        this.loadLogs();
        this.cleanOldLogs();
    }

    /**
     * Log an audit entry
     */
    log(entry: AuditEntry): void {
        this.logs.unshift(entry);

        // Trim to max size
        if (this.logs.length > this.maxLogs) {
            this.logs = this.logs.slice(0, this.maxLogs);
        }

        this.saveLogs();
    }

    /**
     * Get all logs
     */
    getAll(): AuditEntry[] {
        return [...this.logs];
    }

    /**
     * Get recent logs (last N entries)
     */
    getRecent(count: number = 10): AuditEntry[] {
        return this.logs.slice(0, count);
    }

    /**
     * Get logs by type
     */
    getByType(type: AuditEntry['type']): AuditEntry[] {
        return this.logs.filter(log => log.type === type);
    }

    /**
     * Get logs for today
     */
    getToday(): AuditEntry[] {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        return this.logs.filter(log => new Date(log.timestamp) >= today);
    }

    /**
     * Get logs for this week
     */
    getThisWeek(): AuditEntry[] {
        const weekAgo = new Date();
        weekAgo.setDate(weekAgo.getDate() - 7);
        
        return this.logs.filter(log => new Date(log.timestamp) >= weekAgo);
    }

    /**
     * Get statistics
     */
    getStats(): {
        blockedToday: number;
        blockedThisWeek: number;
        warningsToday: number;
        cmvkReviewsToday: number;
        totalLogs: number;
    } {
        const todayLogs = this.getToday();
        const weekLogs = this.getThisWeek();

        return {
            blockedToday: todayLogs.filter(l => l.type === 'blocked').length,
            blockedThisWeek: weekLogs.filter(l => l.type === 'blocked').length,
            warningsToday: todayLogs.filter(l => l.type === 'warning').length,
            cmvkReviewsToday: todayLogs.filter(l => l.type === 'cmvk_review').length,
            totalLogs: this.logs.length
        };
    }

    /**
     * Clear all logs
     */
    clear(): void {
        this.logs = [];
        this.saveLogs();
    }

    /**
     * Load logs from storage
     */
    private loadLogs(): void {
        const stored = this.context.globalState.get<AuditEntry[]>(this.storageKey, []);
        this.logs = stored.map(log => ({
            ...log,
            timestamp: new Date(log.timestamp)
        }));
    }

    /**
     * Save logs to storage
     */
    private saveLogs(): void {
        this.context.globalState.update(this.storageKey, this.logs);
    }

    /**
     * Clean logs older than retention period
     */
    private cleanOldLogs(): void {
        const config = vscode.workspace.getConfiguration('agentOS');
        const retentionDays = config.get<number>('audit.retentionDays', 7);
        
        const cutoff = new Date();
        cutoff.setDate(cutoff.getDate() - retentionDays);

        const originalCount = this.logs.length;
        this.logs = this.logs.filter(log => new Date(log.timestamp) >= cutoff);

        if (this.logs.length !== originalCount) {
            this.saveLogs();
        }
    }
}
