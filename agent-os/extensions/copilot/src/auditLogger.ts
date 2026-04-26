// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Audit Logger for Agent OS Copilot Extension
 */

export interface AuditEntry {
    type: 'blocked' | 'warning' | 'allowed' | 'cmvk_review' | 'agent_created' | 'agent_deployed' | 'compliance_check';
    timestamp: Date;
    file?: string;
    language?: string;
    code?: string;
    violation?: string;
    reason?: string;
    result?: any;
    repository?: string;
    agent?: string;
    description?: string;
}

export class AuditLogger {
    private logs: AuditEntry[] = [];
    private maxLogs = 1000;

    log(entry: AuditEntry): void {
        this.logs.unshift(entry);
        if (this.logs.length > this.maxLogs) {
            this.logs = this.logs.slice(0, this.maxLogs);
        }
    }

    getAll(): AuditEntry[] {
        return [...this.logs];
    }

    getRecent(count: number = 10): AuditEntry[] {
        return this.logs.slice(0, count);
    }

    getByType(type: AuditEntry['type']): AuditEntry[] {
        return this.logs.filter(log => log.type === type);
    }

    getToday(): AuditEntry[] {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        return this.logs.filter(log => new Date(log.timestamp) >= today);
    }

    getThisWeek(): AuditEntry[] {
        const weekAgo = new Date();
        weekAgo.setDate(weekAgo.getDate() - 7);
        return this.logs.filter(log => new Date(log.timestamp) >= weekAgo);
    }

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

    clear(): void {
        this.logs = [];
    }
}
