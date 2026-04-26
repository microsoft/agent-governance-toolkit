// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Audit Logger Service
 * 
 * Maintains immutable audit trail of all agent actions for compliance.
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { AuditEntry, AuditLogInput } from '../types/index.js';

export interface AuditLogOptions {
  action: string;
  agentId: string;
  userId?: string;
  target?: string;
  policyCheck?: AuditEntry['policyCheck'];
  outcome: AuditEntry['outcome'];
  errorMessage?: string;
  metadata?: Record<string, unknown>;
}

export class AuditLogger {
  private dataDir: string;
  private auditDir: string;
  
  constructor(dataDir: string) {
    this.dataDir = dataDir;
    this.auditDir = path.join(dataDir, 'audit');
  }
  
  /**
   * Ensure data directory exists.
   */
  private async ensureDir(): Promise<void> {
    await fs.mkdir(this.auditDir, { recursive: true });
  }
  
  /**
   * Log an action to the audit trail.
   */
  async log(options: AuditLogOptions): Promise<AuditEntry> {
    await this.ensureDir();
    
    const entry: AuditEntry = {
      id: uuidv4(),
      timestamp: new Date().toISOString(),
      agentId: options.agentId,
      userId: options.userId,
      action: options.action,
      target: options.target,
      policyCheck: options.policyCheck,
      outcome: options.outcome,
      errorMessage: options.errorMessage,
      metadata: options.metadata,
    };
    
    // Write to date-partitioned log file for efficient querying
    const date = entry.timestamp.split('T')[0];
    const logFile = path.join(this.auditDir, `${date}.jsonl`);
    
    // Append to log file (JSONL format for efficiency)
    await fs.appendFile(logFile, JSON.stringify(entry) + '\n');
    
    return entry;
  }
  
  /**
   * Query audit log with filters.
   */
  async query(input: AuditLogInput): Promise<AuditEntry[]> {
    await this.ensureDir();
    
    const entries: AuditEntry[] = [];
    const startDate = input.startTime ? new Date(input.startTime) : new Date(0);
    const endDate = input.endTime ? new Date(input.endTime) : new Date();
    
    try {
      const files = await fs.readdir(this.auditDir);
      
      for (const file of files) {
        if (!file.endsWith('.jsonl')) continue;
        
        // Check if file date is in range
        const fileDate = file.replace('.jsonl', '');
        const date = new Date(fileDate);
        if (date < startDate || date > endDate) continue;
        
        const content = await fs.readFile(path.join(this.auditDir, file), 'utf-8');
        const lines = content.trim().split('\n').filter(l => l);
        
        for (const line of lines) {
          try {
            const entry = JSON.parse(line) as AuditEntry;
            
            // Apply filters
            if (entry.agentId !== input.agentId) continue;
            if (input.actionFilter && !entry.action.includes(input.actionFilter)) continue;
            
            const entryDate = new Date(entry.timestamp);
            if (entryDate < startDate || entryDate > endDate) continue;
            
            entries.push(entry);
            
            // Check limit
            if (entries.length >= input.limit) {
              return entries;
            }
          } catch {
            // Skip malformed entries
          }
        }
      }
    } catch {
      // Directory might not exist yet
    }
    
    // Sort by timestamp descending (most recent first)
    entries.sort((a, b) => 
      new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );
    
    return entries.slice(0, input.limit);
  }
  
  /**
   * Get recent logs across all agents.
   */
  async getRecentLogs(limit: number = 100): Promise<AuditEntry[]> {
    await this.ensureDir();
    
    const entries: AuditEntry[] = [];
    
    try {
      const files = await fs.readdir(this.auditDir);
      
      // Sort files by date descending
      const sortedFiles = files
        .filter(f => f.endsWith('.jsonl'))
        .sort((a, b) => b.localeCompare(a));
      
      for (const file of sortedFiles) {
        if (entries.length >= limit) break;
        
        const content = await fs.readFile(path.join(this.auditDir, file), 'utf-8');
        const lines = content.trim().split('\n').filter(l => l).reverse();
        
        for (const line of lines) {
          try {
            entries.push(JSON.parse(line) as AuditEntry);
            if (entries.length >= limit) break;
          } catch {
            // Skip malformed entries
          }
        }
      }
    } catch {
      // Directory might not exist yet
    }
    
    return entries;
  }
  
  /**
   * Get audit summary for an agent.
   */
  async getSummary(agentId: string, days: number = 30): Promise<{
    totalActions: number;
    successCount: number;
    failureCount: number;
    blockedCount: number;
    policyViolations: number;
    topActions: Array<{ action: string; count: number }>;
  }> {
    const startTime = new Date();
    startTime.setDate(startTime.getDate() - days);
    
    const entries = await this.query({
      agentId,
      startTime: startTime.toISOString(),
      limit: 10000, // High limit for summary
    });
    
    const actionCounts = new Map<string, number>();
    let successCount = 0;
    let failureCount = 0;
    let blockedCount = 0;
    let policyViolations = 0;
    
    for (const entry of entries) {
      // Count by outcome
      switch (entry.outcome) {
        case 'SUCCESS':
          successCount++;
          break;
        case 'FAILURE':
          failureCount++;
          break;
        case 'BLOCKED':
          blockedCount++;
          break;
      }
      
      // Count policy violations
      if (entry.policyCheck?.violations?.length) {
        policyViolations += entry.policyCheck.violations.length;
      }
      
      // Count actions
      const count = actionCounts.get(entry.action) || 0;
      actionCounts.set(entry.action, count + 1);
    }
    
    // Get top actions
    const topActions = Array.from(actionCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([action, count]) => ({ action, count }));
    
    return {
      totalActions: entries.length,
      successCount,
      failureCount,
      blockedCount,
      policyViolations,
      topActions,
    };
  }
  
  /**
   * Export audit log for compliance reporting.
   */
  async exportForCompliance(
    agentId: string,
    startTime: string,
    endTime: string,
    format: 'json' | 'csv' = 'json'
  ): Promise<string> {
    const entries = await this.query({
      agentId,
      startTime,
      endTime,
      limit: 100000,
    });
    
    if (format === 'json') {
      return JSON.stringify(entries, null, 2);
    }
    
    // CSV format
    const headers = [
      'id',
      'timestamp',
      'agentId',
      'userId',
      'action',
      'target',
      'outcome',
      'policyResult',
      'errorMessage',
    ];
    
    const rows = entries.map(e => [
      e.id,
      e.timestamp,
      e.agentId,
      e.userId || '',
      e.action,
      e.target || '',
      e.outcome,
      e.policyCheck?.result || '',
      e.errorMessage || '',
    ]);
    
    return [
      headers.join(','),
      ...rows.map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')),
    ].join('\n');
  }
}
