// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * audit_log Tool
 * 
 * Queries the audit trail for agent actions.
 */

import { ServiceContext } from '../server.js';
import { AuditLogInputSchema } from '../types/index.js';

export const auditLogTool = {
  definition: {
    name: 'audit_log',
    description: `Query the audit trail for an agent.

The audit log records:
- Every action attempted by the agent
- Policy evaluations and decisions
- Approval requests and outcomes
- Success/failure status
- Timestamps and metadata

Use for:
- Debugging agent behavior
- Compliance reporting
- Security investigations
- Performance analysis`,
    inputSchema: {
      type: 'object' as const,
      properties: {
        agentId: {
          type: 'string',
          description: 'Agent ID to get audit log for',
        },
        startTime: {
          type: 'string',
          description: 'Start of time range (ISO 8601)',
        },
        endTime: {
          type: 'string',
          description: 'End of time range (ISO 8601)',
        },
        actionFilter: {
          type: 'string',
          description: 'Filter by action type',
        },
        limit: {
          type: 'number',
          description: 'Maximum entries to return (default: 100)',
        },
      },
      required: ['agentId'],
    },
  },
  
  async execute(args: unknown, context: ServiceContext): Promise<string> {
    const input = AuditLogInputSchema.parse(args);
    
    context.logger.info('Querying audit log', { agentId: input.agentId });
    
    // Verify agent exists
    const agent = await context.agentManager.getAgent(input.agentId);
    if (!agent) {
      throw new Error(`Agent not found: ${input.agentId}`);
    }
    
    // Query audit log
    const entries = await context.auditLogger.query(input);
    
    // Get summary
    const summary = await context.auditLogger.getSummary(input.agentId, 30);
    
    if (entries.length === 0) {
      return `
**Audit Log: ${agent.config.name}**

No audit entries found for the specified criteria.

**Filters Applied:**
- Agent: ${input.agentId}
${input.startTime ? `- Start: ${input.startTime}` : ''}
${input.endTime ? `- End: ${input.endTime}` : ''}
${input.actionFilter ? `- Action: ${input.actionFilter}` : ''}

This agent may not have executed any actions yet, or the filter criteria
are too restrictive. Try:
- Removing time filters
- Removing action filter
- Checking agent status
`.trim();
    }
    
    // Format entries
    const outcomeEmoji: Record<string, string> = {
      SUCCESS: '✅',
      FAILURE: '❌',
      BLOCKED: '🚫',
      PENDING: '⏳',
    };
    
    const entriesFormatted = entries.slice(0, 20).map(entry => {
      const time = new Date(entry.timestamp).toLocaleString();
      const emoji = outcomeEmoji[entry.outcome] || '❓';
      const policyResult = entry.policyCheck?.result 
        ? ` [Policy: ${entry.policyCheck.result}]` 
        : '';
      
      return `${emoji} [${time}] ${entry.action}${policyResult}`;
    }).join('\n');
    
    return `
**Audit Log: ${agent.config.name}**

**Summary (Last 30 Days):**
- Total Actions: ${summary.totalActions}
- Successful: ${summary.successCount}
- Failed: ${summary.failureCount}
- Blocked by Policy: ${summary.blockedCount}
- Policy Violations: ${summary.policyViolations}

**Recent Entries (${entries.length} found, showing ${Math.min(entries.length, 20)}):**

${entriesFormatted}

${entries.length > 20 ? `\n... and ${entries.length - 20} more entries\n` : ''}

**Top Actions:**
${summary.topActions.slice(0, 5).map(a => `- ${a.action}: ${a.count}`).join('\n') || 'No actions recorded'}

**Export Options:**
To export for compliance, use the audit export API endpoint or
contact support for bulk export options.
`.trim();
  },
};
