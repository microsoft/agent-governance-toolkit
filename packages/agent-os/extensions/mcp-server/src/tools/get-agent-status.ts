// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * get_agent_status Tool
 * 
 * Gets the current status and metrics for an agent.
 */

import { ServiceContext } from '../server.js';
import { GetAgentStatusInputSchema } from '../types/index.js';

export const getAgentStatusTool = {
  definition: {
    name: 'get_agent_status',
    description: `Get the current status, metrics, and health of an agent.

Returns:
- Current status (draft, testing, deployed, paused, stopped, error)
- Execution metrics (runs, success rate, errors)
- Recent activity
- Policy compliance stats
- Resource usage`,
    inputSchema: {
      type: 'object' as const,
      properties: {
        agentId: {
          type: 'string',
          description: 'Agent ID to get status for',
        },
        includeMetrics: {
          type: 'boolean',
          description: 'Include execution metrics',
        },
        includeLogs: {
          type: 'boolean',
          description: 'Include recent logs',
        },
      },
      required: ['agentId'],
    },
  },
  
  async execute(args: unknown, context: ServiceContext): Promise<string> {
    const input = GetAgentStatusInputSchema.parse(args);
    
    context.logger.info('Getting agent status', { agentId: input.agentId });
    
    // Get agent
    const agent = await context.agentManager.getAgent(input.agentId);
    if (!agent) {
      throw new Error(`Agent not found: ${input.agentId}`);
    }
    
    // Get audit summary for metrics
    const auditSummary = input.includeMetrics 
      ? await context.auditLogger.getSummary(input.agentId, 30)
      : null;
    
    // Get recent logs if requested
    const recentLogs = input.includeLogs
      ? await context.auditLogger.query({
          agentId: input.agentId,
          limit: 10,
        })
      : [];
    
    // Get pending approvals
    const pendingApprovals = await context.approvalWorkflow.getPendingRequests(input.agentId);
    
    // Format status
    const statusEmoji: Record<string, string> = {
      draft: '📝',
      testing: '🧪',
      deployed: '✅',
      paused: '⏸️',
      stopped: '⏹️',
      error: '❌',
    };
    
    let output = `
**Agent Status Report**

**${statusEmoji[agent.config.status] || '❓'} ${agent.config.name}**
ID: ${agent.config.id}
Status: ${agent.config.status.toUpperCase()}
Language: ${agent.config.language}
Created: ${new Date(agent.config.createdAt).toLocaleDateString()}
Updated: ${new Date(agent.config.updatedAt).toLocaleDateString()}

**Task:**
${agent.config.task}
`.trim();
    
    // Add schedule info
    if (agent.config.schedule) {
      output += `\n\n**Schedule:** ${agent.config.schedule}`;
    }
    
    // Add policies
    output += `\n\n**Active Policies (${agent.config.policies.length}):**\n`;
    if (agent.config.policies.length) {
      output += agent.config.policies.map(p => {
        const policy = context.policyEngine.getPolicy(p);
        return `🛡️ ${policy?.name || p}`;
      }).join('\n');
    } else {
      output += '⚠️  No policies attached';
    }
    
    // Add metrics
    if (auditSummary) {
      const successRate = auditSummary.totalActions > 0
        ? Math.round((auditSummary.successCount / auditSummary.totalActions) * 100)
        : 0;
      
      output += `

**Metrics (Last 30 Days):**
- Total Actions: ${auditSummary.totalActions}
- Success Rate: ${successRate}%
- Failures: ${auditSummary.failureCount}
- Blocked: ${auditSummary.blockedCount}
- Policy Violations: ${auditSummary.policyViolations}

**Top Actions:**
${auditSummary.topActions.slice(0, 5).map(a => `- ${a.action}: ${a.count} times`).join('\n') || 'No activity'}`;
    }
    
    // Add pending approvals
    if (pendingApprovals.length) {
      output += `

**Pending Approvals (${pendingApprovals.length}):**
${pendingApprovals.map(a => 
  `⏳ ${a.action} - ${a.description} (expires: ${new Date(a.expiresAt).toLocaleString()})`
).join('\n')}`;
    }
    
    // Add recent logs
    if (recentLogs.length) {
      output += `

**Recent Activity:**
${recentLogs.map(l => {
  const emoji = l.outcome === 'SUCCESS' ? '✅' : l.outcome === 'FAILURE' ? '❌' : '⚠️';
  const time = new Date(l.timestamp).toLocaleTimeString();
  return `${emoji} [${time}] ${l.action}`;
}).join('\n')}`;
    }
    
    return output;
  },
};
