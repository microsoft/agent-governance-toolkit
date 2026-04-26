// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * request_approval Tool
 * 
 * Creates an approval request for sensitive actions.
 */

import { ServiceContext } from '../server.js';
import { RequestApprovalInputSchema } from '../types/index.js';

export const requestApprovalTool = {
  definition: {
    name: 'request_approval',
    description: `Request human approval for a sensitive agent action.

Use this when:
- Policy requires human review before execution
- Agent attempts a high-risk action
- You want to add an extra safety check

Approval requests are sent to designated approvers via:
- Email notification
- Slack notification (if configured)
- Dashboard alert

Requests expire after the specified time (default: 24 hours).`,
    inputSchema: {
      type: 'object' as const,
      properties: {
        agentId: {
          type: 'string',
          description: 'Agent ID requesting approval',
        },
        action: {
          type: 'string',
          description: 'Action requiring approval (e.g., "delete_files", "send_email")',
        },
        description: {
          type: 'string',
          description: 'Detailed description of what will happen if approved',
        },
        approvers: {
          type: 'array',
          items: { type: 'string' },
          description: 'Email addresses of approvers',
        },
        expiresInHours: {
          type: 'number',
          description: 'Hours until approval expires (default: 24)',
        },
      },
      required: ['agentId', 'action', 'description', 'approvers'],
    },
  },
  
  async execute(args: unknown, context: ServiceContext): Promise<string> {
    const input = RequestApprovalInputSchema.parse(args);
    
    context.logger.info('Creating approval request', { 
      agentId: input.agentId, 
      action: input.action 
    });
    
    // Verify agent exists
    const agent = await context.agentManager.getAgent(input.agentId);
    if (!agent) {
      throw new Error(`Agent not found: ${input.agentId}`);
    }
    
    // Create approval request
    const request = await context.approvalWorkflow.createRequest(input);
    
    // Get risk level description
    const riskDescription: Record<string, string> = {
      low: 'Minor action with limited impact',
      medium: 'Action may have noticeable effects',
      high: 'Action could significantly affect data or systems',
      critical: 'Action is irreversible or affects critical systems',
    };
    
    return `
✅ Approval Request Created

**Request ID:** ${request.id}
**Agent:** ${agent.config.name} (${input.agentId})
**Action:** ${request.action}

**Description:**
${request.description}

**Risk Level:** ${request.riskLevel.toUpperCase()}
${riskDescription[request.riskLevel]}

**Approvers Notified:**
${request.approvers.map(a => `📧 ${a.email}`).join('\n')}

**Status:** ⏳ Pending
**Expires:** ${new Date(request.expiresAt).toLocaleString()}
**Required Approvals:** ${request.riskLevel === 'critical' ? '2+' : '1'}

**Approval Methods:**
- Email: Click approve/reject link in notification
- Dashboard: Visit https://agentos.dev/approvals/${request.id}
- CLI: Use approval management commands

The agent will automatically proceed once approval is granted.
`.trim();
  },
};
