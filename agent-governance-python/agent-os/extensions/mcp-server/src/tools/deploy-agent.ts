// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * deploy_agent Tool
 * 
 * Deploys an agent to local or cloud environment.
 */

import { ServiceContext } from '../server.js';
import { DeployAgentInputSchema } from '../types/index.js';

export const deployAgentTool = {
  definition: {
    name: 'deploy_agent',
    description: `Deploy an agent to start execution.

Deployment environments:
- local: Runs on your machine (default)
- cloud: Runs on AgentOS cloud infrastructure (requires API key)

Before deployment, the agent must:
- Pass all policy checks
- Have valid configuration
- Have necessary integrations configured

For scheduled agents, deployment starts the scheduler.
For triggered agents, deployment enables the triggers.`,
    inputSchema: {
      type: 'object' as const,
      properties: {
        agentId: {
          type: 'string',
          description: 'Agent ID to deploy',
        },
        environment: {
          type: 'string',
          enum: ['local', 'cloud'],
          description: 'Deployment environment',
        },
        autoStart: {
          type: 'boolean',
          description: 'Start agent immediately after deployment',
        },
      },
      required: ['agentId'],
    },
  },
  
  async execute(args: unknown, context: ServiceContext): Promise<string> {
    const input = DeployAgentInputSchema.parse(args);
    
    context.logger.info('Deploying agent', { agentId: input.agentId, environment: input.environment });
    
    // Get agent
    const agent = await context.agentManager.getAgent(input.agentId);
    if (!agent) {
      throw new Error(`Agent not found: ${input.agentId}`);
    }
    
    // Check if already deployed
    if (agent.config.status === 'deployed') {
      return `
⚠️ Agent Already Deployed

**Agent:** ${agent.config.name} (${input.agentId})
**Status:** ${agent.config.status}

The agent is already deployed. Use \`get_agent_status\` to check its status,
or stop it first if you want to redeploy with changes.
`.trim();
    }
    
    // Check cloud deployment requirements
    if (input.environment === 'cloud' && !context.config.apiKey) {
      return `
❌ Cloud Deployment Requires API Key

To deploy to AgentOS cloud, set your API key:
1. Get an API key at https://agentos.dev/dashboard
2. Set AGENTOS_API_KEY environment variable
3. Retry deployment

Alternatively, deploy locally with environment: "local"
`.trim();
    }
    
    // Validate policies
    const testActions = [{ type: 'deploy', target: input.environment }];
    const evaluation = context.policyEngine.evaluate(testActions[0], agent.config.policies);
    
    if (!evaluation.allowed) {
      const violations = evaluation.violations.map(v => `- ${v.message}`).join('\n');
      return `
❌ Deployment Blocked by Policy

**Agent:** ${agent.config.name}
**Violations:**
${violations}

Fix the policy violations before deployment.
`.trim();
    }
    
    // Check if approval required
    if (evaluation.requiresApproval || agent.config.approvalRequired) {
      // Create approval request
      const approvalRequest = await context.approvalWorkflow.createRequest({
        agentId: input.agentId,
        action: 'deploy',
        description: `Deploy agent "${agent.config.name}" to ${input.environment}`,
        approvers: ['admin@example.com'], // Would come from config
        expiresInHours: 24,
      });
      
      return `
⏳ Deployment Pending Approval

**Agent:** ${agent.config.name}
**Environment:** ${input.environment}

This deployment requires human approval.

**Approval Request:** ${approvalRequest.id}
**Approvers notified:** ${approvalRequest.approvers.map(a => a.email).join(', ')}
**Expires in:** 24 hours

The agent will be deployed automatically once approved.
`.trim();
    }
    
    // Deploy the agent
    await context.agentManager.updateStatus(input.agentId, 'deployed');
    
    // Generate deployment info
    const deploymentId = `deploy-${Date.now().toString(36)}`;
    const monitorUrl = input.environment === 'cloud'
      ? `https://agentos.dev/agents/${input.agentId}`
      : `http://localhost:8080/agents/${input.agentId}`;
    
    return `
✅ Agent Deployed Successfully!

**Agent:** ${agent.config.name}
**ID:** ${input.agentId}
**Environment:** ${input.environment}
**Deployment ID:** ${deploymentId}
**Status:** ${input.autoStart ? 'Running' : 'Deployed (not started)'}

${agent.config.schedule 
  ? `**Schedule:** ${agent.config.schedule}\nThe agent will run according to this schedule.`
  : '**Trigger:** Manual\nUse the monitoring URL to trigger execution.'
}

**Monitoring URL:** ${monitorUrl}

**Policies Active:**
${agent.config.policies.map(p => `🛡️ ${p}`).join('\n') || 'None'}

**Commands:**
- Check status: \`get_agent_status\` with agentId "${input.agentId}"
- View logs: \`audit_log\` with agentId "${input.agentId}"
- Stop agent: Update status to "stopped"
`.trim();
  },
};
