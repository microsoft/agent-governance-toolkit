// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * create_agent Tool
 * 
 * Creates a new agent from natural language description.
 */

import { ServiceContext } from '../server.js';
import { CreateAgentInputSchema } from '../types/index.js';

export const createAgentTool = {
  definition: {
    name: 'create_agent',
    description: `Create a new AI agent from a natural language description. The agent will be configured with appropriate policies and safety guardrails.

Example usage:
- "Create an agent that processes customer feedback from support emails daily"
- "Build a data pipeline that backs up my Documents folder to Google Drive"
- "Set up an agent to monitor our API health and alert on issues"

Returns the agent specification with recommended safety policies.`,
    inputSchema: {
      type: 'object' as const,
      properties: {
        description: {
          type: 'string',
          description: 'Natural language description of what the agent should do',
        },
        policies: {
          type: 'array',
          items: { type: 'string' },
          description: 'Policy templates to apply (e.g., "pii-protection", "rate-limiting")',
        },
        approvalRequired: {
          type: 'boolean',
          description: 'Whether human approval is required before execution',
        },
        language: {
          type: 'string',
          enum: ['python', 'typescript', 'javascript', 'go'],
          description: 'Programming language for the agent',
        },
        schedule: {
          type: 'string',
          description: 'Cron schedule for recurring execution (e.g., "0 9 * * *" for daily at 9 AM)',
        },
      },
      required: ['description'],
    },
  },
  
  async execute(args: unknown, context: ServiceContext): Promise<string> {
    const input = CreateAgentInputSchema.parse(args);
    
    context.logger.info('Creating agent', { description: input.description });
    
    // Get template suggestions based on description
    const suggestions = context.templateLibrary.suggestTemplates(input.description);
    
    // Auto-suggest policies if not provided
    if (!input.policies?.length && suggestions.policies.length) {
      input.policies = suggestions.policies.map(p => p.id);
      context.logger.info('Auto-suggested policies', { policies: input.policies });
    }
    
    // Create the agent
    const spec = await context.agentManager.createAgent(input);
    
    // Format response for Claude
    const policySummary = spec.config.policies.length
      ? spec.config.policies.map(p => {
          const policy = context.policyEngine.getPolicy(p);
          return `🛡️ ${policy?.name || p}: ${policy?.description || 'Custom policy'}`;
        }).join('\n')
      : '⚠️  No policies attached yet';
    
    const workflowSummary = spec.workflow?.steps.map((s, i) =>
      `${i + 1}. ${s.name}: ${s.action}`
    ).join('\n') || 'No workflow defined';
    
    return `
✅ Agent Created Successfully!

**Agent: ${spec.config.name}**
ID: ${spec.config.id}
Status: ${spec.config.status}
Language: ${spec.config.language}
${spec.config.schedule ? `Schedule: ${spec.config.schedule}` : ''}
${spec.config.approvalRequired ? '⚠️  Human approval required before execution' : ''}

**Task:**
${spec.config.task}

**Workflow Steps:**
${workflowSummary}

**Safety Policies Applied:**
${policySummary}

**Suggested Templates:**
${suggestions.agents.length ? suggestions.agents.map(t => `- ${t.name}: ${t.description}`).join('\n') : 'None'}

**Next Steps:**
1. Use \`test_agent\` to run a dry-run test
2. Use \`attach_policy\` to add more safety policies
3. Use \`deploy_agent\` when ready to run
`.trim();
  },
};
