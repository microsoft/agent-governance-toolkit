// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * create_policy Tool
 * 
 * Creates a custom policy from natural language description.
 */

import { ServiceContext } from '../server.js';
import { CreatePolicyInputSchema } from '../types/index.js';

export const createPolicyTool = {
  definition: {
    name: 'create_policy',
    description: `Create a custom policy from a natural language description.

Policies define rules that agents must follow. Example policies:
- "Block access to customer credit card data"
- "Require approval for any external API calls"
- "Rate limit database queries to 100 per minute"
- "Log all file deletions"

Policies can be based on existing templates:
- pii-protection, rate-limiting, cost-control
- gdpr-compliance, soc2-security, hipaa-healthcare

The policy engine will translate your description into enforceable rules.`,
    inputSchema: {
      type: 'object' as const,
      properties: {
        description: {
          type: 'string',
          description: 'Natural language policy description',
        },
        category: {
          type: 'string',
          enum: ['security', 'privacy', 'compliance', 'operational', 'governance', 'custom'],
          description: 'Policy category',
        },
        framework: {
          type: 'string',
          description: 'Compliance framework (e.g., "SOC2", "GDPR", "HIPAA")',
        },
        basedOn: {
          type: 'string',
          description: 'Policy template to extend',
        },
      },
      required: ['description', 'category'],
    },
  },
  
  async execute(args: unknown, context: ServiceContext): Promise<string> {
    const input = CreatePolicyInputSchema.parse(args);
    
    context.logger.info('Creating custom policy', { description: input.description });
    
    // Check if based on existing policy
    let basePolicy = null;
    if (input.basedOn) {
      basePolicy = context.policyEngine.getPolicy(input.basedOn);
      if (!basePolicy) {
        const available = context.policyEngine.getAllPolicies().map(p => p.id);
        throw new Error(
          `Base policy not found: ${input.basedOn}\n\nAvailable policies:\n${available.join('\n')}`
        );
      }
    }
    
    // Create the policy
    const policy = context.policyEngine.createPolicy(input);
    
    // Format response
    const severityColors: Record<string, string> = {
      info: '🔵',
      warning: '🟡',
      high: '🟠',
      critical: '🔴',
    };
    
    const rulesFormatted = policy.rules.map(r => {
      const emoji = severityColors[r.severity] || '⚪';
      return `${emoji} **${r.name}** [${r.severity}]\n   ${r.description || r.message || 'No description'}\n   Action: ${r.action}`;
    }).join('\n\n');
    
    return `
✅ Custom Policy Created

**Policy:** ${policy.name}
**ID:** ${policy.id}
**Category:** ${policy.category}
${policy.framework ? `**Framework:** ${policy.framework}` : ''}
${basePolicy ? `**Based On:** ${basePolicy.name}` : ''}

**Description:**
${policy.description}

**Rules Generated (${policy.rules.length}):**

${rulesFormatted}

**Usage:**
1. Attach to agent: \`attach_policy\` with policyId "${policy.id}"
2. Test enforcement: \`test_agent\` with policy scenarios
3. View active policies: \`get_agent_status\`

**Note:** Custom policies are stored locally. For organization-wide
policies, consider using the AgentOS cloud dashboard.
`.trim();
  },
};
