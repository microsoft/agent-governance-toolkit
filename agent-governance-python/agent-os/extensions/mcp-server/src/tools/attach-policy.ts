// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * attach_policy Tool
 * 
 * Attaches policy templates to an agent.
 */

import { ServiceContext } from '../server.js';
import { AttachPolicyInputSchema } from '../types/index.js';

export const attachPolicyTool = {
  definition: {
    name: 'attach_policy',
    description: `Attach safety policies to an agent. Policies enforce rules and constraints on agent behavior.

Available policy templates:
- pii-protection: Protects personally identifiable information (GDPR compliant)
- rate-limiting: Prevents resource abuse through rate limits
- cost-control: Prevents runaway costs from automated operations
- data-deletion: Prevents accidental data loss
- secrets-protection: Prevents exposure of secrets and credentials
- human-review: Requires human approval for sensitive actions

Compliance frameworks:
- gdpr-compliance: EU data protection compliance
- soc2-security: SOC 2 Type II security controls
- hipaa-healthcare: Healthcare data privacy (PHI protection)
- pci-dss-payments: Payment card data security`,
    inputSchema: {
      type: 'object' as const,
      properties: {
        agentId: {
          type: 'string',
          description: 'Agent ID to attach policy to',
        },
        policyId: {
          type: 'string',
          description: 'Policy template ID (e.g., "pii-protection", "gdpr-compliance")',
        },
        customRules: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              name: { type: 'string' },
              condition: { type: 'string' },
              action: { type: 'string', enum: ['allow', 'deny', 'require_approval', 'log'] },
              severity: { type: 'string', enum: ['info', 'warning', 'high', 'critical'] },
              message: { type: 'string' },
            },
          },
          description: 'Additional custom rules to add',
        },
      },
      required: ['agentId', 'policyId'],
    },
  },
  
  async execute(args: unknown, context: ServiceContext): Promise<string> {
    const input = AttachPolicyInputSchema.parse(args);
    
    context.logger.info('Attaching policy', { agentId: input.agentId, policyId: input.policyId });
    
    // Verify agent exists
    const agent = await context.agentManager.getAgent(input.agentId);
    if (!agent) {
      throw new Error(`Agent not found: ${input.agentId}`);
    }
    
    // Verify policy exists
    const policy = context.policyEngine.getPolicy(input.policyId);
    const template = context.templateLibrary.getPolicyTemplate(input.policyId);
    
    if (!policy && !template) {
      // List available policies
      const available = context.policyEngine.getAllPolicies().map(p => p.id);
      throw new Error(
        `Policy not found: ${input.policyId}\n\nAvailable policies:\n${available.join('\n')}`
      );
    }
    
    // Check for conflicts
    const allPolicies = [...agent.config.policies, input.policyId];
    const validation = context.policyEngine.validatePolicyCombination(allPolicies);
    
    if (!validation.valid) {
      return `
⚠️ Policy Conflict Detected

Cannot attach "${input.policyId}" due to conflicts:
${validation.conflicts.join('\n')}

Current policies: ${agent.config.policies.join(', ') || 'None'}

Consider removing conflicting policies first.
`.trim();
    }
    
    // Attach the policy
    const updated = await context.agentManager.attachPolicies(input.agentId, [input.policyId]);
    
    // Get policy details for display
    const policyInfo = policy || template?.policy;
    const rules = policyInfo?.rules || [];
    
    return `
✅ Policy Attached Successfully!

**Agent:** ${agent.config.name} (${input.agentId})

**Policy Added:** ${policyInfo?.name || input.policyId}
${policyInfo?.description || ''}
${policyInfo?.framework ? `Framework: ${policyInfo.framework}` : ''}

**Rules Enforced (${rules.length}):**
${rules.slice(0, 5).map(r => 
  `- ${r.name} [${r.severity}]: ${r.message || r.description || 'No description'}`
).join('\n')}
${rules.length > 5 ? `... and ${rules.length - 5} more rules` : ''}

**All Active Policies:**
${updated.config.policies.map(p => {
  const pol = context.policyEngine.getPolicy(p);
  return `🛡️ ${pol?.name || p}`;
}).join('\n')}

The agent will now enforce these policies during execution.
`.trim();
  },
};
