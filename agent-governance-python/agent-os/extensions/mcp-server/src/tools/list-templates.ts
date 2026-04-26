// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * list_templates Tool
 * 
 * Lists available agent and policy templates.
 */

import { ServiceContext } from '../server.js';
import { ListTemplatesInputSchema } from '../types/index.js';

export const listTemplatesTool = {
  definition: {
    name: 'list_templates',
    description: `Browse the library of pre-built agent and policy templates.

Agent templates include:
- Data processors, email assistants, database analysts
- File organizers, backup agents, web scrapers
- Slack bots, API monitors, report generators

Policy templates include:
- Security: PII protection, secrets protection, data deletion safety
- Compliance: GDPR, SOC 2, HIPAA, PCI DSS
- Operational: Rate limiting, cost control, human review

Use templates as a starting point for your custom agents.`,
    inputSchema: {
      type: 'object' as const,
      properties: {
        type: {
          type: 'string',
          enum: ['agent', 'policy', 'all'],
          description: 'Template type to list',
        },
        category: {
          type: 'string',
          description: 'Filter by category (e.g., "data", "security", "compliance")',
        },
        search: {
          type: 'string',
          description: 'Search query to filter templates',
        },
        framework: {
          type: 'string',
          description: 'Filter by compliance framework (e.g., "GDPR", "SOC2")',
        },
      },
    },
  },
  
  async execute(args: unknown, context: ServiceContext): Promise<string> {
    const input = ListTemplatesInputSchema.parse(args);
    
    context.logger.info('Listing templates', input);
    
    const showAgents = input.type === 'all' || input.type === 'agent';
    const showPolicies = input.type === 'all' || input.type === 'policy';
    
    let output = '# Template Library\n\n';
    
    // List agent templates
    if (showAgents) {
      const agents = context.templateLibrary.listAgentTemplates({
        category: input.category,
        search: input.search,
      });
      
      output += `## Agent Templates (${agents.length})\n\n`;
      
      if (agents.length === 0) {
        output += 'No matching agent templates found.\n\n';
      } else {
        // Group by category
        const byCategory = new Map<string, typeof agents>();
        for (const agent of agents) {
          const list = byCategory.get(agent.category) || [];
          list.push(agent);
          byCategory.set(agent.category, list);
        }
        
        for (const [category, list] of byCategory) {
          output += `### ${category.charAt(0).toUpperCase() + category.slice(1)}\n\n`;
          for (const agent of list) {
            const difficultyEmoji = {
              beginner: '🟢',
              intermediate: '🟡',
              advanced: '🔴',
            }[agent.difficulty];
            
            output += `**${agent.name}** (${agent.id}) ${difficultyEmoji}\n`;
            output += `${agent.description}\n`;
            output += `Tags: ${agent.tags.join(', ')}\n`;
            output += `Default policies: ${agent.defaultPolicies.join(', ') || 'None'}\n\n`;
          }
        }
      }
    }
    
    // List policy templates
    if (showPolicies) {
      const policies = context.templateLibrary.listPolicyTemplates({
        category: input.category,
        framework: input.framework,
        search: input.search,
      });
      
      // Also list built-in policies
      const builtInPolicies = context.policyEngine.getAllPolicies();
      
      output += `## Policy Templates (${policies.length + builtInPolicies.length})\n\n`;
      
      // Built-in policies
      output += `### Built-in Policies\n\n`;
      for (const policy of builtInPolicies) {
        const severityEmoji = {
          security: '🔒',
          privacy: '👁️',
          compliance: '📋',
          operational: '⚙️',
          governance: '🏛️',
          custom: '✨',
        }[policy.category] || '📄';
        
        output += `**${policy.name}** (${policy.id}) ${severityEmoji}\n`;
        output += `${policy.description}\n`;
        output += `Rules: ${policy.rules.length}\n`;
        if (policy.framework) {
          output += `Framework: ${policy.framework}\n`;
        }
        output += '\n';
      }
      
      // Compliance templates
      if (policies.length > 0) {
        output += `### Compliance Templates\n\n`;
        for (const template of policies) {
          output += `**${template.name}** (${template.id})\n`;
          output += `${template.description}\n`;
          output += `Framework: ${template.framework || 'General'}\n`;
          output += `Tags: ${template.tags.join(', ')}\n\n`;
        }
      }
    }
    
    // Add usage instructions
    output += `---\n\n`;
    output += `**Usage:**\n`;
    output += `- Create agent from template: Include template name in your description\n`;
    output += `- Attach policy: \`attach_policy\` with policyId\n`;
    output += `- Search templates: Use search parameter to filter\n`;
    
    return output;
  },
};
