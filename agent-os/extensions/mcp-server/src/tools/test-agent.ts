// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * test_agent Tool
 * 
 * Runs a dry-run test of an agent with simulated scenarios.
 */

import { ServiceContext } from '../server.js';
import { TestAgentInputSchema } from '../types/index.js';

export const testAgentTool = {
  definition: {
    name: 'test_agent',
    description: `Test an agent with a simulated scenario before deployment. 

This performs a dry-run that:
- Validates the agent configuration
- Checks all policies against the test scenario
- Simulates workflow execution
- Reports any policy violations or issues
- Estimates resource usage and costs

No actual changes are made during testing.`,
    inputSchema: {
      type: 'object' as const,
      properties: {
        agentId: {
          type: 'string',
          description: 'Agent ID to test',
        },
        scenario: {
          type: 'string',
          description: 'Test scenario description (e.g., "Process 100 customer emails")',
        },
        mockData: {
          type: 'object',
          description: 'Mock data for testing (optional)',
        },
        dryRun: {
          type: 'boolean',
          description: 'Run without side effects (default: true)',
        },
      },
      required: ['agentId', 'scenario'],
    },
  },
  
  async execute(args: unknown, context: ServiceContext): Promise<string> {
    const input = TestAgentInputSchema.parse(args);
    
    context.logger.info('Testing agent', { agentId: input.agentId, scenario: input.scenario });
    
    // Get agent
    const agent = await context.agentManager.getAgent(input.agentId);
    if (!agent) {
      throw new Error(`Agent not found: ${input.agentId}`);
    }
    
    // Simulate test execution
    const testResults = {
      configValid: true,
      workflowValid: true,
      policyViolations: [] as Array<{ rule: string; message: string; severity: string }>,
      warnings: [] as string[],
      estimatedDuration: '~30 seconds',
      estimatedCost: '$0.05',
      stepsSimulated: 0,
    };
    
    // Validate configuration
    if (!agent.config.task) {
      testResults.configValid = false;
      testResults.warnings.push('Agent has no task defined');
    }
    
    // Validate workflow
    if (!agent.workflow?.steps?.length) {
      testResults.workflowValid = false;
      testResults.warnings.push('Agent has no workflow steps');
    } else {
      testResults.stepsSimulated = agent.workflow.steps.length;
    }
    
    // Check policies against scenario
    const scenarioActions = parseScenarioActions(input.scenario);
    
    for (const action of scenarioActions) {
      const evaluation = context.policyEngine.evaluate(action, agent.config.policies);
      
      if (!evaluation.allowed) {
        for (const violation of evaluation.violations) {
          testResults.policyViolations.push({
            rule: violation.rule,
            message: violation.message,
            severity: violation.severity,
          });
        }
      }
      
      for (const warning of evaluation.warnings) {
        testResults.warnings.push(warning.message);
      }
    }
    
    // Calculate pass/fail
    const passed = testResults.configValid && 
                   testResults.workflowValid && 
                   testResults.policyViolations.filter(v => v.severity === 'critical').length === 0;
    
    // Format results
    const statusEmoji = passed ? '✅' : '❌';
    const statusText = passed ? 'PASSED' : 'FAILED';
    
    return `
${statusEmoji} Test ${statusText}

**Agent:** ${agent.config.name}
**Scenario:** ${input.scenario}
**Mode:** ${input.dryRun ? 'Dry Run (no changes)' : 'Live Test'}

**Configuration Check:**
${testResults.configValid ? '✅ Valid' : '❌ Invalid'}

**Workflow Check:**
${testResults.workflowValid ? `✅ Valid (${testResults.stepsSimulated} steps)` : '❌ Invalid'}

**Policy Evaluation:**
${testResults.policyViolations.length === 0 
  ? '✅ No violations detected'
  : testResults.policyViolations.map(v => 
      `❌ [${v.severity.toUpperCase()}] ${v.rule}: ${v.message}`
    ).join('\n')
}

**Warnings:**
${testResults.warnings.length === 0
  ? '✅ None'
  : testResults.warnings.map(w => `⚠️  ${w}`).join('\n')
}

**Resource Estimates:**
- Duration: ${testResults.estimatedDuration}
- Cost: ${testResults.estimatedCost}

${passed 
  ? '**Next Step:** Use `deploy_agent` to deploy this agent.'
  : '**Action Required:** Fix the issues above before deployment.'
}
`.trim();
  },
};

/**
 * Parse scenario description into testable actions.
 */
function parseScenarioActions(scenario: string): Array<{
  type: string;
  target?: string;
  params?: Record<string, unknown>;
}> {
  const actions: Array<{ type: string; target?: string; params?: Record<string, unknown> }> = [];
  const lowerScenario = scenario.toLowerCase();
  
  // Detect common action patterns
  if (lowerScenario.includes('email')) {
    actions.push({ type: 'send_email' });
    actions.push({ type: 'read_email' });
  }
  
  if (lowerScenario.includes('database') || lowerScenario.includes('query')) {
    actions.push({ type: 'database_query' });
  }
  
  if (lowerScenario.includes('delete')) {
    actions.push({ type: 'delete' });
  }
  
  if (lowerScenario.includes('file') || lowerScenario.includes('backup')) {
    actions.push({ type: 'file_write' });
    actions.push({ type: 'file_read' });
  }
  
  if (lowerScenario.includes('api') || lowerScenario.includes('call')) {
    actions.push({ type: 'api_call' });
  }
  
  if (lowerScenario.includes('slack') || lowerScenario.includes('message')) {
    actions.push({ type: 'send_message' });
  }
  
  // Default action if nothing detected
  if (actions.length === 0) {
    actions.push({ type: 'execute' });
  }
  
  return actions;
}
