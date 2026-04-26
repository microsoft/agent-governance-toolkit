// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * MCP Prompts for AgentOS
 * 
 * Standard conversation templates for common workflows.
 */

export interface PromptDefinition {
  name: string;
  description: string;
  arguments?: Array<{
    name: string;
    description: string;
    required: boolean;
  }>;
  template: string;
}

export const PROMPTS: Record<string, PromptDefinition> = {
  create_safe_agent: {
    name: 'create_safe_agent',
    description: 'Guide for creating a new agent with appropriate safety policies',
    arguments: [
      {
        name: 'task',
        description: 'What should the agent do?',
        required: true,
      },
      {
        name: 'data_sensitivity',
        description: 'Type of data: public, internal, confidential, pii',
        required: false,
      },
    ],
    template: `I want to create a safe, policy-compliant agent for the following task:

**Task:** {task}
**Data Sensitivity:** {data_sensitivity}

Please help me:
1. Create the agent with appropriate configuration
2. Recommend safety policies based on the task and data sensitivity
3. Set up any required approval workflows
4. Test the agent before deployment

I want to ensure the agent follows best practices for:
- Data protection and privacy
- Rate limiting and cost control
- Human oversight where appropriate
- Comprehensive audit logging

Please start by creating the agent and explaining what policies you recommend.`,
  },
  
  compliance_setup: {
    name: 'compliance_setup',
    description: 'Set up an agent for regulatory compliance',
    arguments: [
      {
        name: 'agent_id',
        description: 'Existing agent ID to configure',
        required: true,
      },
      {
        name: 'framework',
        description: 'Compliance framework: SOC2, GDPR, HIPAA, PCI_DSS',
        required: true,
      },
    ],
    template: `I need to configure agent {agent_id} for {framework} compliance.

Please help me:
1. Check current compliance status
2. Identify gaps in policy coverage
3. Attach required policies
4. Verify compliance after configuration
5. Generate a compliance report

Framework requirements for {framework}:
- SOC2: Access controls, audit logging, change management
- GDPR: Data minimization, consent, right to erasure
- HIPAA: PHI protection, minimum necessary, audit controls
- PCI_DSS: Cardholder data protection, access restriction

Start by checking the current compliance status and recommending specific policies.`,
  },
  
  troubleshoot_agent: {
    name: 'troubleshoot_agent',
    description: 'Diagnose and fix issues with an agent',
    arguments: [
      {
        name: 'agent_id',
        description: 'Agent ID having issues',
        required: true,
      },
      {
        name: 'issue',
        description: 'Description of the problem',
        required: false,
      },
    ],
    template: `I'm having issues with agent {agent_id}.

**Problem:** {issue}

Please help me diagnose and fix the issue by:
1. Checking the agent status and configuration
2. Reviewing recent audit logs for errors
3. Checking for policy violations
4. Identifying any pending approvals
5. Recommending fixes

Common issues to check:
- Policy violations blocking actions
- Missing permissions or integrations
- Rate limits being exceeded
- Pending approval requests
- Configuration errors

Start by getting the agent status and recent audit logs.`,
  },
  
  batch_policy_update: {
    name: 'batch_policy_update',
    description: 'Apply policies to multiple agents',
    arguments: [
      {
        name: 'policy_id',
        description: 'Policy to apply',
        required: true,
      },
      {
        name: 'reason',
        description: 'Reason for the policy update',
        required: false,
      },
    ],
    template: `I need to apply the {policy_id} policy across my organization.

**Reason:** {reason}

Please help me:
1. List all agents that need this policy
2. Check for any conflicts with existing policies
3. Apply the policy to compatible agents
4. Report any agents that couldn't be updated
5. Verify the changes

This is important for:
- Security incident response
- New compliance requirements
- Organizational policy changes
- Risk mitigation

Start by listing the agents and checking policy compatibility.`,
  },
  
  security_review: {
    name: 'security_review',
    description: 'Comprehensive security review of agents',
    arguments: [
      {
        name: 'scope',
        description: 'Review scope: single agent ID or "all"',
        required: false,
      },
    ],
    template: `I need a comprehensive security review of my agents.

**Scope:** {scope}

Please review:
1. Policy coverage across all agents
2. Secrets protection configuration
3. Access control and approvals
4. Audit log completeness
5. Compliance status for key frameworks

Security checklist:
- [ ] All agents have appropriate policies
- [ ] No hardcoded secrets in configurations
- [ ] Sensitive actions require approval
- [ ] Audit logging is comprehensive
- [ ] PII is properly protected
- [ ] Rate limiting prevents abuse

Provide a security posture summary and actionable recommendations.`,
  },
  
  onboarding: {
    name: 'onboarding',
    description: 'Introduction to AgentOS for new users',
    arguments: [],
    template: `Welcome to AgentOS! I'm ready to help you create safe, policy-compliant AI agents.

**What I can help you with:**

🤖 **Create Agents** - Build autonomous agents from natural language descriptions
🛡️ **Apply Policies** - Enforce safety rules and compliance requirements  
✅ **Manage Approvals** - Set up human-in-the-loop for sensitive actions
📊 **Monitor & Audit** - Track agent activity and generate compliance reports
📋 **Use Templates** - Start from pre-built agent and policy templates

**Quick Start Examples:**

1. "Create an agent that backs up my Documents folder daily"
2. "Set up a data processing pipeline with GDPR compliance"
3. "Build an email responder with human review before sending"

**Safety First:**
All agents run through the AgentOS policy engine, which:
- Blocks dangerous operations automatically
- Enforces rate limits and cost controls
- Logs all actions for audit
- Supports compliance frameworks (SOC2, GDPR, HIPAA)

Would you like to:
1. Create your first agent
2. Browse available templates
3. Learn about safety policies
4. See a demo of agent creation`,
  },
};
