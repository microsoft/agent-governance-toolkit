// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * AgentOS MCP Server - Type Definitions
 */

import { z } from 'zod';

// =============================================================================
// Agent Types
// =============================================================================

export const AgentStatusSchema = z.enum([
  'draft',
  'testing',
  'deployed',
  'paused',
  'stopped',
  'error'
]);

export type AgentStatus = z.infer<typeof AgentStatusSchema>;

export const AgentConfigSchema = z.object({
  id: z.uuid(),
  name: z.string(),
  description: z.string(),
  task: z.string(),
  language: z.enum(['python', 'typescript', 'javascript', 'go']).default('python'),
  schedule: z.string().optional(),
  triggers: z.array(z.string()).optional(),
  policies: z.array(z.string()).default([]),
  approvalRequired: z.boolean().default(false),
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
  status: AgentStatusSchema.default('draft'),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

export type AgentConfig = z.infer<typeof AgentConfigSchema>;

export const AgentSpecSchema = z.object({
  config: AgentConfigSchema,
  code: z.string().optional(),
  workflow: z.object({
    steps: z.array(z.object({
      name: z.string(),
      action: z.string(),
      params: z.record(z.string(), z.unknown()),
      conditions: z.array(z.string()).optional(),
    })),
  }).optional(),
  integrations: z.array(z.object({
    type: z.string(),
    config: z.record(z.string(), z.unknown()),
  })).optional(),
});

export type AgentSpec = z.infer<typeof AgentSpecSchema>;

// =============================================================================
// Policy Types
// =============================================================================

export const PolicySeveritySchema = z.enum(['info', 'warning', 'high', 'critical']);
export type PolicySeverity = z.infer<typeof PolicySeveritySchema>;

export const PolicyRuleSchema = z.object({
  name: z.string(),
  description: z.string().optional(),
  condition: z.string(),
  action: z.enum(['allow', 'deny', 'require_approval', 'log', 'transform']),
  severity: PolicySeveritySchema.default('warning'),
  message: z.string().optional(),
  alternative: z.string().optional(),
});

export type PolicyRule = z.infer<typeof PolicyRuleSchema>;

export const PolicySchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  version: z.string().default('1.0.0'),
  category: z.enum([
    'security',
    'privacy',
    'compliance',
    'operational',
    'governance',
    'custom'
  ]),
  framework: z.string().optional(), // e.g., 'SOC2', 'GDPR', 'HIPAA'
  rules: z.array(PolicyRuleSchema),
  enabled: z.boolean().default(true),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

export type Policy = z.infer<typeof PolicySchema>;

export const PolicyEvaluationResultSchema = z.object({
  allowed: z.boolean(),
  violations: z.array(z.object({
    rule: z.string(),
    severity: PolicySeveritySchema,
    message: z.string(),
    alternative: z.string().optional(),
  })),
  warnings: z.array(z.object({
    rule: z.string(),
    message: z.string(),
  })),
  requiresApproval: z.boolean(),
  approvalReason: z.string().optional(),
});

export type PolicyEvaluationResult = z.infer<typeof PolicyEvaluationResultSchema>;

// =============================================================================
// Approval Types
// =============================================================================

export const ApprovalStatusSchema = z.enum([
  'pending',
  'approved',
  'rejected',
  'expired',
  'cancelled'
]);

export type ApprovalStatus = z.infer<typeof ApprovalStatusSchema>;

export const ApprovalRequestSchema = z.object({
  id: z.uuid(),
  agentId: z.uuid(),
  action: z.string(),
  description: z.string(),
  riskLevel: z.enum(['low', 'medium', 'high', 'critical']),
  requestedBy: z.string(),
  requestedAt: z.iso.datetime(),
  expiresAt: z.iso.datetime(),
  status: ApprovalStatusSchema.default('pending'),
  approvers: z.array(z.object({
    email: z.email(),
    name: z.string().optional(),
    role: z.string().optional(),
  })),
  approvals: z.array(z.object({
    approver: z.email(),
    decision: z.enum(['approved', 'rejected']),
    comment: z.string().optional(),
    timestamp: z.iso.datetime(),
  })).default([]),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

export type ApprovalRequest = z.infer<typeof ApprovalRequestSchema>;

// =============================================================================
// Audit Types
// =============================================================================

export const AuditEntrySchema = z.object({
  id: z.uuid(),
  timestamp: z.iso.datetime(),
  agentId: z.uuid(),
  userId: z.string().optional(),
  action: z.string(),
  target: z.string().optional(),
  policyCheck: z.object({
    policiesEvaluated: z.array(z.string()),
    result: z.enum(['APPROVED', 'DENIED', 'APPROVAL_REQUIRED']),
    violations: z.array(z.string()).optional(),
  }).optional(),
  outcome: z.enum(['SUCCESS', 'FAILURE', 'BLOCKED', 'PENDING']),
  errorMessage: z.string().optional(),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

export type AuditEntry = z.infer<typeof AuditEntrySchema>;

// =============================================================================
// Template Types
// =============================================================================

export const AgentTemplateSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  category: z.string(),
  tags: z.array(z.string()),
  difficulty: z.enum(['beginner', 'intermediate', 'advanced']),
  defaultPolicies: z.array(z.string()),
  config: AgentConfigSchema.partial().omit({ id: true, createdAt: true, updatedAt: true }),
  examplePrompts: z.array(z.string()),
});

export type AgentTemplate = z.infer<typeof AgentTemplateSchema>;

export const PolicyTemplateSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  category: z.string(),
  framework: z.string().optional(),
  tags: z.array(z.string()),
  policy: PolicySchema.omit({ id: true }),
});

export type PolicyTemplate = z.infer<typeof PolicyTemplateSchema>;

// =============================================================================
// Compliance Types
// =============================================================================

export const ComplianceFrameworkSchema = z.enum([
  'SOC2',
  'GDPR',
  'HIPAA',
  'PCI_DSS',
  'CCPA',
  'NIST',
  'ISO27001',
  'FEDRAMP'
]);

export type ComplianceFramework = z.infer<typeof ComplianceFrameworkSchema>;

export const ComplianceReportSchema = z.object({
  framework: ComplianceFrameworkSchema,
  agentId: z.uuid(),
  generatedAt: z.iso.datetime(),
  period: z.object({
    start: z.iso.datetime(),
    end: z.iso.datetime(),
  }),
  summary: z.object({
    compliant: z.boolean(),
    score: z.number().min(0).max(100),
    totalControls: z.number(),
    passedControls: z.number(),
    failedControls: z.number(),
  }),
  controls: z.array(z.object({
    id: z.string(),
    name: z.string(),
    status: z.enum(['passed', 'failed', 'not_applicable']),
    evidence: z.array(z.string()),
    recommendation: z.string().optional(),
  })),
});

export type ComplianceReport = z.infer<typeof ComplianceReportSchema>;

// =============================================================================
// Tool Input/Output Types
// =============================================================================

export const CreateAgentInputSchema = z.object({
  description: z.string().describe('Natural language description of the agent task'),
  policies: z.array(z.string()).optional().describe('Policy templates to apply'),
  approvalRequired: z.boolean().optional().describe('Require human approval before execution'),
  language: z.enum(['python', 'typescript', 'javascript', 'go']).optional().describe('Programming language'),
  schedule: z.string().optional().describe('Cron schedule for recurring execution'),
});

export type CreateAgentInput = z.infer<typeof CreateAgentInputSchema>;

export const AttachPolicyInputSchema = z.object({
  agentId: z.uuid().describe('Agent ID to attach policy to'),
  policyId: z.string().describe('Policy template ID or custom policy ID'),
  customRules: z.array(PolicyRuleSchema).optional().describe('Additional custom rules'),
});

export type AttachPolicyInput = z.infer<typeof AttachPolicyInputSchema>;

export const TestAgentInputSchema = z.object({
  agentId: z.uuid().describe('Agent ID to test'),
  scenario: z.string().describe('Test scenario description'),
  mockData: z.record(z.string(), z.unknown()).optional().describe('Mock data for testing'),
  dryRun: z.boolean().default(true).describe('Run without side effects'),
});

export type TestAgentInput = z.infer<typeof TestAgentInputSchema>;

export const DeployAgentInputSchema = z.object({
  agentId: z.uuid().describe('Agent ID to deploy'),
  environment: z.enum(['local', 'cloud']).default('local').describe('Deployment environment'),
  autoStart: z.boolean().default(false).describe('Start agent immediately after deployment'),
});

export type DeployAgentInput = z.infer<typeof DeployAgentInputSchema>;

export const GetAgentStatusInputSchema = z.object({
  agentId: z.uuid().describe('Agent ID to get status for'),
  includeMetrics: z.boolean().default(true).describe('Include execution metrics'),
  includeLogs: z.boolean().default(false).describe('Include recent logs'),
});

export type GetAgentStatusInput = z.infer<typeof GetAgentStatusInputSchema>;

export const ListTemplatesInputSchema = z.object({
  type: z.enum(['agent', 'policy', 'all']).default('all').describe('Template type'),
  category: z.string().optional().describe('Filter by category'),
  search: z.string().optional().describe('Search query'),
  framework: z.string().optional().describe('Filter by compliance framework'),
});

export type ListTemplatesInput = z.infer<typeof ListTemplatesInputSchema>;

export const RequestApprovalInputSchema = z.object({
  agentId: z.uuid().describe('Agent ID'),
  action: z.string().describe('Action requiring approval'),
  description: z.string().describe('Description of what will happen'),
  approvers: z.array(z.email()).describe('List of approver email addresses'),
  expiresInHours: z.number().default(24).describe('Hours until approval expires'),
});

export type RequestApprovalInput = z.infer<typeof RequestApprovalInputSchema>;

export const AuditLogInputSchema = z.object({
  agentId: z.uuid().describe('Agent ID to get audit log for'),
  startTime: z.iso.datetime().optional().describe('Start of time range'),
  endTime: z.iso.datetime().optional().describe('End of time range'),
  actionFilter: z.string().optional().describe('Filter by action type'),
  limit: z.number().default(100).describe('Maximum entries to return'),
});

export type AuditLogInput = z.infer<typeof AuditLogInputSchema>;

export const CreatePolicyInputSchema = z.object({
  description: z.string().describe('Natural language policy description'),
  category: z.enum(['security', 'privacy', 'compliance', 'operational', 'governance', 'custom'])
    .describe('Policy category'),
  framework: z.string().optional().describe('Compliance framework (e.g., SOC2, GDPR)'),
  basedOn: z.string().optional().describe('Policy template to extend'),
});

export type CreatePolicyInput = z.infer<typeof CreatePolicyInputSchema>;

export const CheckComplianceInputSchema = z.object({
  agentId: z.uuid().describe('Agent ID to check'),
  framework: ComplianceFrameworkSchema.describe('Compliance framework to check against'),
  generateReport: z.boolean().default(true).describe('Generate detailed report'),
});

export type CheckComplianceInput = z.infer<typeof CheckComplianceInputSchema>;
