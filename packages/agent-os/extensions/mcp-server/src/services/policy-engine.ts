// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Policy Engine Service
 * 
 * Evaluates policies against agent actions and enforces compliance.
 */

import {
  Policy,
  PolicyRule,
  PolicyEvaluationResult,
  PolicySeverity,
  CreatePolicyInput,
} from '../types/index.js';
import { v4 as uuidv4 } from 'uuid';

// Built-in policy templates
const BUILT_IN_POLICIES: Policy[] = [
  {
    id: 'pii-protection',
    name: 'PII Protection',
    description: 'Protects personally identifiable information',
    version: '1.0.0',
    category: 'privacy',
    framework: 'GDPR',
    rules: [
      {
        name: 'block_pii_fields',
        description: 'Block access to common PII fields',
        condition: 'field in ["ssn", "social_security", "credit_card", "card_number"]',
        action: 'deny',
        severity: 'critical',
        message: 'Access to PII field blocked by policy',
        alternative: 'Use anonymized or tokenized data instead',
      },
      {
        name: 'redact_email',
        description: 'Redact email addresses from output',
        condition: 'output.matches(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}/)',
        action: 'transform',
        severity: 'high',
        message: 'Email addresses will be redacted from output',
      },
      {
        name: 'log_pii_access',
        description: 'Log all access to PII-related data',
        condition: 'action.type == "data_access" && data.sensitivity == "pii"',
        action: 'log',
        severity: 'info',
        message: 'PII access logged',
      },
    ],
    enabled: true,
  },
  {
    id: 'rate-limiting',
    name: 'Rate Limiting',
    description: 'Prevents resource abuse through rate limiting',
    version: '1.0.0',
    category: 'operational',
    rules: [
      {
        name: 'api_rate_limit',
        description: 'Limit external API calls',
        condition: 'action.type == "api_call" && rate > 100/minute',
        action: 'deny',
        severity: 'high',
        message: 'API rate limit exceeded (100/minute)',
        alternative: 'Add delays between requests or batch operations',
      },
      {
        name: 'database_query_limit',
        description: 'Limit database queries',
        condition: 'action.type == "database_query" && rate > 1000/hour',
        action: 'deny',
        severity: 'warning',
        message: 'Database query rate limit exceeded',
      },
    ],
    enabled: true,
  },
  {
    id: 'cost-control',
    name: 'Cost Control',
    description: 'Prevents runaway costs from automated operations',
    version: '1.0.0',
    category: 'operational',
    rules: [
      {
        name: 'daily_budget',
        description: 'Enforce daily spending limit',
        condition: 'daily_cost > budget.daily',
        action: 'deny',
        severity: 'critical',
        message: 'Daily budget exceeded',
      },
      {
        name: 'expensive_operation_approval',
        description: 'Require approval for expensive operations',
        condition: 'estimated_cost > 10.00',
        action: 'require_approval',
        severity: 'high',
        message: 'Expensive operation requires approval',
      },
    ],
    enabled: true,
  },
  {
    id: 'data-deletion',
    name: 'Data Deletion Safety',
    description: 'Prevents accidental data loss from destructive operations',
    version: '1.0.0',
    category: 'security',
    rules: [
      {
        name: 'block_mass_delete',
        description: 'Block mass deletion without conditions',
        condition: 'action.type == "delete" && !action.has_where_clause',
        action: 'deny',
        severity: 'critical',
        message: 'Mass deletion blocked - WHERE clause required',
        alternative: 'Add specific conditions to limit deletion scope',
      },
      {
        name: 'require_backup',
        description: 'Require backup before deletion',
        condition: 'action.type == "delete" && action.record_count > 100',
        action: 'require_approval',
        severity: 'high',
        message: 'Large deletion requires approval and backup',
      },
      {
        name: 'block_drop_table',
        description: 'Block DROP TABLE operations',
        condition: 'action.sql.matches(/DROP\\s+TABLE/i)',
        action: 'deny',
        severity: 'critical',
        message: 'DROP TABLE operations are blocked',
        alternative: 'Use soft delete or archival instead',
      },
    ],
    enabled: true,
  },
  {
    id: 'secrets-protection',
    name: 'Secrets Protection',
    description: 'Prevents exposure of secrets and credentials',
    version: '1.0.0',
    category: 'security',
    rules: [
      {
        name: 'no_hardcoded_secrets',
        description: 'Block hardcoded API keys and passwords',
        condition: 'code.matches(/api[_-]?key\\s*=\\s*["\'][^"\']{20,}["\']/) || code.matches(/password\\s*=\\s*["\'][^"\']+["\']/',
        action: 'deny',
        severity: 'critical',
        message: 'Hardcoded secrets detected in code',
        alternative: 'Use environment variables or secrets manager',
      },
      {
        name: 'no_secrets_in_logs',
        description: 'Prevent secrets from appearing in logs',
        condition: 'output.matches(/(api[_-]?key|password|secret|token)\\s*[:=]\\s*\\S+/i)',
        action: 'transform',
        severity: 'critical',
        message: 'Secrets will be redacted from logs',
      },
    ],
    enabled: true,
  },
  {
    id: 'human-review',
    name: 'Human Review Required',
    description: 'Requires human approval for sensitive actions',
    version: '1.0.0',
    category: 'governance',
    rules: [
      {
        name: 'external_communication',
        description: 'Require approval for external communications',
        condition: 'action.type in ["send_email", "post_social", "send_message"]',
        action: 'require_approval',
        severity: 'high',
        message: 'External communication requires human approval',
      },
      {
        name: 'financial_transactions',
        description: 'Require approval for financial transactions',
        condition: 'action.type == "financial" && amount > 0',
        action: 'require_approval',
        severity: 'critical',
        message: 'Financial transactions require human approval',
      },
      {
        name: 'production_changes',
        description: 'Require approval for production deployments',
        condition: 'action.environment == "production"',
        action: 'require_approval',
        severity: 'high',
        message: 'Production changes require approval',
      },
    ],
    enabled: true,
  },
];

export class PolicyEngine {
  private mode: 'strict' | 'permissive';
  private policies: Map<string, Policy>;
  
  constructor(mode: 'strict' | 'permissive' = 'strict') {
    this.mode = mode;
    this.policies = new Map();
    
    // Load built-in policies
    for (const policy of BUILT_IN_POLICIES) {
      this.policies.set(policy.id, policy);
    }
  }
  
  /**
   * Get all available policies.
   */
  getAllPolicies(): Policy[] {
    return Array.from(this.policies.values());
  }
  
  /**
   * Get policy by ID.
   */
  getPolicy(id: string): Policy | undefined {
    return this.policies.get(id);
  }
  
  /**
   * Create a new policy from natural language description.
   */
  createPolicy(input: CreatePolicyInput): Policy {
    const id = `custom-${uuidv4().slice(0, 8)}`;
    
    // Parse description to generate rules (simplified - would use AI in production)
    const rules = this.parseDescriptionToRules(input.description);
    
    const policy: Policy = {
      id,
      name: this.generatePolicyName(input.description),
      description: input.description,
      version: '1.0.0',
      category: input.category,
      framework: input.framework,
      rules,
      enabled: true,
    };
    
    // If based on existing policy, inherit rules
    if (input.basedOn) {
      const basePolicy = this.policies.get(input.basedOn);
      if (basePolicy) {
        policy.rules = [...basePolicy.rules, ...rules];
      }
    }
    
    this.policies.set(id, policy);
    
    return policy;
  }
  
  /**
   * Parse description into policy rules.
   */
  private parseDescriptionToRules(description: string): PolicyRule[] {
    const rules: PolicyRule[] = [];
    const lowerDesc = description.toLowerCase();
    
    // Detect common policy intents
    if (lowerDesc.includes('block') || lowerDesc.includes('prevent')) {
      rules.push({
        name: 'custom_block_rule',
        description: `Block actions based on: ${description}`,
        condition: 'custom_condition',
        action: 'deny',
        severity: 'high',
        message: `Blocked by policy: ${description}`,
      });
    }
    
    if (lowerDesc.includes('approval') || lowerDesc.includes('review')) {
      rules.push({
        name: 'custom_approval_rule',
        description: `Require approval based on: ${description}`,
        condition: 'custom_condition',
        action: 'require_approval',
        severity: 'high',
        message: `Approval required: ${description}`,
      });
    }
    
    if (lowerDesc.includes('log') || lowerDesc.includes('audit')) {
      rules.push({
        name: 'custom_log_rule',
        description: `Log actions based on: ${description}`,
        condition: 'custom_condition',
        action: 'log',
        severity: 'info',
        message: `Logged by policy: ${description}`,
      });
    }
    
    // Default rule if nothing matched
    if (rules.length === 0) {
      rules.push({
        name: 'custom_default_rule',
        description: description,
        condition: 'true',
        action: 'log',
        severity: 'info',
        message: description,
      });
    }
    
    return rules;
  }
  
  /**
   * Generate a policy name from description.
   */
  private generatePolicyName(description: string): string {
    const words = description.split(' ').slice(0, 4);
    return words.map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
  }
  
  /**
   * Evaluate an action against policies.
   */
  evaluate(
    action: {
      type: string;
      target?: string;
      params?: Record<string, unknown>;
    },
    policyIds: string[]
  ): PolicyEvaluationResult {
    const violations: PolicyEvaluationResult['violations'] = [];
    const warnings: PolicyEvaluationResult['warnings'] = [];
    let requiresApproval = false;
    let approvalReason: string | undefined;
    
    for (const policyId of policyIds) {
      const policy = this.policies.get(policyId);
      if (!policy || !policy.enabled) continue;
      
      for (const rule of policy.rules) {
        const match = this.evaluateRule(rule, action);
        
        if (match) {
          switch (rule.action) {
            case 'deny':
              violations.push({
                rule: rule.name,
                severity: rule.severity,
                message: rule.message || `Policy violation: ${rule.name}`,
                alternative: rule.alternative,
              });
              break;
              
            case 'require_approval':
              requiresApproval = true;
              approvalReason = rule.message;
              warnings.push({
                rule: rule.name,
                message: rule.message || 'Approval required',
              });
              break;
              
            case 'log':
            case 'transform':
              warnings.push({
                rule: rule.name,
                message: rule.message || `Rule triggered: ${rule.name}`,
              });
              break;
          }
        }
      }
    }
    
    // In strict mode, any violation blocks the action
    // In permissive mode, only critical violations block
    const allowed = this.mode === 'strict'
      ? violations.length === 0
      : !violations.some(v => v.severity === 'critical');
    
    return {
      allowed,
      violations,
      warnings,
      requiresApproval,
      approvalReason,
    };
  }
  
  /**
   * Evaluate a single rule against an action.
   */
  private evaluateRule(
    rule: PolicyRule,
    action: { type: string; target?: string; params?: Record<string, unknown> }
  ): boolean {
    // Simplified rule evaluation - in production would use a proper expression engine
    const condition = rule.condition.toLowerCase();
    const actionType = action.type.toLowerCase();
    
    // Check action type conditions
    if (condition.includes('action.type ==')) {
      const match = condition.match(/action\.type\s*==\s*["']([^"']+)["']/);
      if (match && actionType === match[1].toLowerCase()) {
        return true;
      }
    }
    
    // Check action type "in" conditions
    if (condition.includes('action.type in')) {
      const match = condition.match(/action\.type\s+in\s+\[([^\]]+)\]/);
      if (match) {
        const types = match[1].split(',').map(t => t.trim().replace(/["']/g, '').toLowerCase());
        if (types.includes(actionType)) {
          return true;
        }
      }
    }
    
    // Check for custom conditions
    if (condition === 'custom_condition') {
      // Custom conditions would be evaluated differently
      return false;
    }
    
    // Check for "true" condition (always matches)
    if (condition === 'true') {
      return true;
    }
    
    return false;
  }
  
  /**
   * Validate that policies can be applied together (no conflicts).
   */
  validatePolicyCombination(policyIds: string[]): { valid: boolean; conflicts: string[] } {
    const conflicts: string[] = [];
    
    // Check for conflicting rules (simplified)
    const denyRules: string[] = [];
    const allowRules: string[] = [];
    
    for (const policyId of policyIds) {
      const policy = this.policies.get(policyId);
      if (!policy) continue;
      
      for (const rule of policy.rules) {
        if (rule.action === 'deny') {
          denyRules.push(`${policyId}:${rule.name}`);
        }
        if (rule.action === 'allow') {
          allowRules.push(`${policyId}:${rule.name}`);
        }
      }
    }
    
    // Flag if same action is both denied and allowed
    // (simplified - real implementation would check conditions)
    
    return {
      valid: conflicts.length === 0,
      conflicts,
    };
  }
}
