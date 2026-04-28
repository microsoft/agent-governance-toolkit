// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Policy Engine
 * 
 * Evaluates tool calls against security policies.
 */

import { readFileSync, existsSync } from 'fs';
import { parse as parseYaml } from 'yaml';
import { fileURLToPath } from 'url';
import { dirname, join, isAbsolute } from 'path';

export interface PolicyRule {
  tool: string;
  action: 'allow' | 'deny';
  reason?: string;
  conditions?: PolicyCondition[];
  rate_limit?: { requests: number; per: string };
  mitigates?: string[];
}

export interface PolicyCondition {
  path_starts_with?: string;
  path_not_contains?: string[];
  argument_matches?: { [key: string]: string };
  argument_not_matches?: { [key: string]: string };
}

export interface Policy {
  version: string;
  mode: 'enforce' | 'shadow';
  rules: PolicyRule[];
  rate_limits?: {
    global?: { requests: number; per: string };
    per_tool?: { [tool: string]: { requests: number; per: string } };
  };
}

export interface PolicyDecision {
  allowed: boolean;
  reason?: string;
  matchedRule?: string;
  mitigatedRisks?: string[];
}

// Built-in policies
export const BUILTIN_POLICIES: Record<string, string> = {
  minimal: 'Allow all tools, log everything',
  standard: 'Block known-dangerous tools',
  strict: 'Allowlist only, deny by default',
  enterprise: 'Full audit, PII detection, rate limits',
};

const BUILTIN_POLICY_DEFS: Record<string, Policy> = {
  minimal: {
    version: '1.0',
    mode: 'enforce',
    rules: [
      { tool: '*', action: 'allow' },
    ],
  },
  standard: {
    version: '1.0',
    mode: 'enforce',
    rules: [
      { tool: 'run_shell', action: 'deny', reason: 'Shell execution blocked', mitigates: ['ASI02', 'ASI05'] },
      { tool: 'execute_command', action: 'deny', reason: 'Command execution blocked', mitigates: ['ASI02', 'ASI05'] },
      { tool: 'eval', action: 'deny', reason: 'Eval blocked', mitigates: ['ASI05'] },
      { tool: '*', action: 'allow' },
    ],
  },
  strict: {
    version: '1.0',
    mode: 'enforce',
    rules: [
      { tool: 'read_file', action: 'allow' },
      { tool: 'list_directory', action: 'allow' },
      { tool: 'search_files', action: 'allow' },
      { tool: '*', action: 'deny', reason: 'Tool not in allowlist' },
    ],
  },
  enterprise: {
    version: '1.0',
    mode: 'enforce',
    rules: [
      { tool: 'run_shell', action: 'deny', reason: 'Shell execution blocked', mitigates: ['ASI02', 'ASI05'] },
      { tool: 'execute_command', action: 'deny', reason: 'Command execution blocked', mitigates: ['ASI02', 'ASI05'] },
      { tool: 'write_file', action: 'allow', rate_limit: { requests: 10, per: 'minute' } },
      { tool: '*', action: 'allow' },
    ],
    rate_limits: {
      global: { requests: 100, per: 'minute' },
    },
  },
};

export async function loadPolicy(nameOrPath: string): Promise<Policy> {
  // Check if it's a built-in policy
  if (BUILTIN_POLICY_DEFS[nameOrPath]) {
    return BUILTIN_POLICY_DEFS[nameOrPath];
  }

  // Load from file
  const path = isAbsolute(nameOrPath) ? nameOrPath : join(process.cwd(), nameOrPath);
  
  if (!existsSync(path)) {
    throw new Error(`Policy file not found: ${path}`);
  }

  const content = readFileSync(path, 'utf-8');
  
  // Parse YAML or JSON
  let policy: Policy;
  if (path.endsWith('.json')) {
    policy = JSON.parse(content);
  } else {
    policy = parseYaml(content);
  }

  // Validate
  validatePolicy(policy);
  
  return policy;
}

function validatePolicy(policy: Policy): void {
  if (!policy.version) {
    throw new Error('Policy must have a version');
  }
  if (!policy.rules || !Array.isArray(policy.rules)) {
    throw new Error('Policy must have rules array');
  }
  for (const rule of policy.rules) {
    if (!rule.tool) {
      throw new Error('Each rule must have a tool field');
    }
    if (!['allow', 'deny'].includes(rule.action)) {
      throw new Error(`Invalid action: ${rule.action}. Must be 'allow' or 'deny'`);
    }
  }
}

export function evaluatePolicy(
  policy: Policy,
  toolName: string,
  args: Record<string, any>
): PolicyDecision {
  // Find matching rule (first match wins)
  for (const rule of policy.rules) {
    if (matchesRule(rule, toolName, args)) {
      return {
        allowed: rule.action === 'allow',
        reason: rule.reason,
        matchedRule: rule.tool,
        mitigatedRisks: rule.mitigates ? [...rule.mitigates] : undefined,
      };
    }
  }

  // Default: deny if no rule matches
  return {
    allowed: false,
    reason: 'No matching policy rule',
  };
}

function matchesRule(
  rule: PolicyRule,
  toolName: string,
  args: Record<string, any>
): boolean {
  // Check tool name
  if (rule.tool !== '*' && rule.tool !== toolName) {
    // Wildcard matching
    if (rule.tool.includes('*')) {
      const pattern = rule.tool.replace(/\*/g, '.*');
      if (!new RegExp(`^${pattern}$`).test(toolName)) {
        return false;
      }
    } else {
      return false;
    }
  }

  // Check conditions
  if (rule.conditions) {
    for (const condition of rule.conditions) {
      if (!evaluateCondition(condition, args)) {
        return false;
      }
    }
  }

  return true;
}

function evaluateCondition(
  condition: PolicyCondition,
  args: Record<string, any>
): boolean {
  // path_starts_with
  if (condition.path_starts_with) {
    const path = args.path || args.file_path || args.filename || '';
    if (!path.startsWith(condition.path_starts_with)) {
      return false;
    }
  }

  // path_not_contains
  if (condition.path_not_contains) {
    const path = (args.path || args.file_path || args.filename || '').toLowerCase();
    for (const forbidden of condition.path_not_contains) {
      if (path.includes(forbidden.toLowerCase())) {
        return false;
      }
    }
  }

  // argument_matches (regex)
  if (condition.argument_matches) {
    for (const [key, pattern] of Object.entries(condition.argument_matches)) {
      const value = args[key];
      if (value === undefined || !new RegExp(pattern).test(String(value))) {
        return false;
      }
    }
  }

  // argument_not_matches (regex)
  if (condition.argument_not_matches) {
    for (const [key, pattern] of Object.entries(condition.argument_not_matches)) {
      const value = args[key];
      if (value !== undefined && new RegExp(pattern).test(String(value))) {
        return false;
      }
    }
  }

  return true;
}
