// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { Policy, PolicyRule, PolicyAction } from '../src/types';

/**
 * Validates a policy entry structure.
 * Returns an object with isValid boolean and any error message.
 */
export function validatePolicyEntry(policy: unknown): { isValid: boolean; error?: string } {
  if (!policy || typeof policy !== 'object') {
    return { isValid: false, error: 'Policy must be an object' };
  }

  const p = policy as Record<string, unknown>;

  // name is required
  if (!p.name || typeof p.name !== 'string') {
    return { isValid: false, error: 'Policy must have a name string' };
  }

  // rules must be an array if present
  if (p.rules !== undefined && !Array.isArray(p.rules)) {
    return { isValid: false, error: 'Policy rules must be an array' };
  }

  return { isValid: true };
}

/**
 * Validates a policy rule structure.
 */
export function validatePolicyRule(rule: unknown): { isValid: boolean; error?: string } {
  if (!rule || typeof rule !== 'object') {
    return { isValid: false, error: 'Rule must be an object' };
  }

  return { isValid: true };
}

describe('Policy Schema Validation', () => {
  describe('validatePolicyEntry()', () => {
    it('accepts a valid policy entry structure with name, description, and rules', () => {
      const validPolicy: Policy = {
        name: 'test-policy',
        description: 'A test policy for validation',
        rules: [
          {
            name: 'block-dangerous',
            action: 'execute_code',
            effect: 'deny',
            priority: 100,
          },
        ],
      };

      const result = validatePolicyEntry(validPolicy);
      expect(result.isValid).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it('accepts policy with minimal required fields (name only)', () => {
      const minimalPolicy: Policy = {
        name: 'minimal-policy',
        rules: [],
      };

      const result = validatePolicyEntry(minimalPolicy);
      expect(result.isValid).toBe(true);
    });

    it('accepts policy with all optional fields populated', () => {
      const fullPolicy: Policy = {
        apiVersion: 'v1',
        version: '1.0.0',
        name: 'full-policy',
        description: 'Policy with all fields',
        agent: 'agent-001',
        agents: ['agent-001', 'agent-002'],
        scope: 'tenant',
        rules: [
          {
            name: 'allow-read',
            description: 'Allow read operations',
            condition: 'role == "reader"',
            ruleAction: 'allow' as PolicyAction,
            priority: 50,
            enabled: true,
          },
        ],
        default_action: 'deny',
      };

      const result = validatePolicyEntry(fullPolicy);
      expect(result.isValid).toBe(true);
    });

    it('rejects policy entry with missing name field', () => {
      const noNamePolicy = {
        description: 'Missing name',
        rules: [],
      };

      const result = validatePolicyEntry(noNamePolicy);
      expect(result.isValid).toBe(false);
      expect(result.error).toContain('name');
    });

    it('rejects policy entry with non-string name', () => {
      const badNamePolicy = {
        name: 12345,
        rules: [],
      };

      const result = validatePolicyEntry(badNamePolicy);
      expect(result.isValid).toBe(false);
      expect(result.error).toContain('name');
    });

    it('rejects policy with non-array rules', () => {
      const badRulesPolicy = {
        name: 'bad-rules',
        rules: 'not-an-array',
      };

      const result = validatePolicyEntry(badRulesPolicy);
      expect(result.isValid).toBe(false);
      expect(result.error).toContain('array');
    });

    it('handles missing required fields gracefully without crashing', () => {
      const nullPolicy = null;
      const result = validatePolicyEntry(nullPolicy);
      expect(result.isValid).toBe(false);
      expect(result.error).toContain('object');
    });

    it('handles undefined input gracefully without crashing', () => {
      const result = validatePolicyEntry(undefined);
      expect(result.isValid).toBe(false);
    });

    it('handles empty rules array gracefully', () => {
      const emptyRulesPolicy: Policy = {
        name: 'empty-rules-policy',
        rules: [],
      };

      const result = validatePolicyEntry(emptyRulesPolicy);
      expect(result.isValid).toBe(true);
    });
  });

  describe('validatePolicyRule()', () => {
    it('accepts a valid policy rule structure', () => {
      const validRule: PolicyRule = {
        name: 'test-rule',
        description: 'A test rule',
        action: 'data.read',
        effect: 'allow',
        priority: 100,
      };

      const result = validatePolicyRule(validRule);
      expect(result.isValid).toBe(true);
    });

    it('accepts rule with condition expression', () => {
      const ruleWithCondition: PolicyRule = {
        name: 'conditional-rule',
        condition: 'user.role == "admin"',
        ruleAction: 'allow' as PolicyAction,
      };

      const result = validatePolicyRule(ruleWithCondition);
      expect(result.isValid).toBe(true);
    });

    it('accepts rule with conditions object', () => {
      const ruleWithConditions: PolicyRule = {
        name: 'object-conditions-rule',
        conditions: { role: 'admin', env: 'production' },
        effect: 'deny',
      };

      const result = validatePolicyRule(ruleWithConditions);
      expect(result.isValid).toBe(true);
    });

    it('handles null rule gracefully without crashing', () => {
      const result = validatePolicyRule(null);
      expect(result.isValid).toBe(false);
      expect(result.error).toContain('object');
    });

    it('handles undefined rule gracefully without crashing', () => {
      const result = validatePolicyRule(undefined);
      expect(result.isValid).toBe(false);
    });

    it('handles non-object rule gracefully without crashing', () => {
      const result = validatePolicyRule('not an object');
      expect(result.isValid).toBe(false);
    });
  });

  describe('Policy interface completeness', () => {
    it('represents a real-world governance policy entry', () => {
      const governancePolicy: Policy = {
        name: 'production-governance',
        description: 'Governance policy for production environment',
        agent: 'governance-agent',
        rules: [
          {
            name: 'block-shell-exec',
            description: 'Block shell execution in production',
            condition: 'environment == "production"',
            action: 'shell.exec',
            effect: 'deny',
            priority: 200,
            enabled: true,
          },
          {
            name: 'allow-web-search',
            description: 'Allow web search for research',
            action: 'web.search',
            effect: 'allow',
            priority: 50,
            enabled: true,
          },
        ],
        default_action: 'deny',
      };

      const validationResult = validatePolicyEntry(governancePolicy);
      expect(validationResult.isValid).toBe(true);

      // Verify rule count
      expect(governancePolicy.rules).toHaveLength(2);

      // Verify priority ordering works
      const sortedRules = [...governancePolicy.rules].sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0));
      expect(sortedRules[0].name).toBe('block-shell-exec');
    });

    it('handles policy with no rules gracefully', () => {
      const noRulesPolicy: Policy = {
        name: 'no-rules-policy',
        description: 'Policy with empty rules array',
        rules: [],
      };

      const result = validatePolicyEntry(noRulesPolicy);
      expect(result.isValid).toBe(true);
    });
  });
});