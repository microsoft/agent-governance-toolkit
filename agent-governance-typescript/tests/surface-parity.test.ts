// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { SurfaceParityChecker } from '../src/surface-parity';
import type { Policy, PolicyRule } from '../src/types';

function makePolicy(name: string, rules: PolicyRule[]): Policy {
  return { name, rules, default_action: 'deny' };
}

describe('SurfaceParityChecker', () => {
  let checker: SurfaceParityChecker;

  beforeEach(() => {
    checker = new SurfaceParityChecker();
  });

  describe('detectSurfaces()', () => {
    it('returns empty array for universal rules (no surface restriction)', () => {
      const rule: PolicyRule = {
        name: 'block-external',
        condition: "agent.type == 'external'",
        ruleAction: 'deny',
      };
      expect(checker.detectSurfaces(rule)).toEqual([]);
    });

    it('detects surface from explicit surfaces field', () => {
      const rule: PolicyRule = {
        name: 'cli-only',
        condition: "agent.type == 'external'",
        ruleAction: 'deny',
        surfaces: ['cli'],
      };
      expect(checker.detectSurfaces(rule)).toEqual(['cli']);
    });

    it('detects surface from condition string (surface == "cli")', () => {
      const rule: PolicyRule = {
        name: 'cli-check',
        condition: "surface == 'cli' and agent.risk > 5",
        ruleAction: 'deny',
      };
      expect(checker.detectSurfaces(rule)).toEqual(['cli']);
    });

    it('detects surface from context.surface in condition', () => {
      const rule: PolicyRule = {
        name: 'ide-check',
        condition: "context.surface == 'ide'",
        ruleAction: 'warn',
      };
      expect(checker.detectSurfaces(rule)).toEqual(['ide']);
    });

    it('detects multiple surfaces from in-expression', () => {
      const rule: PolicyRule = {
        name: 'multi-surface',
        condition: "surface in ['cli', 'api']",
        ruleAction: 'log',
      };
      const surfaces = checker.detectSurfaces(rule);
      expect(surfaces).toContain('cli');
      expect(surfaces).toContain('api');
    });

    it('detects surface from object-form condition', () => {
      const rule: PolicyRule = {
        name: 'obj-cond',
        condition: { surface: 'api', 'agent.type': 'external' },
        ruleAction: 'deny',
      };
      expect(checker.detectSurfaces(rule)).toEqual(['api']);
    });

    it('prefers explicit surfaces over condition parsing', () => {
      const rule: PolicyRule = {
        name: 'explicit-wins',
        condition: "surface == 'cli'",
        ruleAction: 'deny',
        surfaces: ['ide', 'api'],
      };
      expect(checker.detectSurfaces(rule)).toEqual(['ide', 'api']);
    });
  });

  describe('analyzePolicies()', () => {
    it('reports no gaps for all-universal rules', () => {
      const policy = makePolicy('universal-policy', [
        { name: 'rule-a', condition: "agent.type == 'external'", ruleAction: 'deny' },
        { name: 'rule-b', condition: 'agent.risk >= 8', ruleAction: 'require_approval' },
      ]);
      const report = checker.analyzePolicies([policy]);
      expect(report.totalRules).toBe(2);
      expect(report.universalRules).toBe(2);
      expect(report.surfaceSpecificRules).toBe(0);
      expect(report.gaps).toHaveLength(0);
      expect(report.parityScore).toBe(100);
    });

    it('detects CLI-only deny rule as high severity gap', () => {
      const policy = makePolicy('cli-only-policy', [
        { name: 'block-external', condition: "surface == 'cli' and agent.type == 'external'", ruleAction: 'deny' },
      ]);
      const report = checker.analyzePolicies([policy]);
      expect(report.gaps).toHaveLength(1);
      expect(report.gaps[0].severity).toBe('high');
      expect(report.gaps[0].presentOn).toEqual(['cli']);
      expect(report.gaps[0].missingFrom).toContain('ide');
      expect(report.gaps[0].missingFrom).toContain('api');
    });

    it('no gap when all surfaces covered explicitly', () => {
      const policy = makePolicy('full-coverage', [
        { name: 'rule-cli', surfaces: ['cli'], condition: "agent.type == 'external'", ruleAction: 'deny' },
        { name: 'rule-ide', surfaces: ['ide'], condition: "agent.type == 'external'", ruleAction: 'deny' },
        { name: 'rule-api', surfaces: ['api'], condition: "agent.type == 'external'", ruleAction: 'deny' },
      ]);
      const report = checker.analyzePolicies([policy]);
      expect(report.gaps).toHaveLength(0);
    });

    it('skips disabled rules', () => {
      const policy = makePolicy('disabled-policy', [
        { name: 'disabled-rule', surfaces: ['cli'], condition: "agent.type == 'external'", ruleAction: 'deny', enabled: false },
      ]);
      const report = checker.analyzePolicies([policy]);
      expect(report.totalRules).toBe(0);
      expect(report.gaps).toHaveLength(0);
    });

    it('classifies warn/log gaps as medium severity', () => {
      const policy = makePolicy('warn-policy', [
        { name: 'warn-rule', surfaces: ['ide'], condition: 'agent.risk >= 3', ruleAction: 'warn' },
      ]);
      const report = checker.analyzePolicies([policy]);
      expect(report.gaps).toHaveLength(1);
      expect(report.gaps[0].severity).toBe('medium');
    });

    it('classifies allow gaps as low severity', () => {
      const policy = makePolicy('allow-policy', [
        { name: 'allow-rule', surfaces: ['api'], condition: 'agent.trusted', ruleAction: 'allow' },
      ]);
      const report = checker.analyzePolicies([policy]);
      expect(report.gaps).toHaveLength(1);
      expect(report.gaps[0].severity).toBe('low');
    });

    it('handles empty policies', () => {
      const report = checker.analyzePolicies([]);
      expect(report.totalRules).toBe(0);
      expect(report.gaps).toHaveLength(0);
      expect(report.parityScore).toBe(100);
    });

    it('handles policies with no rules', () => {
      const report = checker.analyzePolicies([makePolicy('empty', [])]);
      expect(report.totalRules).toBe(0);
      expect(report.parityScore).toBe(100);
    });

    it('computes surface coverage including universal rules', () => {
      const policy = makePolicy('mixed', [
        { name: 'universal', condition: 'agent.risk >= 9', ruleAction: 'deny' },
        { name: 'cli-only', surfaces: ['cli'], condition: 'agent.risk >= 5', ruleAction: 'warn' },
      ]);
      const report = checker.analyzePolicies([policy]);
      expect(report.surfaceCoverage.cli).toBe(2);
      expect(report.surfaceCoverage.ide).toBe(1);
      expect(report.surfaceCoverage.api).toBe(1);
    });

    it('analyzes across multiple policies', () => {
      const policies = [
        makePolicy('policy-a', [
          { name: 'deny-external', surfaces: ['cli'], condition: "agent.type == 'external'", ruleAction: 'deny' },
        ]),
        makePolicy('policy-b', [
          { name: 'deny-external', surfaces: ['ide'], condition: "agent.type == 'external'", ruleAction: 'deny' },
        ]),
      ];
      const report = checker.analyzePolicies(policies);
      // cli + ide covered, only api missing
      expect(report.gaps).toHaveLength(1);
      expect(report.gaps[0].missingFrom).toEqual(['api']);
    });

    it('generates recommendation with bypass warning for deny gaps', () => {
      const policy = makePolicy('test', [
        { name: 'block-untrusted', surfaces: ['cli'], condition: "trust == 'none'", ruleAction: 'deny' },
      ]);
      const report = checker.analyzePolicies([policy]);
      expect(report.gaps[0].recommendation).toContain('bypass');
    });

    it('parity score decreases with high-severity gaps', () => {
      const noGaps = checker.analyzePolicies([
        makePolicy('all-universal', [
          { name: 'r1', condition: 'agent.risk >= 9', ruleAction: 'deny' },
        ]),
      ]);
      const withGaps = checker.analyzePolicies([
        makePolicy('cli-only', [
          { name: 'r1', surfaces: ['cli'], condition: 'agent.risk >= 9', ruleAction: 'deny' },
        ]),
      ]);
      expect(noGaps.parityScore).toBeGreaterThan(withGaps.parityScore);
    });
  });
});
