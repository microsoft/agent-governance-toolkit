// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { PolicyEngine } from '../src/policy';
import { PolicyRule } from '../src/types';
import { writeFileSync, unlinkSync, mkdtempSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

describe('PolicyEngine', () => {
  describe('evaluate()', () => {
    it('returns deny by default when no rules match', () => {
      const engine = new PolicyEngine();
      expect(engine.evaluate('some.action')).toBe('deny');
    });

    it('matches exact action names', () => {
      const engine = new PolicyEngine([
        { action: 'data.read', effect: 'allow' },
      ]);
      expect(engine.evaluate('data.read')).toBe('allow');
      expect(engine.evaluate('data.write')).toBe('deny');
    });

    it('matches wildcard (*) rules', () => {
      const engine = new PolicyEngine([
        { action: '*', effect: 'allow' },
      ]);
      expect(engine.evaluate('anything')).toBe('allow');
    });

    it('matches prefix wildcard (action.*)', () => {
      const engine = new PolicyEngine([
        { action: 'data.*', effect: 'allow' },
      ]);
      expect(engine.evaluate('data.read')).toBe('allow');
      expect(engine.evaluate('data.write')).toBe('allow');
      expect(engine.evaluate('data')).toBe('allow');
      expect(engine.evaluate('network.call')).toBe('deny');
    });

    it('evaluates rules in order (first match wins)', () => {
      const engine = new PolicyEngine([
        { action: 'data.delete', effect: 'deny' },
        { action: 'data.*', effect: 'allow' },
      ]);
      expect(engine.evaluate('data.delete')).toBe('deny');
      expect(engine.evaluate('data.read')).toBe('allow');
    });

    it('supports the review decision', () => {
      const engine = new PolicyEngine([
        { action: 'sensitive.op', effect: 'review' },
      ]);
      expect(engine.evaluate('sensitive.op')).toBe('review');
    });
  });

  describe('conditions', () => {
    it('matches when all conditions are met', () => {
      const engine = new PolicyEngine([
        {
          action: 'data.read',
          effect: 'allow',
          conditions: { role: 'admin' },
        },
      ]);
      expect(engine.evaluate('data.read', { role: 'admin' })).toBe('allow');
    });

    it('rejects when conditions are not met', () => {
      const engine = new PolicyEngine([
        {
          action: 'data.read',
          effect: 'allow',
          conditions: { role: 'admin' },
        },
      ]);
      expect(engine.evaluate('data.read', { role: 'user' })).toBe('deny');
    });

    it('handles multiple conditions', () => {
      const engine = new PolicyEngine([
        {
          action: 'data.write',
          effect: 'allow',
          conditions: { role: 'admin', env: 'production' },
        },
      ]);
      expect(engine.evaluate('data.write', { role: 'admin', env: 'production' })).toBe('allow');
      expect(engine.evaluate('data.write', { role: 'admin', env: 'staging' })).toBe('deny');
    });
  });

  describe('addRule()', () => {
    it('adds a rule that is evaluated', () => {
      const engine = new PolicyEngine();
      engine.addRule({ action: 'new.action', effect: 'allow' });
      expect(engine.evaluate('new.action')).toBe('allow');
    });

    it('appends to existing rules', () => {
      const engine = new PolicyEngine([
        { action: 'first', effect: 'deny' },
      ]);
      engine.addRule({ action: 'second', effect: 'allow' });
      expect(engine.getRules()).toHaveLength(2);
    });
  });

  describe('loadFromYAML()', () => {
    let tempDir: string;
    let yamlPath: string;

    beforeEach(() => {
      tempDir = mkdtempSync(join(tmpdir(), 'policy-test-'));
      yamlPath = join(tempDir, 'policy.yaml');
    });

    afterEach(() => {
      try { unlinkSync(yamlPath); } catch { /* ignore */ }
    });

    it('loads rules from a YAML file', async () => {
      writeFileSync(
        yamlPath,
        `rules:
  - action: "file.read"
    effect: "allow"
  - action: "file.delete"
    effect: "deny"
`,
      );

      const engine = new PolicyEngine();
      await engine.loadFromYAML(yamlPath);

      expect(engine.evaluate('file.read')).toBe('allow');
      expect(engine.evaluate('file.delete')).toBe('deny');
    });

    it('appends YAML rules to existing rules', async () => {
      writeFileSync(
        yamlPath,
        `rules:
  - action: "extra"
    effect: "review"
`,
      );

      const engine = new PolicyEngine([
        { action: 'existing', effect: 'allow' },
      ]);
      await engine.loadFromYAML(yamlPath);

      expect(engine.getRules()).toHaveLength(2);
      expect(engine.evaluate('extra')).toBe('review');
    });
  });
});
