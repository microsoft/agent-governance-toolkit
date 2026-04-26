// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Mock Policy Backend Unit Tests
 */

import * as assert from 'assert';
import { createMockPolicyBackend } from '../../mockBackend/MockPolicyBackend';

suite('MockPolicyBackend Test Suite', () => {
    test('Returns 5 default rules', async () => {
        const backend = createMockPolicyBackend();
        const snapshot = await backend.getSnapshot();
        assert.strictEqual(snapshot.rules.length, 5);
    });

    test('All rules have required fields', async () => {
        const backend = createMockPolicyBackend();
        const snapshot = await backend.getSnapshot();

        snapshot.rules.forEach(rule => {
            assert.ok(rule.id, 'Rule should have id');
            assert.ok(rule.name, 'Rule should have name');
            assert.ok(rule.description !== undefined, 'Rule should have description');
            assert.ok(['ALLOW', 'DENY', 'AUDIT', 'BLOCK'].includes(rule.action));
            assert.ok(rule.pattern !== undefined, 'Rule should have pattern');
            assert.ok(['file', 'tool', 'agent', 'global'].includes(rule.scope));
            assert.ok(typeof rule.enabled === 'boolean');
            assert.ok(typeof rule.evaluationsToday === 'number');
            assert.ok(typeof rule.violationsToday === 'number');
        });
    });

    test('Returns recent violations', async () => {
        const backend = createMockPolicyBackend();
        const snapshot = await backend.getSnapshot();
        assert.ok(snapshot.recentViolations.length > 0, 'Should have recent violations');

        snapshot.recentViolations.forEach(v => {
            assert.ok(v.id, 'Violation should have id');
            assert.ok(v.ruleId, 'Violation should have ruleId');
            assert.ok(v.ruleName, 'Violation should have ruleName');
            assert.ok(v.timestamp, 'Violation should have timestamp');
            assert.ok(v.context, 'Violation should have context');
        });
    });

    test('Evaluation counts are at least the base values', async () => {
        const backend = createMockPolicyBackend();
        const snapshot = await backend.getSnapshot();
        const total = snapshot.rules.reduce((s, r) => s + r.evaluationsToday, 0);
        // Base: 342 + 156 + 28 + 89 + 0 = 615. Random adds 0-4 per enabled rule.
        assert.ok(total >= 615, `Total evaluations should be >= base (615), got ${total}`);
    });

    test('Totals match rule sums', async () => {
        const backend = createMockPolicyBackend();
        const snapshot = await backend.getSnapshot();

        const evalSum = snapshot.rules.reduce((s, r) => s + r.evaluationsToday, 0);
        const violSum = snapshot.rules.reduce((s, r) => s + r.violationsToday, 0);

        assert.strictEqual(snapshot.totalEvaluationsToday, evalSum);
        assert.strictEqual(snapshot.totalViolationsToday, violSum);
    });

    test('Disabled rule has zero counts', async () => {
        const backend = createMockPolicyBackend();
        const snapshot = await backend.getSnapshot();

        const disabledRule = snapshot.rules.find(r => !r.enabled);
        assert.ok(disabledRule, 'Should have at least one disabled rule');
        assert.strictEqual(disabledRule.evaluationsToday, 0);
        assert.strictEqual(disabledRule.violationsToday, 0);
    });
});
