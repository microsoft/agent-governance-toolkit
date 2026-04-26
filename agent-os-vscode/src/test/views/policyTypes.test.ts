// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Policy Types Unit Tests
 */

import * as assert from 'assert';
import {
    PolicyAction,
    PolicyRule,
    PolicyViolation,
    PolicySnapshot
} from '../../views/policyTypes';

suite('PolicyTypes Test Suite', () => {
    test('PolicyRule accepts all action types', () => {
        const actions: PolicyAction[] = ['ALLOW', 'DENY', 'AUDIT', 'BLOCK'];
        actions.forEach(action => {
            const rule: PolicyRule = {
                id: 'test-rule',
                name: 'Test Rule',
                description: 'A test rule',
                action,
                pattern: '.*',
                scope: 'file',
                enabled: true,
                evaluationsToday: 0,
                violationsToday: 0,
            };
            assert.strictEqual(rule.action, action);
        });
    });

    test('PolicyViolation can be created with file context', () => {
        const violation: PolicyViolation = {
            id: 'viol-1',
            ruleId: 'rule-1',
            ruleName: 'Test Rule',
            timestamp: new Date(),
            file: 'src/test.ts',
            line: 42,
            context: 'API_KEY = "secret"',
            action: 'BLOCK',
        };
        assert.strictEqual(violation.file, 'src/test.ts');
        assert.strictEqual(violation.line, 42);
        assert.strictEqual(violation.agentDid, undefined);
    });

    test('PolicyViolation can be created with agent context', () => {
        const violation: PolicyViolation = {
            id: 'viol-2',
            ruleId: 'rule-2',
            ruleName: 'Shell Block',
            timestamp: new Date(),
            agentDid: 'did:mesh:abc123',
            context: 'exec("rm -rf /")',
            action: 'DENY',
        };
        assert.strictEqual(violation.agentDid, 'did:mesh:abc123');
        assert.strictEqual(violation.file, undefined);
    });

    test('PolicySnapshot aggregates totals correctly', () => {
        const rules: PolicyRule[] = [
            {
                id: 'r1', name: 'Rule 1', description: '', action: 'ALLOW',
                pattern: '', scope: 'file', enabled: true,
                evaluationsToday: 100, violationsToday: 2
            },
            {
                id: 'r2', name: 'Rule 2', description: '', action: 'DENY',
                pattern: '', scope: 'tool', enabled: true,
                evaluationsToday: 50, violationsToday: 3
            },
        ];

        const snapshot: PolicySnapshot = {
            rules,
            recentViolations: [],
            totalEvaluationsToday: rules.reduce((s, r) => s + r.evaluationsToday, 0),
            totalViolationsToday: rules.reduce((s, r) => s + r.violationsToday, 0),
        };

        assert.strictEqual(snapshot.totalEvaluationsToday, 150);
        assert.strictEqual(snapshot.totalViolationsToday, 5);
    });

    test('PolicyRule scope types are exhaustive', () => {
        const scopes: Array<PolicyRule['scope']> = ['file', 'tool', 'agent', 'global'];
        scopes.forEach(scope => {
            const rule: PolicyRule = {
                id: 'test', name: 'Test', description: '',
                action: 'AUDIT', pattern: '', scope, enabled: true,
                evaluationsToday: 0, violationsToday: 0
            };
            assert.strictEqual(rule.scope, scope);
        });
    });
});
