// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Translator Tests
 *
 * Pure function tests — no I/O, no mocks. Validates that REST response
 * shapes are correctly mapped, invalid input is rejected, and size
 * limits are enforced.
 */

import * as assert from 'assert';
import { translateSLO, translateTopology, translatePolicy } from '../../services/translators';

suite('translateSLO', () => {
    test('valid snapshot returns typed SLOSnapshot', () => {
        const result = translateSLO({ sli: { passRate: 0.97, totalDecisions: 200 } });
        assert.ok(result);
        assert.strictEqual(result.policyCompliance.compliancePercent, 97);
        assert.strictEqual(result.policyCompliance.totalEvaluations, 200);
        assert.ok(result.fetchedAt);
    });
    test('pass_rate 0.0 maps to compliancePercent 0', () => {
        const result = translateSLO({ sli: { passRate: 0.0 } });
        assert.ok(result);
        assert.strictEqual(result.policyCompliance.compliancePercent, 0);
    });
    test('pass_rate 1.0 maps to compliancePercent 100', () => {
        const result = translateSLO({ sli: { passRate: 1.0 } });
        assert.ok(result);
        assert.strictEqual(result.policyCompliance.compliancePercent, 100);
    });
    test('missing sli key returns zero-value SLO (not null)', () => {
        const result = translateSLO({});
        assert.ok(result);
        assert.strictEqual(result.policyCompliance.totalEvaluations, 0);
    });
    test('negative pass_rate rejected', () => {
        assert.strictEqual(translateSLO({ sli: { passRate: -0.5 } }), null);
    });
    test('non-object input returns null', () => {
        assert.strictEqual(translateSLO('string'), null);
        assert.strictEqual(translateSLO(42), null);
        assert.strictEqual(translateSLO(null), null);
        assert.strictEqual(translateSLO(undefined), null);
        assert.strictEqual(translateSLO([1, 2]), null);
    });
    test('Infinity/NaN in pass_rate rejected', () => {
        assert.strictEqual(translateSLO({ sli: { passRate: Infinity } }), null);
        assert.strictEqual(translateSLO({ sli: { passRate: NaN } }), null);
    });
    test('snake_case keys accepted', () => {
        const result = translateSLO({ sli: { pass_rate: 0.9, total_decisions: 50 } });
        assert.ok(result);
        assert.strictEqual(result.policyCompliance.compliancePercent, 90);
        assert.strictEqual(result.policyCompliance.totalEvaluations, 50);
    });
    test('missing pass_rate yields zero compliance (not phantom violations)', () => {
        const result = translateSLO({ sli: { totalDecisions: 100 } });
        assert.ok(result);
        assert.strictEqual(result.policyCompliance.compliancePercent, 0);
        assert.strictEqual(result.policyCompliance.violationsToday, 0);
    });
    test('availability and latency are zero (not fabricated)', () => {
        const result = translateSLO({ sli: { passRate: 0.95 } });
        assert.ok(result);
        assert.strictEqual(result.availability.currentPercent, 0);
        assert.strictEqual(result.latency.p99Ms, 0);
        assert.strictEqual(result.trustScore.meanScore, 0);
    });
});

suite('translateTopology', () => {
    test('valid fleet maps to AgentNode[]', () => {
        const result = translateTopology({
            fleet: [{ agentId: 'agent-1', successRate: 0.85, circuitState: 'closed', taskCount: 10 }],
        });
        assert.strictEqual(result.length, 1);
        assert.strictEqual(result[0].did, 'agent-1');
        assert.strictEqual(result[0].trustScore, 850);
        assert.strictEqual(result[0].circuitState, 'closed');
        assert.strictEqual(result[0].taskCount, 10);
    });
    test('empty fleet returns empty array', () => {
        assert.deepStrictEqual(translateTopology({ fleet: [] }), []);
    });
    test('agent with missing agentId is skipped', () => {
        const result = translateTopology({ fleet: [{ successRate: 0.5 }] });
        assert.strictEqual(result.length, 0);
    });
    test('fleet capped at 1000 agents', () => {
        const fleet = Array.from({ length: 1500 }, (_, i) => ({ agentId: `a-${i}`, successRate: 0.5 }));
        const result = translateTopology({ fleet });
        assert.strictEqual(result.length, 1000);
    });
    test('long DID strings truncated at 500 chars', () => {
        const longDid = 'x'.repeat(600);
        const result = translateTopology({ fleet: [{ agentId: longDid, successRate: 0.5 }] });
        assert.strictEqual(result[0].did.length, 500);
    });
    test('success_rate maps to trustScore 0-1000', () => {
        const result = translateTopology({ fleet: [{ agentId: 'a', successRate: 0.0 }] });
        assert.strictEqual(result[0].trustScore, 0);
    });
    test('invalid circuit_state defaults to closed', () => {
        const result = translateTopology({ fleet: [{ agentId: 'a', successRate: 0.5, circuitState: 'invalid' }] });
        assert.strictEqual(result[0].circuitState, 'closed');
    });
    test('non-object input returns empty array', () => {
        assert.deepStrictEqual(translateTopology(null), []);
        assert.deepStrictEqual(translateTopology('bad'), []);
    });
    test('accepts agents key (from /sre/fleet)', () => {
        const result = translateTopology({ agents: [{ agentId: 'b', successRate: 0.9 }] });
        assert.strictEqual(result.length, 1);
    });
    test('optional fields populated when present', () => {
        const result = translateTopology({
            fleet: [{ agentId: 'a', successRate: 0.8, taskCount: 42, avgLatencyMs: 150, trustStage: 'IBT' }],
        });
        assert.strictEqual(result[0].taskCount, 42);
        assert.strictEqual(result[0].avgLatencyMs, 150);
        assert.strictEqual(result[0].trustStage, 'IBT');
    });
    test('optional fields absent when not provided', () => {
        const result = translateTopology({ fleet: [{ agentId: 'a', successRate: 0.5 }] });
        assert.strictEqual(result[0].taskCount, undefined);
        assert.strictEqual(result[0].avgLatencyMs, undefined);
        assert.strictEqual(result[0].trustStage, undefined);
    });
    test('snake_case keys accepted for fleet agents', () => {
        const result = translateTopology({ fleet: [{ agent_id: 'x', success_rate: 0.7 }] });
        assert.strictEqual(result.length, 1);
        assert.strictEqual(result[0].did, 'x');
        assert.strictEqual(result[0].trustScore, 700);
    });
});

suite('translatePolicy', () => {
    test('valid policies maps to PolicyRule[]', () => {
        const result = translatePolicy({
            policies: [{ name: 'no-secrets', action: 'DENY', pattern: '*.key' }],
            auditEvents: [],
        });
        assert.strictEqual(result.rules.length, 1);
        assert.strictEqual(result.rules[0].name, 'no-secrets');
        assert.strictEqual(result.rules[0].action, 'DENY');
    });
    test('empty policies returns empty snapshot (not null)', () => {
        const result = translatePolicy({});
        assert.ok(result);
        assert.strictEqual(result.rules.length, 0);
        assert.strictEqual(result.totalEvaluationsToday, 0);
    });
    test('unknown action defaults to AUDIT', () => {
        const result = translatePolicy({ policies: [{ name: 'test', action: 'UNKNOWN' }] });
        assert.strictEqual(result.rules[0].action, 'AUDIT');
    });
    test('policies capped at 200', () => {
        const policies = Array.from({ length: 300 }, (_, i) => ({ name: `p-${i}` }));
        const result = translatePolicy({ policies });
        assert.strictEqual(result.rules.length, 200);
    });
    test('auditEvents capped at 500', () => {
        const auditEvents = Array.from({ length: 600 }, (_, i) => ({ id: `e-${i}` }));
        const result = translatePolicy({ auditEvents });
        assert.strictEqual(result.recentViolations.length, 500);
    });
    test('asiCoverage preserved when present', () => {
        const asi = { 'ASI-01': { label: 'Intent', covered: true, feature: 'Interceptor' } };
        const result = translatePolicy({ asiCoverage: asi });
        assert.deepStrictEqual(result.asiCoverage, asi);
    });
    test('non-object input returns empty snapshot', () => {
        const result = translatePolicy(null);
        assert.strictEqual(result.rules.length, 0);
    });
    test('fetchedAt is set', () => {
        const result = translatePolicy({});
        assert.ok(result.fetchedAt);
    });
});
