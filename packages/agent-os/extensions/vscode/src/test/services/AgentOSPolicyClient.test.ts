// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import * as assert from 'assert';
import { AgentOSPolicyClient } from '../../services/AgentOSPolicyClient';
import { FakeTransport } from './FakeTransport';

suite('AgentOSPolicyClient', () => {
    const validPayload = {
        rules: [
            { id: 'r1', name: 'Block Secrets', action: 'block', pattern: '.*API_KEY.*', scope: 'file', enabled: true, evaluations_today: 100, violations_today: 2 },
        ],
        recent_violations: [
            { id: 'v1', rule_id: 'r1', rule_name: 'Block Secrets', timestamp: '2026-03-24T12:00:00Z', context: 'API_KEY=xxx', action: 'block' },
        ],
        total_evaluations_today: 615,
        total_violations_today: 3,
    };

    test('returns translated snapshot on success', async () => {
        const transport = new FakeTransport();
        transport.setNext({ ok: true, data: validPayload, durationMs: 8 });
        const client = new AgentOSPolicyClient(transport);

        const snap = await client.getSnapshot();
        assert.strictEqual(snap.rules.length, 1);
        assert.strictEqual(snap.rules[0].action, 'BLOCK');
        assert.strictEqual(snap.recentViolations.length, 1);
        assert.strictEqual(snap.totalEvaluationsToday, 615);
        assert.strictEqual(snap.totalViolationsToday, 3);
    });

    test('returns stale on failure after first success', async () => {
        const transport = new FakeTransport();
        transport.setNext({ ok: true, data: validPayload, durationMs: 8 });
        const client = new AgentOSPolicyClient(transport);

        const first = await client.getSnapshot();
        assert.strictEqual(first.totalEvaluationsToday, 615);

        transport.setNext({ ok: false, data: undefined, error: 'timeout', durationMs: 5000 });
        const stale = await client.getSnapshot();
        assert.strictEqual(stale.totalEvaluationsToday, 615);
        assert.strictEqual(stale.rules[0].name, 'Block Secrets');
    });

    test('throws when no prior data and transport fails', async () => {
        const transport = new FakeTransport();
        transport.setNext({ ok: false, data: undefined, error: 'not found', durationMs: 0 });
        const client = new AgentOSPolicyClient(transport);

        await assert.rejects(
            () => client.getSnapshot(),
            (err: Error) => err.message.includes('not found'),
        );
    });
});
