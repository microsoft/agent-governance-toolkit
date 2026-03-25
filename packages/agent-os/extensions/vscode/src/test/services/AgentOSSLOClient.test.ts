// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import * as assert from 'assert';
import { AgentOSSLOClient } from '../../services/AgentOSSLOClient';
import { FakeTransport } from './FakeTransport';

suite('AgentOSSLOClient', () => {
    const validPayload = {
        task_success_rate: { value: 0.999, target: 0.995 },
        response_latency: { p50: 100, p95: 300, p99: 800, target: 5000 },
        policy_compliance: { value: 0.998, target: 1.0, compliance: 0.998 },
        trust_scores: { mean: 700, min: 300, below_threshold: 2, distribution: [1, 3, 10, 20] },
    };

    test('returns translated snapshot on successful query', async () => {
        const transport = new FakeTransport();
        transport.setNext({ ok: true, data: validPayload, durationMs: 10 });
        const client = new AgentOSSLOClient(transport);

        const snap = await client.getSnapshot();
        assert.strictEqual(snap.availability.currentPercent, 99.9);
        assert.strictEqual(snap.latency.p50Ms, 100);
        assert.strictEqual(snap.trustScore.meanScore, 700);
    });

    test('returns stale snapshot when transport fails after first success', async () => {
        const transport = new FakeTransport();
        transport.setNext({ ok: true, data: validPayload, durationMs: 10 });
        const client = new AgentOSSLOClient(transport);

        const first = await client.getSnapshot();
        assert.strictEqual(first.trustScore.meanScore, 700);

        transport.setNext({ ok: false, data: undefined, error: 'timeout', durationMs: 5000 });
        const stale = await client.getSnapshot();
        assert.strictEqual(stale.trustScore.meanScore, 700);
    });

    test('throws when transport fails with no prior snapshot', async () => {
        const transport = new FakeTransport();
        transport.setNext({ ok: false, data: undefined, error: 'connection refused', durationMs: 0 });
        const client = new AgentOSSLOClient(transport);

        await assert.rejects(
            () => client.getSnapshot(),
            (err: Error) => err.message.includes('connection refused'),
        );
    });
});
