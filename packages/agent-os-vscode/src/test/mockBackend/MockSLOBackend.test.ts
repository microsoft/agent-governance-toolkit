// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Unit tests for MockSLOBackend.
 *
 * Validates the shape, bounds, and drift behavior of the simulated SLO data feed.
 */

import * as assert from 'assert';
import { createMockSLOBackend } from '../../mockBackend/MockSLOBackend';

suite('MockSLOBackend Test Suite', () => {
    test('returns SLOSnapshot with all 4 required sections', async () => {
        const backend = createMockSLOBackend();
        const snapshot = await backend.getSnapshot();

        assert.ok(snapshot.availability, 'snapshot should have availability');
        assert.ok(snapshot.latency, 'snapshot should have latency');
        assert.ok(snapshot.policyCompliance, 'snapshot should have policyCompliance');
        assert.ok(snapshot.trustScore, 'snapshot should have trustScore');
    });

    test('availability currentPercent is between 90 and 100', async () => {
        const backend = createMockSLOBackend();
        for (let i = 0; i < 10; i++) {
            const snapshot = await backend.getSnapshot();
            const val = snapshot.availability.currentPercent;
            assert.ok(val >= 90 && val <= 100,
                `availability currentPercent ${val} should be between 90 and 100`);
        }
    });

    test('availability targetPercent is a positive number', async () => {
        const backend = createMockSLOBackend();
        const snapshot = await backend.getSnapshot();
        assert.ok(typeof snapshot.availability.targetPercent === 'number');
        assert.ok(snapshot.availability.targetPercent > 0,
            `targetPercent ${snapshot.availability.targetPercent} should be positive`);
    });

    test('latency P50 <= P95 <= P99 invariant holds over 10 calls', async () => {
        const backend = createMockSLOBackend();
        for (let i = 0; i < 10; i++) {
            const snapshot = await backend.getSnapshot();
            const { p50Ms, p95Ms, p99Ms } = snapshot.latency;
            assert.ok(p50Ms <= p95Ms,
                `Call ${i}: p50 (${p50Ms}) should be <= p95 (${p95Ms})`);
            assert.ok(p95Ms <= p99Ms,
                `Call ${i}: p95 (${p95Ms}) should be <= p99 (${p99Ms})`);
        }
    });

    test('latency targetMs is positive', async () => {
        const backend = createMockSLOBackend();
        const snapshot = await backend.getSnapshot();
        assert.ok(snapshot.latency.targetMs > 0,
            `targetMs ${snapshot.latency.targetMs} should be positive`);
    });

    test('error budget remaining is between 0 and 100', async () => {
        const backend = createMockSLOBackend();
        for (let i = 0; i < 5; i++) {
            const snapshot = await backend.getSnapshot();
            const val = snapshot.availability.errorBudgetRemainingPercent;
            assert.ok(val >= 0 && val <= 100,
                `errorBudgetRemainingPercent ${val} should be between 0 and 100`);
        }
    });

    test('burn rate is positive', async () => {
        const backend = createMockSLOBackend();
        for (let i = 0; i < 5; i++) {
            const snapshot = await backend.getSnapshot();
            assert.ok(snapshot.availability.burnRate > 0,
                `burnRate ${snapshot.availability.burnRate} should be positive`);
        }
    });

    test('trust score meanScore is between 0 and 1000', async () => {
        const backend = createMockSLOBackend();
        for (let i = 0; i < 5; i++) {
            const snapshot = await backend.getSnapshot();
            const val = snapshot.trustScore.meanScore;
            assert.ok(val >= 0 && val <= 1000,
                `meanScore ${val} should be between 0 and 1000`);
        }
    });

    test('trust score distribution has exactly 4 elements', async () => {
        const backend = createMockSLOBackend();
        const snapshot = await backend.getSnapshot();
        assert.strictEqual(snapshot.trustScore.distribution.length, 4,
            'distribution should have exactly 4 buckets');
    });

    test('trust score distribution elements are non-negative', async () => {
        const backend = createMockSLOBackend();
        const snapshot = await backend.getSnapshot();
        for (let i = 0; i < snapshot.trustScore.distribution.length; i++) {
            assert.ok(snapshot.trustScore.distribution[i] >= 0,
                `distribution[${i}] = ${snapshot.trustScore.distribution[i]} should be >= 0`);
        }
    });

    test('values drift between consecutive calls (not all identical)', async () => {
        const backend = createMockSLOBackend();
        const first = await backend.getSnapshot();
        let drifted = false;
        for (let i = 0; i < 20; i++) {
            const next = await backend.getSnapshot();
            if (next.availability.currentPercent !== first.availability.currentPercent ||
                next.latency.p50Ms !== first.latency.p50Ms ||
                next.trustScore.meanScore !== first.trustScore.meanScore) {
                drifted = true;
                break;
            }
        }
        assert.ok(drifted, 'Values should drift between consecutive calls');
    });

    test('policy compliance percent is between 0 and 100', async () => {
        const backend = createMockSLOBackend();
        for (let i = 0; i < 5; i++) {
            const snapshot = await backend.getSnapshot();
            const val = snapshot.policyCompliance.compliancePercent;
            assert.ok(val >= 0 && val <= 100,
                `compliancePercent ${val} should be between 0 and 100`);
        }
    });

    test('policy compliance totalEvaluations increases over calls', async () => {
        const backend = createMockSLOBackend();
        const first = await backend.getSnapshot();
        const second = await backend.getSnapshot();
        assert.ok(second.policyCompliance.totalEvaluations >= first.policyCompliance.totalEvaluations,
            'totalEvaluations should not decrease between calls');
    });

    test('policy compliance trend is one of up, down, stable', async () => {
        const backend = createMockSLOBackend();
        const snapshot = await backend.getSnapshot();
        assert.ok(
            ['up', 'down', 'stable'].includes(snapshot.policyCompliance.trend),
            `trend "${snapshot.policyCompliance.trend}" should be up, down, or stable`,
        );
    });

    test('latency errorBudgetRemainingPercent is between 0 and 100', async () => {
        const backend = createMockSLOBackend();
        for (let i = 0; i < 5; i++) {
            const snapshot = await backend.getSnapshot();
            const val = snapshot.latency.errorBudgetRemainingPercent;
            assert.ok(val >= 0 && val <= 100,
                `latency errorBudgetRemainingPercent ${val} should be between 0 and 100`);
        }
    });
});
