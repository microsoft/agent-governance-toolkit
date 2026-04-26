// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Unit tests for sidebar health color functions.
 *
 * Tests pure functions with no React or VS Code dependencies:
 * percentColor, latencyColor, trustColor from SLOSummary.
 */

import * as assert from 'assert';
import {
    percentColor,
    latencyColor,
    trustColor,
} from '../../webviews/sidebar/healthColors';

suite('SLOSummary — percentColor', () => {
    test('returns success when value meets target', () => {
        assert.strictEqual(percentColor(99.8, 99.5), 'text-ml-success');
    });

    test('returns success when value exactly equals target', () => {
        assert.strictEqual(percentColor(99.5, 99.5), 'text-ml-success');
    });

    test('returns warning when within 1% below target', () => {
        assert.strictEqual(percentColor(99.0, 99.5), 'text-ml-warning');
    });

    test('returns error when more than 1% below target', () => {
        assert.strictEqual(percentColor(97.0, 99.5), 'text-ml-error');
    });

    test('returns warning at exact boundary (target - 1)', () => {
        assert.strictEqual(percentColor(98.5, 99.5), 'text-ml-warning');
    });

    test('returns error just below warning boundary', () => {
        // 99.5 - 1 = 98.5, so 98.4 should be error
        assert.strictEqual(percentColor(98.4, 99.5), 'text-ml-error');
    });
});

suite('SLOSummary — latencyColor', () => {
    test('returns success when latency is at or below target', () => {
        assert.strictEqual(latencyColor(100, 200), 'text-ml-success');
    });

    test('returns success when latency exactly equals target', () => {
        assert.strictEqual(latencyColor(200, 200), 'text-ml-success');
    });

    test('returns warning when latency is within 20% above target', () => {
        assert.strictEqual(latencyColor(220, 200), 'text-ml-warning');
    });

    test('returns warning at exact 1.2x boundary', () => {
        assert.strictEqual(latencyColor(240, 200), 'text-ml-warning');
    });

    test('returns error when latency exceeds 1.2x target', () => {
        assert.strictEqual(latencyColor(241, 200), 'text-ml-error');
    });

    test('returns success for zero latency', () => {
        assert.strictEqual(latencyColor(0, 200), 'text-ml-success');
    });
});

suite('SLOSummary — trustColor', () => {
    test('returns success for trust >= 750', () => {
        assert.strictEqual(trustColor(750), 'text-ml-success');
    });

    test('returns success for trust of 1000', () => {
        assert.strictEqual(trustColor(1000), 'text-ml-success');
    });

    test('returns warning for trust 400-749', () => {
        assert.strictEqual(trustColor(749), 'text-ml-warning');
        assert.strictEqual(trustColor(400), 'text-ml-warning');
    });

    test('returns error for trust below 400', () => {
        assert.strictEqual(trustColor(399), 'text-ml-error');
        assert.strictEqual(trustColor(0), 'text-ml-error');
    });
});
