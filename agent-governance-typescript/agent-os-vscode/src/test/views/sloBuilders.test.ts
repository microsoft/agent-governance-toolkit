// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Unit tests for pure health assessment functions in sloBuilders.ts.
 *
 * Only tests pure functions that have no VS Code API dependency.
 * Builder functions (buildAvailability, etc.) are skipped because they
 * create VS Code TreeItem objects.
 */

import * as assert from 'assert';
import {
    percentHealth,
    budgetHealth,
    burnRateHealth,
    latencyHealth,
    trustScoreHealth,
    trendArrow,
    violationCountHealth,
    thresholdCountHealth,
} from '../../views/sloBuilders';

suite('sloBuilders — percentHealth', () => {
    test('returns healthy when current meets target', () => {
        assert.strictEqual(percentHealth(99.8, 99.5), 'healthy');
    });

    test('returns healthy when current exactly equals target', () => {
        assert.strictEqual(percentHealth(99.5, 99.5), 'healthy');
    });

    test('returns warning when within 0.5% band below target', () => {
        // target * 0.005 = 99.5 * 0.005 = 0.4975
        // threshold = 99.5 - 0.4975 = 99.0025
        assert.strictEqual(percentHealth(99.4, 99.5), 'warning');
    });

    test('returns breached when well below target', () => {
        assert.strictEqual(percentHealth(98.0, 99.5), 'breached');
    });

    test('returns breached at the warning boundary edge', () => {
        // target - target*0.005 = 99.5 - 0.4975 = 99.0025
        // 99.0 < 99.0025 so breached
        assert.strictEqual(percentHealth(99.0, 99.5), 'breached');
    });
});

suite('sloBuilders — budgetHealth', () => {
    test('returns healthy when budget is above 30%', () => {
        assert.strictEqual(budgetHealth(50), 'healthy');
    });

    test('returns warning when budget is between 10% and 30%', () => {
        assert.strictEqual(budgetHealth(15), 'warning');
    });

    test('returns breached when budget is 10% or below', () => {
        assert.strictEqual(budgetHealth(5), 'breached');
    });

    test('returns warning at exactly 30% (boundary: not > 30)', () => {
        assert.strictEqual(budgetHealth(30), 'warning');
    });

    test('returns breached at exactly 10% (boundary: not > 10)', () => {
        assert.strictEqual(budgetHealth(10), 'breached');
    });

    test('returns healthy at 31%', () => {
        assert.strictEqual(budgetHealth(31), 'healthy');
    });
});

suite('sloBuilders — burnRateHealth', () => {
    test('returns healthy when rate is below 1.0', () => {
        assert.strictEqual(burnRateHealth(0.8), 'healthy');
    });

    test('returns healthy at exactly 1.0 (boundary: <= 1.0)', () => {
        assert.strictEqual(burnRateHealth(1.0), 'healthy');
    });

    test('returns warning when rate is between 1.0 and 2.0', () => {
        assert.strictEqual(burnRateHealth(1.5), 'warning');
    });

    test('returns warning at exactly 2.0 (boundary: <= 2.0)', () => {
        assert.strictEqual(burnRateHealth(2.0), 'warning');
    });

    test('returns breached when rate exceeds 2.0', () => {
        assert.strictEqual(burnRateHealth(3.0), 'breached');
    });
});

suite('sloBuilders — latencyHealth', () => {
    test('returns healthy when value is well below 75% of target', () => {
        assert.strictEqual(latencyHealth(100, 300), 'healthy');
    });

    test('returns healthy at exactly 75% of target (boundary: <= 0.75)', () => {
        assert.strictEqual(latencyHealth(225, 300), 'healthy');
    });

    test('returns warning when value is between 75% and 100% of target', () => {
        assert.strictEqual(latencyHealth(280, 300), 'warning');
    });

    test('returns warning at exactly target (boundary: <= target)', () => {
        assert.strictEqual(latencyHealth(300, 300), 'warning');
    });

    test('returns breached when value exceeds target', () => {
        assert.strictEqual(latencyHealth(400, 300), 'breached');
    });
});

suite('sloBuilders — trustScoreHealth', () => {
    test('returns healthy when score is 800', () => {
        assert.strictEqual(trustScoreHealth(800), 'healthy');
    });

    test('returns healthy at exactly 700 (boundary: >= 700)', () => {
        assert.strictEqual(trustScoreHealth(700), 'healthy');
    });

    test('returns warning when score is 600', () => {
        assert.strictEqual(trustScoreHealth(600), 'warning');
    });

    test('returns warning at exactly 500 (boundary: >= 500)', () => {
        assert.strictEqual(trustScoreHealth(500), 'warning');
    });

    test('returns breached when score is 300', () => {
        assert.strictEqual(trustScoreHealth(300), 'breached');
    });

    test('returns breached at 499', () => {
        assert.strictEqual(trustScoreHealth(499), 'breached');
    });
});

suite('sloBuilders — trendArrow', () => {
    test('returns up arrow for up trend', () => {
        assert.ok(trendArrow('up').includes('\u2191'));
    });

    test('returns down arrow for down trend', () => {
        assert.ok(trendArrow('down').includes('\u2193'));
    });

    test('returns right arrow for stable trend', () => {
        assert.ok(trendArrow('stable').includes('\u2192'));
    });
});

suite('sloBuilders — violationCountHealth', () => {
    test('returns healthy when count is 0', () => {
        assert.strictEqual(violationCountHealth(0), 'healthy');
    });

    test('returns warning when count is between 1 and 5', () => {
        assert.strictEqual(violationCountHealth(3), 'warning');
    });

    test('returns warning at exactly 5 (boundary: <= 5)', () => {
        assert.strictEqual(violationCountHealth(5), 'warning');
    });

    test('returns breached when count exceeds 5', () => {
        assert.strictEqual(violationCountHealth(6), 'breached');
    });
});

suite('sloBuilders — thresholdCountHealth', () => {
    test('returns healthy when count is 0', () => {
        assert.strictEqual(thresholdCountHealth(0), 'healthy');
    });

    test('returns warning when count is between 1 and 2', () => {
        assert.strictEqual(thresholdCountHealth(1), 'warning');
    });

    test('returns warning at exactly 2 (boundary: <= 2)', () => {
        assert.strictEqual(thresholdCountHealth(2), 'warning');
    });

    test('returns breached when count exceeds 2', () => {
        assert.strictEqual(thresholdCountHealth(3), 'breached');
    });
});
