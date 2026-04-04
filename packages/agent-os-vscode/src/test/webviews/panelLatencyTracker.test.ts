// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import * as assert from 'assert';
import {
    createTiming, recordDuration, averageDuration,
    shouldIsolate, shouldRejoin, markIsolated, markRejoined,
    recordFastTick, resetFastTick,
} from '../../webviews/sidebar/panelLatencyTracker';

suite('PanelLatencyTracker', () => {
    test('createTiming returns clean defaults', () => {
        const t = createTiming();
        assert.deepStrictEqual(t.durations, []);
        assert.strictEqual(t.isolated, false);
        assert.strictEqual(t.consecutiveFast, 0);
    });

    test('recordDuration appends to rolling window', () => {
        let t = createTiming();
        t = recordDuration(t, 100);
        t = recordDuration(t, 200);
        assert.deepStrictEqual(t.durations, [100, 200]);
    });

    test('recordDuration caps at 5 entries', () => {
        let t = createTiming();
        for (let i = 1; i <= 7; i++) { t = recordDuration(t, i * 100); }
        assert.strictEqual(t.durations.length, 5);
        assert.deepStrictEqual(t.durations, [300, 400, 500, 600, 700]);
    });

    test('recordDuration does not mutate input', () => {
        const original = createTiming();
        const updated = recordDuration(original, 100);
        assert.deepStrictEqual(original.durations, []);
        assert.deepStrictEqual(updated.durations, [100]);
    });

    test('averageDuration returns 0 for empty window', () => {
        assert.strictEqual(averageDuration(createTiming()), 0);
    });

    test('averageDuration computes correct mean', () => {
        let t = createTiming();
        t = recordDuration(t, 100);
        t = recordDuration(t, 200);
        t = recordDuration(t, 300);
        assert.strictEqual(averageDuration(t), 200);
    });

    test('shouldIsolate returns false with fewer than 5 samples', () => {
        let t = createTiming();
        for (let i = 0; i < 4; i++) { t = recordDuration(t, 3000); }
        assert.strictEqual(shouldIsolate(t, 2000), false);
    });

    test('shouldIsolate returns true when average exceeds threshold over full window', () => {
        let t = createTiming();
        for (let i = 0; i < 5; i++) { t = recordDuration(t, 3000); }
        assert.strictEqual(shouldIsolate(t, 2000), true);
    });

    test('shouldIsolate returns false if already isolated', () => {
        let t = createTiming();
        for (let i = 0; i < 5; i++) { t = recordDuration(t, 3000); }
        t = markIsolated(t);
        assert.strictEqual(shouldIsolate(t, 2000), false);
    });

    test('shouldRejoin returns false if not isolated', () => {
        let t = createTiming();
        t = { ...t, consecutiveFast: 10 };
        assert.strictEqual(shouldRejoin(t), false);
    });

    test('shouldRejoin returns true after 5 consecutive fast ticks', () => {
        let t = markIsolated(createTiming());
        for (let i = 0; i < 5; i++) { t = recordFastTick(t); }
        assert.strictEqual(shouldRejoin(t), true);
    });

    test('shouldRejoin returns false with fewer than 5 consecutive fast ticks', () => {
        let t = markIsolated(createTiming());
        for (let i = 0; i < 4; i++) { t = recordFastTick(t); }
        assert.strictEqual(shouldRejoin(t), false);
    });

    test('markIsolated sets isolated and resets fast count', () => {
        let t = createTiming();
        t = { ...t, consecutiveFast: 3 };
        t = markIsolated(t);
        assert.strictEqual(t.isolated, true);
        assert.strictEqual(t.consecutiveFast, 0);
    });

    test('markRejoined clears isolated and resets fast count', () => {
        let t = markIsolated(createTiming());
        t = { ...t, consecutiveFast: 5 };
        t = markRejoined(t);
        assert.strictEqual(t.isolated, false);
        assert.strictEqual(t.consecutiveFast, 0);
    });

    test('resetFastTick clears consecutive counter', () => {
        let t = markIsolated(createTiming());
        t = recordFastTick(t);
        t = recordFastTick(t);
        t = resetFastTick(t);
        assert.strictEqual(t.consecutiveFast, 0);
    });
});
