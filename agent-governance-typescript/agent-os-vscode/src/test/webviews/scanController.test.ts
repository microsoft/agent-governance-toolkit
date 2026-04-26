// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import * as assert from 'assert';
import { nextSlot, shouldScan, SCAN_INTERVAL_MS, IDLE_RESUME_MS } from '../../webviews/sidebar/scanController';

suite('ScanController', () => {
    test('nextSlot rotates A → B', () => {
        assert.strictEqual(nextSlot('slotA'), 'slotB');
    });

    test('nextSlot rotates B → C', () => {
        assert.strictEqual(nextSlot('slotB'), 'slotC');
    });

    test('nextSlot wraps C → A', () => {
        assert.strictEqual(nextSlot('slotC'), 'slotA');
    });

    test('shouldScan returns true for auto mode without reduced motion', () => {
        assert.strictEqual(shouldScan('auto', false), true);
    });

    test('shouldScan returns false for manual mode', () => {
        assert.strictEqual(shouldScan('manual', false), false);
    });

    test('shouldScan returns false for auto mode with reduced motion', () => {
        assert.strictEqual(shouldScan('auto', true), false);
    });

    test('SCAN_INTERVAL_MS is 4000', () => {
        assert.strictEqual(SCAN_INTERVAL_MS, 4000);
    });

    test('IDLE_RESUME_MS is 2000', () => {
        assert.strictEqual(IDLE_RESUME_MS, 2000);
    });
});
