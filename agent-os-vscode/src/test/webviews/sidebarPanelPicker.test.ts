// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Unit tests for PanelPicker pure utility functions.
 *
 * Tests findSlotForPanel, slotBadgeLetter, and hasChanges with no React dependency.
 */

import * as assert from 'assert';
import {
    findSlotForPanel,
    slotBadgeLetter,
    hasChanges,
} from '../../webviews/sidebar/pickerUtils';
import type { SlotConfig } from '../../webviews/sidebar/types';

const DEFAULT: SlotConfig = {
    slotA: 'slo-dashboard',
    slotB: 'audit-log',
    slotC: 'agent-topology',
};

suite('PanelPicker — findSlotForPanel', () => {
    test('returns slotA when panel is assigned to slot A', () => {
        assert.strictEqual(findSlotForPanel(DEFAULT, 'slo-dashboard'), 'slotA');
    });

    test('returns slotB when panel is assigned to slot B', () => {
        assert.strictEqual(findSlotForPanel(DEFAULT, 'audit-log'), 'slotB');
    });

    test('returns slotC when panel is assigned to slot C', () => {
        assert.strictEqual(findSlotForPanel(DEFAULT, 'agent-topology'), 'slotC');
    });

    test('returns null when panel is not assigned to any slot', () => {
        assert.strictEqual(findSlotForPanel(DEFAULT, 'governance-hub'), null);
        assert.strictEqual(findSlotForPanel(DEFAULT, 'kernel-debugger'), null);
    });
});

suite('PanelPicker — slotBadgeLetter', () => {
    test('returns A for slotA', () => {
        assert.strictEqual(slotBadgeLetter('slotA'), 'A');
    });

    test('returns B for slotB', () => {
        assert.strictEqual(slotBadgeLetter('slotB'), 'B');
    });

    test('returns C for slotC', () => {
        assert.strictEqual(slotBadgeLetter('slotC'), 'C');
    });
});

suite('PanelPicker — hasChanges', () => {
    test('returns false when current and draft are identical', () => {
        const draft: SlotConfig = { ...DEFAULT };
        assert.strictEqual(hasChanges(DEFAULT, draft), false);
    });

    test('returns true when slotA differs', () => {
        const draft: SlotConfig = { ...DEFAULT, slotA: 'governance-hub' };
        assert.strictEqual(hasChanges(DEFAULT, draft), true);
    });

    test('returns true when slotB differs', () => {
        const draft: SlotConfig = { ...DEFAULT, slotB: 'safety-stats' };
        assert.strictEqual(hasChanges(DEFAULT, draft), true);
    });

    test('returns true when slotC differs', () => {
        const draft: SlotConfig = { ...DEFAULT, slotC: 'kernel-debugger' };
        assert.strictEqual(hasChanges(DEFAULT, draft), true);
    });

    test('returns true when all slots differ', () => {
        const draft: SlotConfig = {
            slotA: 'governance-hub',
            slotB: 'safety-stats',
            slotC: 'kernel-debugger',
        };
        assert.strictEqual(hasChanges(DEFAULT, draft), true);
    });

    test('returns false when panels are swapped but values match original', () => {
        // Same object shape — no changes
        const draft: SlotConfig = {
            slotA: 'slo-dashboard',
            slotB: 'audit-log',
            slotC: 'agent-topology',
        };
        assert.strictEqual(hasChanges(DEFAULT, draft), false);
    });
});
