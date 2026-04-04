// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Panel Picker Utilities
 *
 * Pure functions for slot assignment logic.
 * Extracted for testability without JSX dependency.
 */

import type { PanelId, SlotConfig } from './types';

export type SlotKey = 'slotA' | 'slotB' | 'slotC';

export const SLOT_KEYS: SlotKey[] = ['slotA', 'slotB', 'slotC'];

/** Returns the slot key a panel is assigned to, or null. */
export function findSlotForPanel(draft: SlotConfig, panelId: PanelId): SlotKey | null {
    for (const key of SLOT_KEYS) {
        if (draft[key] === panelId) {
            return key;
        }
    }
    return null;
}

/** Badge letter for a slot key. */
export function slotBadgeLetter(key: SlotKey): string {
    return key.replace('slot', '');
}

/** Check if draft differs from current config. */
export function hasChanges(current: SlotConfig, draft: SlotConfig): boolean {
    return (
        current.slotA !== draft.slotA ||
        current.slotB !== draft.slotB ||
        current.slotC !== draft.slotC
    );
}
