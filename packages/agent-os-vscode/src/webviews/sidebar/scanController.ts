// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Scan Controller
 *
 * Pure functions for sidebar scan rotation logic.
 * No React, no timers, no side effects.
 */

import type { AttentionMode, SlotKey } from './types';

const SLOT_ORDER: SlotKey[] = ['slotA', 'slotB', 'slotC'];

/** Scan interval in milliseconds (4 seconds per slot). */
export const SCAN_INTERVAL_MS = 4000;

/** Idle delay before resuming scan after hover/focus (2 seconds). */
export const IDLE_RESUME_MS = 2000;

/** Rotate to the next slot in A → B → C → A order. */
export function nextSlot(current: SlotKey): SlotKey {
    const idx = SLOT_ORDER.indexOf(current);
    return SLOT_ORDER[(idx + 1) % SLOT_ORDER.length];
}

/** Should scanning be active? Only in auto mode without reduced motion. */
export function shouldScan(mode: AttentionMode, reducedMotion: boolean): boolean {
    return mode === 'auto' && !reducedMotion;
}
