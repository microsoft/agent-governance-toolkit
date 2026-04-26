// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Panel Latency Tracker
 *
 * Pure functions for per-panel latency tracking decisions.
 * No timers, no side effects, no state mutations.
 * The GovernanceStore calls these to decide isolation/rejoin.
 */

const WINDOW_SIZE = 5;

/** Rolling latency state for a single data source. */
export interface PanelTiming {
    readonly durations: readonly number[];
    readonly isolated: boolean;
    readonly consecutiveFast: number;
}

/** Create default timing for a new panel. */
export function createTiming(): PanelTiming {
    return { durations: [], isolated: false, consecutiveFast: 0 };
}

/** Record a fetch duration. Returns new timing (does not mutate input). */
export function recordDuration(timing: PanelTiming, durationMs: number): PanelTiming {
    const durations = [...timing.durations, durationMs].slice(-WINDOW_SIZE);
    return { ...timing, durations };
}

/** Compute average duration from the rolling window. */
export function averageDuration(timing: PanelTiming): number {
    if (timing.durations.length === 0) { return 0; }
    const sum = timing.durations.reduce((a, b) => a + b, 0);
    return sum / timing.durations.length;
}

/** Should this panel be isolated? Requires full window above threshold. */
export function shouldIsolate(timing: PanelTiming, thresholdMs: number): boolean {
    if (timing.isolated) { return false; }
    if (timing.durations.length < WINDOW_SIZE) { return false; }
    return averageDuration(timing) > thresholdMs;
}

/** Should this isolated panel rejoin the main loop? Requires 5 consecutive fast ticks. */
export function shouldRejoin(timing: PanelTiming): boolean {
    if (!timing.isolated) { return false; }
    return timing.consecutiveFast >= WINDOW_SIZE;
}

/** Mark a panel as isolated. Resets consecutive fast counter. */
export function markIsolated(timing: PanelTiming): PanelTiming {
    return { ...timing, isolated: true, consecutiveFast: 0 };
}

/** Mark a panel as rejoined. Resets consecutive fast counter. */
export function markRejoined(timing: PanelTiming): PanelTiming {
    return { ...timing, isolated: false, consecutiveFast: 0 };
}

/** Increment consecutive fast count after a sub-threshold fetch. */
export function recordFastTick(timing: PanelTiming): PanelTiming {
    return { ...timing, consecutiveFast: timing.consecutiveFast + 1 };
}

/** Reset consecutive fast count after a slow fetch. */
export function resetFastTick(timing: PanelTiming): PanelTiming {
    return { ...timing, consecutiveFast: 0 };
}
