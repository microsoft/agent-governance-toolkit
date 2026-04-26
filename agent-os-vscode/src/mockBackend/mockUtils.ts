// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Shared utilities for mock backend services.
 *
 * Provides bounded random-walk helpers used by both
 * MockSLOBackend and MockTopologyBackend.
 */

/** Clamp a number between min and max. */
export function clamp(v: number, lo: number, hi: number): number {
    return Math.max(lo, Math.min(hi, v));
}

/** Add bounded random walk to a value. */
export function drift(
    current: number,
    step: number,
    lo: number,
    hi: number,
): number {
    return clamp(current + (Math.random() - 0.48) * step, lo, hi);
}
