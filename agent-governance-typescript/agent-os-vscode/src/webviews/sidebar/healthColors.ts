// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Health Color Utilities
 *
 * Pure functions that map metric values to Tailwind text-color classes.
 * Extracted from panel components for testability without JSX dependency.
 */

/** Returns a Tailwind text-color class based on percentage health. */
export function percentColor(value: number, target: number): string {
    if (value >= target) { return 'text-ml-success'; }
    if (value >= target - 1) { return 'text-ml-warning'; }
    return 'text-ml-error';
}

/** Returns a Tailwind text-color class based on latency health. */
export function latencyColor(value: number, target: number): string {
    if (value <= target) { return 'text-ml-success'; }
    if (value <= target * 1.2) { return 'text-ml-warning'; }
    return 'text-ml-error';
}

/** Returns a Tailwind text-color class for trust scores (0-1000). */
export function trustColor(value: number): string {
    if (value >= 750) { return 'text-ml-success'; }
    if (value >= 400) { return 'text-ml-warning'; }
    return 'text-ml-error';
}
