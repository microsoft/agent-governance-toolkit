// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Time Utilities
 *
 * Pure functions for time formatting.
 * Extracted for testability without JSX dependency.
 */

/** Converts an ISO timestamp to a relative time string. */
export function timeAgo(isoString: string): string {
    const now = Date.now();
    const then = new Date(isoString).getTime();
    const diffMs = now - then;

    if (diffMs < 0) { return 'just now'; }

    const minutes = Math.floor(diffMs / 60_000);
    if (minutes < 1) { return 'just now'; }
    if (minutes < 60) { return `${minutes}m ago`; }

    const hours = Math.floor(minutes / 60);
    if (hours < 24) { return `${hours}h ago`; }

    const days = Math.floor(hours / 24);
    return `${days}d ago`;
}

/** Formats seconds into a compact uptime string (e.g. "3h 12m" or "45m"). */
export function formatUptime(seconds: number): string {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    if (h > 0) { return `${h}h ${m}m`; }
    return `${m}m`;
}
