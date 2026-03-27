// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Staleness Bar Component
 *
 * Displays how recently data was fetched. Color indicates freshness.
 * Empty when no fetchedAt timestamp is available.
 */

import React from 'react';

export interface StalenessBarProps {
    /** ISO timestamp of when data was last fetched */
    fetchedAt?: string;
}

function formatAge(fetchedAt: string): { text: string; level: 'fresh' | 'warn' | 'stale' } {
    const ageMs = Date.now() - new Date(fetchedAt).getTime();
    if (isNaN(ageMs) || ageMs < 0) { return { text: '', level: 'fresh' }; }
    const ageSec = Math.round(ageMs / 1000);
    if (ageSec < 10) { return { text: '', level: 'fresh' }; }
    const text = ageSec < 60 ? `${ageSec}s ago` : `${Math.round(ageSec / 60)}m ago`;
    const level = ageSec > 60 ? 'stale' : ageSec > 30 ? 'warn' : 'fresh';
    return { text, level };
}

const LEVEL_COLORS = {
    fresh: 'text-ml-text-muted',
    warn: 'text-ml-warning',
    stale: 'text-ml-error',
};

/** Displays data freshness indicator. Empty when data is fresh or absent. */
export function StalenessBar({ fetchedAt }: StalenessBarProps) {
    if (!fetchedAt) { return null; }
    const { text, level } = formatAge(fetchedAt);
    if (!text) { return null; }

    return (
        <div className={`text-xs ${LEVEL_COLORS[level]} opacity-70`}>
            Last updated: {text}
        </div>
    );
}
