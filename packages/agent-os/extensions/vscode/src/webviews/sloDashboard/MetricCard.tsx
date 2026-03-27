// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Metric Card Component
 *
 * Displays a single SLO metric with value, target, health status,
 * and optional error budget. Uses Monolith Ledger design tokens.
 */

import React from 'react';

export type HealthStatus = 'ok' | 'warn' | 'breach';

export interface MetricCardProps {
    /** Display label (e.g., "Availability") */
    label: string;
    /** Current metric value */
    value: number;
    /** Unit suffix (e.g., "%", "ms") */
    suffix: string;
    /** Target threshold for health calculation */
    target?: number;
    /** Health status determines border and accent color */
    health: HealthStatus;
    /** Error budget remaining (0-100) */
    errorBudget?: number;
}

const HEALTH_COLORS: Record<HealthStatus, string> = {
    ok: 'border-ml-success',
    warn: 'border-ml-warning',
    breach: 'border-ml-error',
};

const HEALTH_TEXT: Record<HealthStatus, string> = {
    ok: 'text-ml-success',
    warn: 'text-ml-warning',
    breach: 'text-ml-error',
};

/** Single SLO metric card with health-colored border and optional error budget. */
export function MetricCard({ label, value, suffix, target, health, errorBudget }: MetricCardProps) {
    const borderClass = HEALTH_COLORS[health];
    const textClass = HEALTH_TEXT[health];

    return (
        <div className={`bg-ml-surface rounded-ml border-l-4 ${borderClass} p-ml-lg`}>
            <div className="text-ml-text-muted text-xs uppercase tracking-wider mb-ml-xs">
                {label}
            </div>
            <div className={`text-3xl font-bold font-mono ${textClass}`}>
                {value === 0 ? '--' : value.toFixed(1)}
                <span className="text-lg text-ml-text-muted ml-1">{suffix}</span>
            </div>
            {target !== undefined && (
                <div className="text-xs text-ml-text-muted mt-ml-xs">
                    Target: {target.toFixed(1)}{suffix}
                </div>
            )}
            {errorBudget !== undefined && (
                <div className="mt-ml-sm">
                    <div className="flex justify-between text-xs text-ml-text-muted mb-1">
                        <span>Error Budget</span>
                        <span>{errorBudget.toFixed(0)}%</span>
                    </div>
                    <div className="h-1.5 bg-ml-border rounded-full overflow-hidden">
                        <div
                            className={`h-full rounded-full ${health === 'ok' ? 'bg-ml-success' : health === 'warn' ? 'bg-ml-warning' : 'bg-ml-error'}`}
                            style={{ width: `${Math.max(0, Math.min(100, errorBudget))}%` }}
                        />
                    </div>
                </div>
            )}
        </div>
    );
}
