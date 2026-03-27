// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * SLO Summary Panel
 *
 * Compact 2x2 metric grid showing availability, latency,
 * compliance, and trust scores with health-color coding.
 */

import React from 'react';
import type { SLOSummaryData } from '../types';
import { percentColor, latencyColor, trustColor } from '../healthColors';

/** A single compact metric cell with label, value, and suffix. */
function MiniMetric(props: {
    label: string;
    value: string;
    suffix: string;
    colorClass: string;
}): React.ReactElement {
    return (
        <div className="flex flex-col items-start">
            <span className="text-xs text-ml-text-muted">{props.label}</span>
            <span className={`text-lg font-bold ${props.colorClass}`}>
                {props.value}
                <span className="text-xs font-normal text-ml-text-muted ml-0.5">
                    {props.suffix}
                </span>
            </span>
        </div>
    );
}

/** Builds the array of metric props from SLO data. */
function buildMetrics(data: SLOSummaryData): Array<{
    label: string; value: string; suffix: string; colorClass: string;
}> {
    return [
        { label: 'Avail', value: data.availability.toFixed(1), suffix: '%',
          colorClass: percentColor(data.availability, data.availabilityTarget) },
        { label: 'P99', value: Math.round(data.latencyP99).toString(), suffix: 'ms',
          colorClass: latencyColor(data.latencyP99, data.latencyTarget) },
        { label: 'Comply', value: data.compliancePercent.toFixed(1), suffix: '%',
          colorClass: percentColor(data.compliancePercent, 100) },
        { label: 'Trust', value: Math.round(data.trustMean).toString(), suffix: '',
          colorClass: trustColor(data.trustMean) },
    ];
}

export function SLOSummary(
    { data }: { data: SLOSummaryData | null }
): React.ReactElement {
    if (!data) {
        return (
            <div className="flex items-center justify-center p-ml-sm">
                <span className="text-sm text-ml-text-muted">Awaiting SLO data...</span>
            </div>
        );
    }

    const metrics = buildMetrics(data);
    const hasViolations = data.violationsToday > 0;
    const violationLabel = `${data.violationsToday} violation${data.violationsToday !== 1 ? 's' : ''} today`;

    return (
        <div className="p-ml-sm">
            <div className="grid grid-cols-2 gap-ml-xs p-ml-sm">
                {metrics.map((m) => (
                    <MiniMetric key={m.label} {...m} />
                ))}
            </div>
            {hasViolations && (
                <div className="flex items-center gap-ml-xs mt-1 px-ml-sm">
                    <span className="text-xs text-ml-error font-medium">{violationLabel}</span>
                </div>
            )}
        </div>
    );
}
