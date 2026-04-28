// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Stats Summary Panel
 *
 * Vertical list of 5 metric rows with conditional
 * health-color coding for blocked and warning counts.
 */

import React from 'react';
import type { StatsSummaryData } from '../types';
import { Tooltip } from '../../shared/Tooltip';
import { HELP } from '../../shared/helpContent';

function MetricRow(props: {
    label: string; value: number; colorClass: string; tooltip: string;
}): React.ReactElement {
    return (
        <div className="flex items-center justify-between py-0.5">
            <Tooltip text={props.tooltip}><span className="text-xs text-ml-text-muted">{props.label}</span></Tooltip>
            <span className={`text-sm font-bold ${props.colorClass}`}>{props.value}</span>
        </div>
    );
}

function buildRows(data: StatsSummaryData): Array<{
    label: string; value: number; colorClass: string; tooltip: string;
}> {
    return [
        { label: 'Blocked Today', value: data.blockedToday,
          colorClass: data.blockedToday > 0 ? 'text-ml-error' : 'text-ml-text',
          tooltip: HELP.stats.blockedToday },
        { label: 'Blocked This Week', value: data.blockedThisWeek, colorClass: 'text-ml-text',
          tooltip: HELP.stats.blockedThisWeek },
        { label: 'Warnings Today', value: data.warningsToday,
          colorClass: data.warningsToday > 0 ? 'text-ml-warning' : 'text-ml-text',
          tooltip: HELP.stats.warnings },
        { label: 'CMVK Reviews', value: data.cmvkReviews, colorClass: 'text-ml-text',
          tooltip: HELP.stats.cmvkReviews },
        { label: 'Total Logs', value: data.totalLogs, colorClass: 'text-ml-text',
          tooltip: HELP.stats.totalLogs },
    ];
}

export function StatsSummary(
    { data }: { data: StatsSummaryData | null }
): React.ReactElement {
    if (!data) {
        return (
            <div className="flex items-center justify-center p-ml-sm">
                <span className="text-sm text-ml-text-muted">Awaiting stats data...</span>
            </div>
        );
    }

    const rows = buildRows(data);

    return (
        <div className="p-ml-sm">
            {rows.map((r) => (
                <MetricRow key={r.label} {...r} />
            ))}
        </div>
    );
}
