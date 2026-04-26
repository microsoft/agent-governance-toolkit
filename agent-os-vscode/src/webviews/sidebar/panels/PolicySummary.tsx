// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Policy Summary Panel
 *
 * Shows enabled/total rule count headline with a 2x2
 * metric grid for deny, block, evaluations, and violations.
 */

import React from 'react';
import type { PolicySummaryData } from '../types';
import { Tooltip } from '../../shared/Tooltip';
import { HELP } from '../../shared/helpContent';

function MetricCell(props: {
    label: string; value: number; colorClass: string; tooltip: string;
}): React.ReactElement {
    return (
        <div className="flex flex-col items-start">
            <Tooltip text={props.tooltip}><span className="text-xs text-ml-text-muted">{props.label}</span></Tooltip>
            <span className={`text-sm font-bold ${props.colorClass}`}>{props.value}</span>
        </div>
    );
}

function buildMetrics(data: PolicySummaryData): Array<{
    label: string; value: number; colorClass: string; tooltip: string;
}> {
    return [
        { label: 'DENY', value: data.denyRules, colorClass: data.denyRules > 0 ? 'text-ml-error' : 'text-ml-text',
          tooltip: HELP.policy.deny },
        { label: 'BLOCK', value: data.blockRules, colorClass: data.blockRules > 0 ? 'text-ml-error' : 'text-ml-text',
          tooltip: HELP.policy.block },
        { label: 'Evals Today', value: data.evaluationsToday, colorClass: 'text-ml-text',
          tooltip: HELP.policy.evaluations },
        { label: 'Violations', value: data.violationsToday, colorClass: data.violationsToday > 0 ? 'text-ml-error' : 'text-ml-text',
          tooltip: HELP.policy.violations },
    ];
}

export function PolicySummary(
    { data }: { data: PolicySummaryData | null }
): React.ReactElement {
    if (!data) {
        return (
            <div className="flex items-center justify-center p-ml-sm">
                <span className="text-sm text-ml-text-muted">Awaiting policy data...</span>
            </div>
        );
    }

    const metrics = buildMetrics(data);

    return (
        <div className="p-ml-sm">
            <div className="text-sm text-ml-text mb-2">
                <span className="font-bold">{data.enabledRules}/{data.totalRules}</span>
                <span className="text-ml-text-muted ml-1">rules active</span>
            </div>
            <div className="grid grid-cols-2 gap-ml-xs">
                {metrics.map((m) => (
                    <MetricCell key={m.label} {...m} />
                ))}
            </div>
        </div>
    );
}
