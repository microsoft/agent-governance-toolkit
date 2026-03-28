// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Kernel Summary Panel
 *
 * 2x2 grid showing active agents, policy violations,
 * checkpoints, and formatted uptime.
 */

import React from 'react';
import type { KernelSummaryData } from '../types';
import { formatUptime } from '../timeUtils';
import { Tooltip } from '../../shared/Tooltip';
import { HELP } from '../../shared/helpContent';

function MetricCell(props: {
    label: string; value: string; colorClass: string; tooltip: string;
}): React.ReactElement {
    return (
        <div className="flex flex-col items-start">
            <Tooltip text={props.tooltip}><span className="text-xs text-ml-text-muted">{props.label}</span></Tooltip>
            <span className={`text-sm font-bold ${props.colorClass}`}>{props.value}</span>
        </div>
    );
}

function buildMetrics(data: KernelSummaryData): Array<{
    label: string; value: string; colorClass: string; tooltip: string;
}> {
    return [
        { label: 'Agents', value: data.activeAgents.toString(), colorClass: 'text-ml-text',
          tooltip: HELP.kernel.activeAgents },
        { label: 'Violations', value: data.policyViolations.toString(),
          colorClass: data.policyViolations > 0 ? 'text-ml-error' : 'text-ml-text',
          tooltip: HELP.kernel.violations },
        { label: 'Checkpoints', value: data.totalCheckpoints.toString(), colorClass: 'text-ml-text',
          tooltip: HELP.kernel.checkpoints },
        { label: 'Uptime', value: formatUptime(data.uptimeSeconds), colorClass: 'text-ml-text',
          tooltip: HELP.kernel.uptime },
    ];
}

export function KernelSummary(
    { data }: { data: KernelSummaryData | null }
): React.ReactElement {
    if (!data) {
        return (
            <div className="flex items-center justify-center p-ml-sm">
                <span className="text-sm text-ml-text-muted">Awaiting kernel data...</span>
            </div>
        );
    }

    const metrics = buildMetrics(data);

    return (
        <div className="p-ml-sm">
            <div className="grid grid-cols-2 gap-ml-xs">
                {metrics.map((m) => (
                    <MetricCell key={m.label} {...m} />
                ))}
            </div>
        </div>
    );
}
