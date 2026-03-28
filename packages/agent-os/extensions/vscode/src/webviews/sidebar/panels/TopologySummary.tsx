// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Topology Summary Panel
 *
 * Compact 2x2 grid showing agent count, bridge count,
 * mean trust score, and delegation chain count.
 */

import React from 'react';
import type { TopologySummaryData } from '../types';
import { trustColor } from '../healthColors';
import { Tooltip } from '../../shared/Tooltip';
import { HELP } from '../../shared/helpContent';

/** A single compact metric cell with label and value. */
function MetricCell(props: {
    label: string;
    value: string;
    colorClass?: string;
    tooltip: string;
}): React.ReactElement {
    return (
        <div className="flex flex-col items-start">
            <Tooltip text={props.tooltip}><span className="text-xs text-ml-text-muted">{props.label}</span></Tooltip>
            <span className={`text-lg font-bold ${props.colorClass ?? 'text-ml-text'}`}>
                {props.value}
            </span>
        </div>
    );
}

export function TopologySummary(
    { data }: { data: TopologySummaryData | null }
): React.ReactElement {
    if (!data) {
        return (
            <div className="flex items-center justify-center p-ml-sm">
                <span className="text-sm text-ml-text-muted">Awaiting topology data...</span>
            </div>
        );
    }

    return (
        <div className="grid grid-cols-2 gap-ml-xs p-ml-sm">
            <MetricCell
                label="Agents"
                value={data.agentCount.toString()}
                tooltip={HELP.topology.agents}
            />
            <MetricCell
                label="Bridges"
                value={data.bridgeCount.toString()}
                tooltip={HELP.topology.bridges}
            />
            <MetricCell
                label="Trust"
                value={Math.round(data.meanTrust).toString()}
                colorClass={trustColor(data.meanTrust)}
                tooltip={HELP.topology.trust}
            />
            <MetricCell
                label="Chains"
                value={data.delegationCount.toString()}
                tooltip={HELP.topology.chains}
            />
        </div>
    );
}
