// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Governance Hub Summary Panel
 *
 * Large health indicator with colored status circle,
 * plus a 3-stat compact row for alerts, compliance, and agent count.
 */

import React from 'react';
import type { GovernanceHubData } from '../types';
import { Tooltip } from '../../shared/Tooltip';
import { HELP } from '../../shared/helpContent';

const HEALTH_MAP: Record<GovernanceHubData['overallHealth'], {
    label: string; colorClass: string; dotClass: string;
}> = {
    healthy:  { label: 'Healthy',  colorClass: 'text-ml-success', dotClass: 'bg-ml-success' },
    warning:  { label: 'Warning',  colorClass: 'text-ml-warning', dotClass: 'bg-ml-warning' },
    critical: { label: 'Critical', colorClass: 'text-ml-error',   dotClass: 'bg-ml-error' },
};

function HealthIndicator(
    { health }: { health: GovernanceHubData['overallHealth'] }
): React.ReactElement {
    const { label, colorClass, dotClass } = HEALTH_MAP[health];
    return (
        <div className="flex items-center gap-ml-xs">
            <span className={`inline-block w-3 h-3 rounded-full ${dotClass}`} />
            <Tooltip text={HELP.governanceHub.health}><span className={`text-lg font-bold ${colorClass}`}>{label}</span></Tooltip>
        </div>
    );
}

function StatRow(props: {
    alerts: number; compliance: number; agents: number;
}): React.ReactElement {
    return (
        <div className="grid grid-cols-3 gap-ml-xs mt-2">
            <div className="flex flex-col items-start">
                <Tooltip text={HELP.governanceHub.activeAlerts}><span className="text-xs text-ml-text-muted">Alerts</span></Tooltip>
                <span className={`text-sm font-bold ${props.alerts > 0 ? 'text-ml-error' : 'text-ml-text'}`}>
                    {props.alerts}
                </span>
            </div>
            <div className="flex flex-col items-start">
                <Tooltip text={HELP.governanceHub.compliance}><span className="text-xs text-ml-text-muted">Compliance</span></Tooltip>
                <span className="text-sm font-bold text-ml-text">{props.compliance}%</span>
            </div>
            <div className="flex flex-col items-start">
                <Tooltip text={HELP.governanceHub.agents}><span className="text-xs text-ml-text-muted">Agents</span></Tooltip>
                <span className="text-sm font-bold text-ml-text">{props.agents}</span>
            </div>
        </div>
    );
}

export function GovernanceHubSummary(
    { data }: { data: GovernanceHubData | null }
): React.ReactElement {
    if (!data) {
        return (
            <div className="flex items-center justify-center p-ml-sm">
                <span className="text-sm text-ml-text-muted">Awaiting governance data...</span>
            </div>
        );
    }

    return (
        <div className="p-ml-sm">
            <HealthIndicator health={data.overallHealth} />
            <StatRow
                alerts={data.activeAlerts}
                compliance={data.policyCompliance}
                agents={data.agentCount}
            />
        </div>
    );
}
