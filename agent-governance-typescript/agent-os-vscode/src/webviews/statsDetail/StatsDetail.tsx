// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Safety Stats Detail Panel
 *
 * Full-panel view of safety metrics: blocked actions, warnings,
 * CMVK reviews, and total log count.
 */

import React from 'react';
import { DetailShell } from '../shared/DetailShell';
import { useExtensionMessage } from '../shared/useExtensionMessage';
import { getVSCodeAPI } from '../shared/vscode';
import type { StatsDetailData } from '../shared/types';

function StatCard({ label, value, colorClass, description }: {
    label: string; value: number; colorClass?: string; description: string;
}): React.JSX.Element {
    return (
        <div className="bg-ml-surface rounded-ml p-ml-sm">
            <div className="text-xs text-ml-text-muted">{label}</div>
            <div className={`text-2xl font-bold ${colorClass ?? 'text-ml-text'}`}>{value}</div>
            <div className="text-xs text-ml-text-muted mt-1">{description}</div>
        </div>
    );
}

function LoadingState(): React.JSX.Element {
    return (
        <div className="flex items-center justify-center h-64 text-ml-text-muted text-sm">
            Waiting for safety stats...
        </div>
    );
}

function StatsContent({ data }: { data: StatsDetailData }): React.JSX.Element {
    return (
        <div className="space-y-ml-md">
            <div className="grid grid-cols-2 gap-ml-sm">
                <StatCard
                    label="Blocked Today"
                    value={data.blockedToday}
                    colorClass={data.blockedToday > 0 ? 'text-ml-error' : 'text-ml-text'}
                    description="Tool calls denied by governance policies"
                />
                <StatCard
                    label="Blocked This Week"
                    value={data.blockedThisWeek}
                    description="Cumulative blocked actions over 7 days"
                />
                <StatCard
                    label="Warnings Today"
                    value={data.warningsToday}
                    colorClass={data.warningsToday > 0 ? 'text-ml-warning' : 'text-ml-text'}
                    description="Actions flagged for review but allowed"
                />
                <StatCard
                    label="CMVK Reviews"
                    value={data.cmvkReviews}
                    description="Constitutional verification checks performed"
                />
            </div>

            <div className="bg-ml-surface rounded-ml p-ml-sm">
                <div className="flex items-center justify-between">
                    <div>
                        <div className="text-xs text-ml-text-muted">Total Audit Logs</div>
                        <div className="text-2xl font-bold text-ml-text">{data.totalLogs}</div>
                    </div>
                    <div className="text-xs text-ml-text-muted">
                        All governance events recorded this session
                    </div>
                </div>
            </div>
        </div>
    );
}

export function StatsDetail({ data: propData }: { data?: StatsDetailData }): React.JSX.Element {
    const msgData = useExtensionMessage<StatsDetailData>('statsDetailUpdate');
    const data = propData ?? msgData;

    const handleRefresh = () => getVSCodeAPI().postMessage({ type: 'refresh' });

    return (
        <DetailShell title="Safety Stats" timestamp={data?.fetchedAt ?? null} onRefresh={handleRefresh}>
            {data ? <StatsContent data={data} /> : <LoadingState />}
        </DetailShell>
    );
}
