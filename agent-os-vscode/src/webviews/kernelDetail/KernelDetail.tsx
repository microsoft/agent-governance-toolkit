// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Kernel Debugger Detail Panel
 *
 * Full-panel view of kernel state: active agents, policy violations,
 * checkpoints, uptime, and signal history.
 */

import React from 'react';
import { DetailShell } from '../shared/DetailShell';
import { useExtensionMessage } from '../shared/useExtensionMessage';
import { getVSCodeAPI } from '../shared/vscode';
import type { KernelDetailData, KernelAgent } from '../shared/types';

function formatUptime(seconds: number): string {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    return `${h}h ${m}m ${s}s`;
}

function StatusDot({ status }: { status: KernelAgent['status'] }): React.JSX.Element {
    const colors: Record<string, string> = {
        running: 'bg-ml-success',
        paused: 'bg-ml-warning',
        stopped: 'bg-ml-error',
        error: 'bg-ml-error',
    };
    return <span className={`inline-block w-2 h-2 rounded-full ${colors[status] ?? 'bg-ml-text-muted'}`} />;
}

function MetricCard({ label, value, colorClass }: {
    label: string; value: string; colorClass?: string;
}): React.JSX.Element {
    return (
        <div className="bg-ml-surface rounded-ml p-ml-sm">
            <div className="text-xs text-ml-text-muted">{label}</div>
            <div className={`text-lg font-bold ${colorClass ?? 'text-ml-text'}`}>{value}</div>
        </div>
    );
}

function AgentRow({ agent }: { agent: KernelAgent }): React.JSX.Element {
    return (
        <div className="flex items-center justify-between py-1.5 px-ml-sm border-b border-ml-border last:border-b-0">
            <div className="flex items-center gap-2">
                <StatusDot status={agent.status} />
                <span className="text-sm font-medium text-ml-text">{agent.name}</span>
                <span className="text-xs text-ml-text-muted font-mono">{agent.id}</span>
            </div>
            <div className="flex items-center gap-3 text-xs text-ml-text-muted">
                {agent.currentTask && <span className="truncate max-w-[200px]">{agent.currentTask}</span>}
                <span>Mem: {agent.memoryUsage}%</span>
                <span>{agent.checkpointCount} ckpt</span>
                <span>{agent.signalCount} sig</span>
            </div>
        </div>
    );
}

function LoadingState(): React.JSX.Element {
    return (
        <div className="flex items-center justify-center h-64 text-ml-text-muted text-sm">
            Waiting for kernel data...
        </div>
    );
}

function KernelContent({ data }: { data: KernelDetailData }): React.JSX.Element {
    return (
        <div className="space-y-ml-md">
            <div className="grid grid-cols-4 gap-ml-sm">
                <MetricCard label="Uptime" value={formatUptime(data.uptimeSeconds)} />
                <MetricCard label="Active Agents" value={String(data.activeAgents.length)} />
                <MetricCard
                    label="Policy Violations"
                    value={String(data.policyViolations)}
                    colorClass={data.policyViolations > 0 ? 'text-ml-error' : 'text-ml-text'}
                />
                <MetricCard label="Checkpoints" value={String(data.totalCheckpoints)} />
            </div>

            <div className="bg-ml-surface rounded-ml">
                <div className="px-ml-sm py-1.5 border-b border-ml-border">
                    <h2 className="text-sm font-semibold text-ml-text-bright">Active Agents</h2>
                </div>
                {data.activeAgents.length === 0 ? (
                    <div className="p-ml-sm text-sm text-ml-text-muted">No active agents</div>
                ) : (
                    data.activeAgents.map(agent => <AgentRow key={agent.id} agent={agent} />)
                )}
            </div>
        </div>
    );
}

export function KernelDetail({ data: propData }: { data?: KernelDetailData }): React.JSX.Element {
    const msgData = useExtensionMessage<KernelDetailData>('kernelDetailUpdate');
    const data = propData ?? msgData;

    const handleRefresh = () => getVSCodeAPI().postMessage({ type: 'refresh' });

    return (
        <DetailShell title="Kernel Debugger" timestamp={data?.fetchedAt ?? null} onRefresh={handleRefresh}>
            {data ? <KernelContent data={data} /> : <LoadingState />}
        </DetailShell>
    );
}
