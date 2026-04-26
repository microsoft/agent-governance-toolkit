// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Audit Log Detail Panel
 *
 * Full-panel view of governance audit events with severity badges,
 * timestamps, agent DIDs, and affected files.
 */

import React from 'react';
import { DetailShell } from '../shared/DetailShell';
import { useExtensionMessage } from '../shared/useExtensionMessage';
import { getVSCodeAPI } from '../shared/vscode';
import { timeAgo } from '../sidebar/timeUtils';
import type { AuditDetailData, AuditEntry } from '../shared/types';

function SeverityBadge({ severity }: { severity: AuditEntry['severity'] }): React.JSX.Element {
    const colors: Record<string, string> = {
        critical: 'bg-ml-error/20 text-ml-error',
        warning: 'bg-ml-warning/20 text-ml-warning',
        info: 'bg-ml-surface text-ml-text-muted',
    };
    return (
        <span className={`px-1.5 py-0.5 rounded text-[10px] uppercase font-semibold ${colors[severity] ?? colors.info}`}>
            {severity}
        </span>
    );
}

function AuditRow({ entry }: { entry: AuditEntry }): React.JSX.Element {
    return (
        <div className="flex items-center gap-3 py-1.5 px-ml-sm border-b border-ml-border last:border-b-0 text-sm">
            <SeverityBadge severity={entry.severity} />
            <span className="text-ml-text font-medium min-w-[100px]">{entry.action}</span>
            {entry.agentDid && (
                <span className="text-xs text-ml-text-muted font-mono truncate max-w-[160px]">{entry.agentDid}</span>
            )}
            {entry.file && (
                <span className="text-xs text-ml-text-muted font-mono truncate max-w-[180px]">{entry.file}</span>
            )}
            <span className="ml-auto text-xs text-ml-text-muted whitespace-nowrap">{timeAgo(entry.timestamp)}</span>
        </div>
    );
}

function LoadingState(): React.JSX.Element {
    return (
        <div className="flex items-center justify-center h-64 text-ml-text-muted text-sm">
            Waiting for audit data...
        </div>
    );
}

function AuditContent({ data }: { data: AuditDetailData }): React.JSX.Element {
    const criticalCount = data.entries.filter(e => e.severity === 'critical').length;
    const warningCount = data.entries.filter(e => e.severity === 'warning').length;

    return (
        <div className="space-y-ml-md">
            <div className="grid grid-cols-3 gap-ml-sm">
                <div className="bg-ml-surface rounded-ml p-ml-sm">
                    <div className="text-xs text-ml-text-muted">Total Events</div>
                    <div className="text-lg font-bold text-ml-text">{data.entries.length}</div>
                </div>
                <div className="bg-ml-surface rounded-ml p-ml-sm">
                    <div className="text-xs text-ml-text-muted">Critical</div>
                    <div className={`text-lg font-bold ${criticalCount > 0 ? 'text-ml-error' : 'text-ml-text'}`}>{criticalCount}</div>
                </div>
                <div className="bg-ml-surface rounded-ml p-ml-sm">
                    <div className="text-xs text-ml-text-muted">Warnings</div>
                    <div className={`text-lg font-bold ${warningCount > 0 ? 'text-ml-warning' : 'text-ml-text'}`}>{warningCount}</div>
                </div>
            </div>

            <div className="bg-ml-surface rounded-ml">
                <div className="px-ml-sm py-1.5 border-b border-ml-border">
                    <h2 className="text-sm font-semibold text-ml-text-bright">Event Log</h2>
                </div>
                {data.entries.length === 0 ? (
                    <div className="p-ml-sm text-sm text-ml-text-muted">No audit events recorded</div>
                ) : (
                    data.entries.map(entry => <AuditRow key={entry.id} entry={entry} />)
                )}
            </div>
        </div>
    );
}

export function AuditDetail({ data: propData }: { data?: AuditDetailData }): React.JSX.Element {
    const msgData = useExtensionMessage<AuditDetailData>('auditDetailUpdate');
    const data = propData ?? msgData;

    const handleRefresh = () => getVSCodeAPI().postMessage({ type: 'refresh' });

    return (
        <DetailShell title="Audit Log" timestamp={data?.fetchedAt ?? null} onRefresh={handleRefresh}>
            {data ? <AuditContent data={data} /> : <LoadingState />}
        </DetailShell>
    );
}
