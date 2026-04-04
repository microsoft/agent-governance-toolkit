// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Active Policies Detail Panel
 *
 * Full-panel view of governance policy rules with action badges,
 * pattern matches, evaluation counts, and violation counts.
 */

import React from 'react';
import { DetailShell } from '../shared/DetailShell';
import { useExtensionMessage } from '../shared/useExtensionMessage';
import { getVSCodeAPI } from '../shared/vscode';
import type { PolicyDetailData, PolicyRuleDetail } from '../shared/types';

function ActionBadge({ action }: { action: PolicyRuleDetail['action'] }): React.JSX.Element {
    const colors: Record<string, string> = {
        ALLOW: 'bg-ml-success/20 text-ml-success',
        DENY: 'bg-ml-error/20 text-ml-error',
        AUDIT: 'bg-ml-accent/20 text-ml-accent',
        BLOCK: 'bg-ml-error/20 text-ml-error',
    };
    return (
        <span className={`px-1.5 py-0.5 rounded text-[10px] uppercase font-semibold ${colors[action] ?? 'bg-ml-surface text-ml-text-muted'}`}>
            {action}
        </span>
    );
}

function RuleRow({ rule }: { rule: PolicyRuleDetail }): React.JSX.Element {
    return (
        <div className="flex items-center gap-3 py-2 px-ml-sm border-b border-ml-border last:border-b-0 text-sm">
            <ActionBadge action={rule.action} />
            <div className="flex-1 min-w-0">
                <div className="font-medium text-ml-text truncate">{rule.name}</div>
                <div className="text-xs text-ml-text-muted font-mono truncate">{rule.pattern}</div>
            </div>
            <div className="flex items-center gap-3 text-xs text-ml-text-muted shrink-0">
                <span>{rule.evaluationsToday} evals</span>
                <span className={rule.violationsToday > 0 ? 'text-ml-error font-semibold' : ''}>
                    {rule.violationsToday} violations
                </span>
                <span className={`w-2 h-2 rounded-full ${rule.enabled ? 'bg-ml-success' : 'bg-ml-text-muted'}`} />
            </div>
        </div>
    );
}

function LoadingState(): React.JSX.Element {
    return (
        <div className="flex items-center justify-center h-64 text-ml-text-muted text-sm">
            Waiting for policy data...
        </div>
    );
}

function PolicyContent({ data }: { data: PolicyDetailData }): React.JSX.Element {
    const enabledRules = data.rules.filter(r => r.enabled);
    const denyRules = data.rules.filter(r => r.action === 'DENY' || r.action === 'BLOCK');

    return (
        <div className="space-y-ml-md">
            <div className="grid grid-cols-4 gap-ml-sm">
                <div className="bg-ml-surface rounded-ml p-ml-sm">
                    <div className="text-xs text-ml-text-muted">Total Rules</div>
                    <div className="text-lg font-bold text-ml-text">{data.rules.length}</div>
                </div>
                <div className="bg-ml-surface rounded-ml p-ml-sm">
                    <div className="text-xs text-ml-text-muted">Enabled</div>
                    <div className="text-lg font-bold text-ml-text">{enabledRules.length}</div>
                </div>
                <div className="bg-ml-surface rounded-ml p-ml-sm">
                    <div className="text-xs text-ml-text-muted">Deny/Block</div>
                    <div className={`text-lg font-bold ${denyRules.length > 0 ? 'text-ml-error' : 'text-ml-text'}`}>{denyRules.length}</div>
                </div>
                <div className="bg-ml-surface rounded-ml p-ml-sm">
                    <div className="text-xs text-ml-text-muted">Evaluations Today</div>
                    <div className="text-lg font-bold text-ml-text">{data.totalEvaluations}</div>
                </div>
            </div>

            <div className="bg-ml-surface rounded-ml">
                <div className="px-ml-sm py-1.5 border-b border-ml-border">
                    <h2 className="text-sm font-semibold text-ml-text-bright">Policy Rules</h2>
                </div>
                {data.rules.length === 0 ? (
                    <div className="p-ml-sm text-sm text-ml-text-muted">No policies configured</div>
                ) : (
                    data.rules.map(rule => <RuleRow key={rule.id} rule={rule} />)
                )}
            </div>
        </div>
    );
}

export function PolicyDetail({ data: propData }: { data?: PolicyDetailData }): React.JSX.Element {
    const msgData = useExtensionMessage<PolicyDetailData>('policyDetailUpdate');
    const data = propData ?? msgData;

    const handleRefresh = () => getVSCodeAPI().postMessage({ type: 'refresh' });

    return (
        <DetailShell title="Active Policies" timestamp={data?.fetchedAt ?? null} onRefresh={handleRefresh}>
            {data ? <PolicyContent data={data} /> : <LoadingState />}
        </DetailShell>
    );
}
