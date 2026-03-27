// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * SLO Dashboard App
 *
 * Root React component for the SLO Dashboard webview.
 * Subscribes to sloUpdate messages from the extension host.
 */

import React, { useState, useEffect } from 'react';
import { onMessage, getVSCodeAPI } from '../shared/vscode';
import { MetricCard, HealthStatus } from './MetricCard';
import { StalenessBar } from './StalenessBar';

interface SLOSnapshot {
    availability: { currentPercent: number; targetPercent: number; errorBudgetRemainingPercent: number };
    latency: { p99Ms: number; targetMs: number; errorBudgetRemainingPercent: number };
    policyCompliance: { compliancePercent: number; totalEvaluations: number; violationsToday: number };
    trustScore: { meanScore: number; minScore: number; agentsBelowThreshold: number };
    fetchedAt?: string;
}

function healthFromPercent(value: number, target: number): HealthStatus {
    if (value === 0 && target === 0) { return 'ok'; }
    if (value >= target) { return 'ok'; }
    if (value >= target - 1) { return 'warn'; }
    return 'breach';
}

function healthFromLatency(value: number, target: number): HealthStatus {
    if (value === 0) { return 'ok'; }
    if (value <= target) { return 'ok'; }
    if (value <= target * 1.2) { return 'warn'; }
    return 'breach';
}

/** Root component for the SLO Dashboard. */
export function App() {
    const [snapshot, setSnapshot] = useState<SLOSnapshot | null>(null);

    useEffect(() => {
        const cleanup = onMessage((msg) => {
            if (msg.type === 'sloUpdate' && msg.snapshot) {
                setSnapshot(msg.snapshot as SLOSnapshot);
            }
        });
        return cleanup;
    }, []);

    if (!snapshot) {
        return (
            <div className="flex items-center justify-center h-screen text-ml-text-muted">
                <div className="text-center">
                    <div className="text-2xl mb-ml-sm">Waiting for data...</div>
                    <div className="text-sm">Connect to agent-failsafe to see live SLO metrics</div>
                </div>
            </div>
        );
    }

    const { availability: a, latency: l, policyCompliance: c, trustScore: t } = snapshot;

    return (
        <div className="p-ml-xl">
            <div className="flex items-center justify-between mb-ml-lg">
                <h1 className="text-lg font-semibold text-ml-text-bright">SLO Dashboard</h1>
                <div className="flex items-center gap-ml-md">
                    <StalenessBar fetchedAt={snapshot.fetchedAt} />
                    <button
                        className="text-xs bg-ml-surface hover:bg-ml-surface-hover text-ml-text px-ml-md py-ml-xs rounded-ml border border-ml-border"
                        onClick={() => getVSCodeAPI().postMessage({ type: 'refresh' })}
                    >
                        Refresh
                    </button>
                </div>
            </div>
            <div className="grid grid-cols-2 gap-ml-md">
                <MetricCard
                    label="Availability"
                    value={a.currentPercent}
                    suffix="%"
                    target={a.targetPercent}
                    health={healthFromPercent(a.currentPercent, a.targetPercent)}
                    errorBudget={a.errorBudgetRemainingPercent}
                />
                <MetricCard
                    label="P99 Latency"
                    value={l.p99Ms}
                    suffix="ms"
                    target={l.targetMs}
                    health={healthFromLatency(l.p99Ms, l.targetMs)}
                    errorBudget={l.errorBudgetRemainingPercent}
                />
                <MetricCard
                    label="Policy Compliance"
                    value={c.compliancePercent}
                    suffix="%"
                    target={100}
                    health={healthFromPercent(c.compliancePercent, 95)}
                />
                <MetricCard
                    label="Mean Trust Score"
                    value={t.meanScore}
                    suffix=""
                    target={750}
                    health={healthFromPercent(t.meanScore / 10, 75)}
                />
            </div>
            <div className="mt-ml-lg grid grid-cols-3 gap-ml-md text-center text-xs text-ml-text-muted">
                <div>
                    <span className="text-ml-text font-mono text-sm">{c.totalEvaluations}</span>
                    <div>Evaluations Today</div>
                </div>
                <div>
                    <span className="text-ml-error font-mono text-sm">{c.violationsToday}</span>
                    <div>Violations Today</div>
                </div>
                <div>
                    <span className="text-ml-warning font-mono text-sm">{t.agentsBelowThreshold}</span>
                    <div>Agents Below Threshold</div>
                </div>
            </div>
        </div>
    );
}
