// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * SLO Detail Panel
 *
 * Root component for the full-panel SLO dashboard. Displays gauges,
 * sparklines, budget bars, and trust distribution in a structured layout.
 */

import React from 'react';
import { DetailShell } from '../shared/DetailShell';
import { useExtensionMessage } from '../shared/useExtensionMessage';
import { getVSCodeAPI } from '../shared/vscode';
import { trustColor } from '../sidebar/healthColors';
import { Tooltip } from '../shared/Tooltip';
import { HELP } from '../shared/helpContent';
import type { SLODetailData } from '../shared/types';
import { SLOGauge } from './SLOGauge';
import { SLOSparkline } from './SLOSparkline';
import { SLOBudgetBar } from './SLOBudgetBar';

interface SLODetailProps {
    /** Optional data prop for testing. Falls back to extension messages. */
    data?: SLODetailData;
    /** When true, render content only (no DetailShell wrapper). Used by Hub embedding. */
    embedded?: boolean;
}

/** Trust distribution bucket labels. */
const TRUST_BUCKETS = ['0-250', '251-500', '501-750', '751-1000'] as const;

/** Trust bucket midpoint scores for color mapping. */
const TRUST_MIDPOINTS = [125, 375, 625, 875] as const;

/** Loading placeholder shown before data arrives. */
function LoadingState(): React.JSX.Element {
    return (
        <div className="flex items-center justify-center h-64 text-ml-text-muted text-sm">
            Waiting for SLO data...
        </div>
    );
}

/** Top row: availability and compliance gauges side by side. */
function GaugeRow({ data }: { data: SLODetailData }): React.JSX.Element {
    return (
        <div className="grid grid-cols-2 gap-ml-md">
            <SLOGauge
                value={data.availability}
                target={data.availabilityTarget}
                label="Availability"
            />
            <SLOGauge
                value={data.compliancePercent}
                target={data.complianceTarget}
                label="Compliance"
            />
        </div>
    );
}

/** Latency breakdown with stacked bars for P50, P95, P99. */
function LatencySection({ data }: { data: SLODetailData }): React.JSX.Element {
    return (
        <section className="flex flex-col gap-2">
            <h2 className="text-sm font-semibold text-ml-text-bright flex items-center gap-1">
                Latency <Tooltip text={HELP.slo.latencyP99} />
            </h2>
            <LatencyBar label="P50" value={data.latencyP50} target={data.latencyTarget} />
            <LatencyBar label="P95" value={data.latencyP95} target={data.latencyTarget} />
            <LatencyBar label="P99" value={data.latencyP99} target={data.latencyTarget} />
        </section>
    );
}

/** Single latency bar showing value vs target. */
function LatencyBar({ label, value, target }: { label: string; value: number; target: number }): React.JSX.Element {
    const pct = Math.min((value / target) * 100, 150);
    const isOver = value > target;
    const color = isOver ? 'var(--vscode-errorForeground)' : 'var(--vscode-testing-iconPassed)';

    return (
        <div className="flex items-center gap-2">
            <span className="w-8 text-xs text-ml-text-muted font-mono">{label}</span>
            <div className="flex-1 h-2 rounded-full bg-ml-surface overflow-hidden">
                <div
                    className="h-full rounded-full"
                    style={{
                        width: `${Math.min(pct, 100)}%`,
                        backgroundColor: color,
                        transition: 'width 0.4s ease-out',
                    }}
                />
            </div>
            <span className="w-16 text-xs text-ml-text font-mono text-right">
                {value.toFixed(0)}ms
            </span>
        </div>
    );
}

/** Burn rate sparkline with current value label. */
function BurnRateSection({ data }: { data: SLODetailData }): React.JSX.Element {
    return (
        <section className="flex flex-col gap-2">
            <div className="flex justify-between items-baseline">
                <h2 className="text-sm font-semibold text-ml-text-bright flex items-center gap-1">
                    Burn Rate <Tooltip text={HELP.slo.burnRate} />
                </h2>
                <span className="text-xs text-ml-text font-mono">{data.burnRate.toFixed(2)}x</span>
            </div>
            <SLOSparkline points={data.burnRateSeries} height={60} />
        </section>
    );
}

/** Error budget bars for availability and latency. */
function BudgetSection({ data }: { data: SLODetailData }): React.JSX.Element {
    const availConsumed = 100 - data.availabilityBudgetRemaining;
    const latencyConsumed = 100 - data.latencyBudgetRemaining;

    return (
        <section className="flex flex-col gap-3">
            <h2 className="text-sm font-semibold text-ml-text-bright flex items-center gap-1">
                Error Budgets <Tooltip text={HELP.slo.budgetAvailability} />
            </h2>
            <SLOBudgetBar consumed={availConsumed} total={100} label="Availability" />
            <SLOBudgetBar consumed={latencyConsumed} total={100} label="Latency" />
        </section>
    );
}

/** Trust distribution as horizontal segments with counts. */
function TrustSection({ data }: { data: SLODetailData }): React.JSX.Element {
    const total = data.trustDistribution.reduce((a, b) => a + b, 0) || 1;

    return (
        <section className="flex flex-col gap-2">
            <div className="flex justify-between items-baseline">
                <h2 className="text-sm font-semibold text-ml-text-bright flex items-center gap-1">
                    Trust Distribution <Tooltip text={HELP.slo.trust} />
                </h2>
                <span className="text-xs text-ml-text-muted">
                    mean {data.trustMean.toFixed(0)} / min {data.trustMin.toFixed(0)}
                </span>
            </div>
            <div className="flex flex-col gap-1">
                {data.trustDistribution.map((count, i) => (
                    <TrustBucket
                        key={TRUST_BUCKETS[i]}
                        label={TRUST_BUCKETS[i]}
                        count={count}
                        total={total}
                        midpoint={TRUST_MIDPOINTS[i]}
                    />
                ))}
            </div>
        </section>
    );
}

/** Single trust distribution bucket row. */
function TrustBucket(
    { label, count, total, midpoint }: { label: string; count: number; total: number; midpoint: number }
): React.JSX.Element {
    const pct = (count / total) * 100;
    const colorClass = trustColor(midpoint);
    const colorMap: Record<string, string> = {
        'text-ml-success': 'var(--vscode-testing-iconPassed)',
        'text-ml-warning': 'var(--vscode-list-warningForeground)',
        'text-ml-error': 'var(--vscode-errorForeground)',
    };
    const color = colorMap[colorClass] ?? 'var(--vscode-foreground)';

    return (
        <div className="flex items-center gap-2">
            <span className="w-16 text-xs text-ml-text-muted font-mono">{label}</span>
            <div className="flex-1 h-2 rounded-full bg-ml-surface overflow-hidden">
                <div
                    className="h-full rounded-full"
                    style={{
                        width: `${pct}%`,
                        backgroundColor: color,
                        transition: 'width 0.4s ease-out',
                    }}
                />
            </div>
            <span className="w-8 text-xs text-ml-text font-mono text-right">{count}</span>
        </div>
    );
}

/**
 * Root SLO detail panel component.
 *
 * Accepts optional data prop for testing. When not provided,
 * listens for 'sloDetailUpdate' messages from the extension host.
 */
export function SLODetail({ data: propData, embedded }: SLODetailProps = {}): React.JSX.Element {
    const messageData = useExtensionMessage<SLODetailData>('sloDetailUpdate');
    const data = propData ?? messageData;
    const content = data ? <SLOContent data={data} /> : <LoadingState />;

    if (embedded) { return content; }

    return (
        <DetailShell
            title="SLO Dashboard"
            timestamp={data?.fetchedAt ?? null}
            onRefresh={() => getVSCodeAPI().postMessage({ type: 'refresh' })}
        >
            {content}
        </DetailShell>
    );
}

/** Main content layout with all SLO sections. Exported for Hub embedding. */
export function SLOContent({ data }: { data: SLODetailData }): React.JSX.Element {
    return (
        <div className="flex flex-col gap-ml-lg">
            <GaugeRow data={data} />
            <LatencySection data={data} />
            <BurnRateSection data={data} />
            <BudgetSection data={data} />
            <TrustSection data={data} />
        </div>
    );
}
