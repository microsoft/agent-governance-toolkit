// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Slot Component
 *
 * Renders a single configurable panel slot within the sidebar.
 * Routes the correct data to the matched panel summary component
 * and provides an expand button to promote to a full webview.
 */
import React from 'react';
import {
    PanelId,
    SidebarState,
    PANEL_LABELS,
} from './types';
import { SLOSummary } from './panels/SLOSummary';
import { AuditSummary } from './panels/AuditSummary';
import { TopologySummary } from './panels/TopologySummary';
import { GovernanceHubSummary } from './panels/GovernanceHubSummary';
import { PolicySummary } from './panels/PolicySummary';
import { StatsSummary } from './panels/StatsSummary';
import { KernelSummary } from './panels/KernelSummary';
import { MemorySummary } from './panels/MemorySummary';

/** Renders the panel content for a given panelId with routed data. */
function PanelContent(props: { panelId: PanelId; state: SidebarState }): React.ReactElement {
    const { panelId, state } = props;
    switch (panelId) {
        case 'slo-dashboard': return <SLOSummary data={state.slo} />;
        case 'audit-log': return <AuditSummary data={state.audit} />;
        case 'agent-topology': return <TopologySummary data={state.topology} />;
        case 'governance-hub': return <GovernanceHubSummary data={state.hub} />;
        case 'active-policies': return <PolicySummary data={state.policy} />;
        case 'safety-stats': return <StatsSummary data={state.stats} />;
        case 'kernel-debugger': return <KernelSummary data={state.kernel} />;
        case 'memory-browser': return <MemorySummary data={state.memory} />;
    }
}

/** Inline 12x12 expand (arrow-up-right) SVG icon. */
function ExpandIcon(): React.ReactElement {
    return (
        <svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
            <path d="M6 2V3H12.3L2 13.3L2.7 14L13 3.7V10H14V2H6Z" />
        </svg>
    );
}

/** Props for a single sidebar slot. */
interface SlotProps {
    position: 'A' | 'B' | 'C';
    panelId: PanelId;
    state: SidebarState;
    stale?: boolean;
    active?: boolean;
    onPromote: (panelId: PanelId) => void;
}

/** Inline 10x10 clock SVG for the staleness indicator. */
function ClockIcon(): React.ReactElement {
    return (
        <svg width="10" height="10" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
            <path d="M8 1C4.1 1 1 4.1 1 8s3.1 7 7 7 7-3.1 7-7-3.1-7-7-7zm0 12.5c-3 0-5.5-2.5-5.5-5.5S5 2.5 8 2.5s5.5 2.5 5.5 5.5-2.5 5.5-5.5 5.5zM8.5 4H7v5l4.3 2.5.7-1.2-3.5-2V4z" />
        </svg>
    );
}

/** Renders the slot header with label, stale badge, and expand button. */
function SlotHeader(
    props: { panelId: PanelId; stale?: boolean; onPromote: () => void },
): React.ReactElement {
    return (
        <div className="flex items-center justify-between px-ml-sm py-ml-xs">
            <span className="text-[10px] uppercase tracking-wider text-ml-text-muted font-medium flex items-center gap-1">
                {PANEL_LABELS[props.panelId]}
                {props.stale && (
                    <span className="text-ml-text-muted opacity-60" title="Refreshing on a slower cadence due to latency">
                        <ClockIcon />
                    </span>
                )}
            </span>
            <button
                className="p-0.5 rounded hover:bg-ml-surface-hover text-ml-text-muted hover:text-ml-text"
                onClick={props.onPromote}
                aria-label={`Expand ${PANEL_LABELS[props.panelId]} to full panel`}
                title="Open in panel"
            >
                <ExpandIcon />
            </button>
        </div>
    );
}

/** Single slot container rendering the appropriate panel summary. */
export function Slot(props: SlotProps): React.ReactElement {
    const { panelId, state, stale, active, onPromote } = props;
    const borderClass = active ? 'border-l-2 border-ml-accent' : 'border-l-2 border-transparent';

    return (
        <div
            className={`flex-1 flex flex-col min-h-0 ${borderClass} focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ml-accent`}
            tabIndex={0}
            role="region"
            aria-label={PANEL_LABELS[panelId]}
        >
            <SlotHeader
                panelId={panelId}
                stale={stale}
                onPromote={() => onPromote(panelId)}
            />
            <div className="flex-1 overflow-auto px-ml-sm pb-ml-xs">
                <PanelContent panelId={panelId} state={state} />
            </div>
        </div>
    );
}
