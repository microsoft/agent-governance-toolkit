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
    onPromote: (panelId: PanelId) => void;
}

/** Renders the slot header with label and expand button. */
function SlotHeader(
    props: { panelId: PanelId; onPromote: () => void },
): React.ReactElement {
    return (
        <div className="flex items-center justify-between px-ml-sm py-ml-xs">
            <span className="text-[10px] uppercase tracking-wider text-ml-text-muted font-medium">
                {PANEL_LABELS[props.panelId]}
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
    const { panelId, state, onPromote } = props;

    return (
        <div className="flex-1 flex flex-col min-h-0">
            <SlotHeader
                panelId={panelId}
                onPromote={() => onPromote(panelId)}
            />
            <div className="flex-1 overflow-auto px-ml-sm pb-ml-xs">
                <PanelContent panelId={panelId} state={state} />
            </div>
        </div>
    );
}
