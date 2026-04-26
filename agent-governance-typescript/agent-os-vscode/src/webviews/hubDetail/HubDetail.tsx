// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Hub Detail
 *
 * Root composite dashboard for the Governance Hub panel.
 * Aggregates SLO, Topology, Audit, and Policy views behind
 * a tabbed interface, reusing Phase 1 and Phase 2 detail components.
 */

import React, { useState } from 'react';
import type { HubDetailData } from '../shared/types';
import { useExtensionMessage } from '../shared/useExtensionMessage';
import { getVSCodeAPI } from '../shared/vscode';
import { DetailShell } from '../shared/DetailShell';
import { Tooltip } from '../shared/Tooltip';
import { HELP } from '../shared/helpContent';
import { HubTabBar } from './HubTabBar';
import type { TabDef } from './HubTabBar';
import { SLODetail } from '../sloDetail/SLODetail';
import { TopologyDetail } from '../topologyDetail/TopologyDetail';
import { HubAuditTab } from './HubAuditTab';
import { HubPolicyTab } from './HubPolicyTab';

/** Tooltip text for each hub tab. */
const TAB_TOOLTIPS: Record<string, string> = {
    slo: HELP.hub.sloTab,
    topology: HELP.hub.topologyTab,
    audit: HELP.hub.auditTab,
    policies: HELP.hub.policiesTab,
};

/** Tab definitions for the hub panel. */
const TABS: TabDef[] = [
    { id: 'slo', label: 'SLO' },
    { id: 'topology', label: 'Topology' },
    { id: 'audit', label: 'Audit' },
    { id: 'policies', label: 'Policies' },
];

/** Post a refresh request to the extension host. */
function requestRefresh(): void {
    getVSCodeAPI().postMessage({ type: 'refresh' });
}

/** Check if all data sections are null (initial loading state). */
function isAllNull(data: HubDetailData | null): boolean {
    if (!data) { return true; }
    return !data.slo && !data.topology && !data.audit && !data.policy;
}

/** Loading placeholder shown before any data arrives. */
function LoadingState(): React.JSX.Element {
    return (
        <div className="flex items-center justify-center py-ml-xl">
            <p className="text-sm text-ml-text-muted">Loading governance data...</p>
        </div>
    );
}

/** Render the active tab content based on tab ID. */
function TabContent(
    { activeTab, data }: { activeTab: string; data: HubDetailData | null },
): React.JSX.Element {
    if (activeTab === 'slo') {
        return <SLODetail data={data?.slo ?? undefined} embedded />;
    }
    if (activeTab === 'topology') {
        return <TopologyDetail data={data?.topology ?? undefined} embedded />;
    }
    if (activeTab === 'audit') {
        return <HubAuditTab data={data?.audit ?? null} />;
    }
    return <HubPolicyTab data={data?.policy ?? null} />;
}

/**
 * Governance Hub detail panel.
 *
 * Subscribes to 'hubDetailUpdate' messages and distributes
 * data to the appropriate tab component. When SLO or Topology
 * data is passed as a prop, those components skip their own
 * message subscription.
 */
export function HubDetail(): React.JSX.Element {
    const data = useExtensionMessage<HubDetailData>('hubDetailUpdate');
    const [activeTab, setActiveTab] = useState('slo');

    return (
        <DetailShell
            title="Governance Hub"
            timestamp={data?.fetchedAt ?? null}
            onRefresh={requestRefresh}
        >
            <div className="flex items-center gap-1">
                <HubTabBar tabs={TABS} activeId={activeTab} onSelect={setActiveTab} />
                <Tooltip text={TAB_TOOLTIPS[activeTab] ?? ''} />
            </div>
            <div className="flex-1 overflow-y-auto pt-ml-sm" role="tabpanel">
                {isAllNull(data)
                    ? <LoadingState />
                    : <TabContent activeTab={activeTab} data={data} />}
            </div>
        </DetailShell>
    );
}
