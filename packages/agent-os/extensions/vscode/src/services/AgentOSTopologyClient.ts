// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Agent OS Topology Client
 *
 * Real backend client that queries agentmesh for topology data via the
 * ServiceTransport abstraction. Methods are synchronous and return
 * cached data; refresh is triggered asynchronously from getAgents().
 */

import type {
    AgentTopologyDataProvider,
    AgentNode,
    BridgeStatus,
    DelegationChain,
} from '../views/topologyTypes';
import type { ServiceTransport } from './serviceTypes';
import type { RawAgent, RawBridge, RawDelegation } from './translators';
import { translateAgent, translateBridge, translateDelegation } from './translators';

/** Raw topology snapshot from the Python backend. */
interface RawTopologyPayload {
    agents?: RawAgent[];
    bridges?: RawBridge[];
    delegations?: RawDelegation[];
}

export class AgentOSTopologyClient implements AgentTopologyDataProvider {
    private readonly transport: ServiceTransport;
    private _agents: AgentNode[] = [];
    private _bridges: BridgeStatus[] = [];
    private _delegations: DelegationChain[] = [];
    private _refreshing = false;

    constructor(transport: ServiceTransport) {
        this.transport = transport;
    }

    getAgents(): AgentNode[] {
        this._triggerRefresh();
        return this._agents;
    }

    getBridges(): BridgeStatus[] {
        return this._bridges;
    }

    getDelegations(): DelegationChain[] {
        return this._delegations;
    }

    /** Trigger an async refresh. Safe to call multiple times. */
    private _triggerRefresh(): void {
        if (this._refreshing) { return; }
        this._refreshing = true;
        void this._refresh().finally(() => { this._refreshing = false; });
    }

    /** Fetch fresh topology data from the backend. */
    private async _refresh(): Promise<void> {
        const response = await this.transport.query<RawTopologyPayload>(
            'agentmesh.topology',
            'snapshot',
        );
        if (!response.ok || !response.data) { return; }

        const payload = response.data;
        this._agents = (payload.agents ?? []).map(translateAgent);
        this._bridges = (payload.bridges ?? []).map(translateBridge);
        this._delegations = (payload.delegations ?? []).map(translateDelegation);
    }

    /**
     * Public refresh for testing. Awaits the refresh to completion.
     * Production code uses getAgents() which triggers fire-and-forget.
     */
    async refreshForTest(): Promise<void> {
        await this._refresh();
    }
}
