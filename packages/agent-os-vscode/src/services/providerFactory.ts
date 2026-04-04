// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Provider Factory
 *
 * Creates data providers for the governance dashboard. On activation,
 * attempts to start a local agent-failsafe REST server. If agent-failsafe
 * is installed, dashboards populate with live governance data. If not,
 * returns disconnected providers with empty state.
 */

import { SLODataProvider, SLOSnapshot } from '../views/sloTypes';
import { AgentTopologyDataProvider, AgentNode } from '../views/topologyTypes';
import { PolicyDataProvider, PolicySnapshot } from '../views/policyTypes';
import { LiveSREClient } from './liveClient';
import { translateSLO, translateTopology, translatePolicy } from './translators';
import { SREServerManager, isAgentFailsafeAvailable, promptAndInstall } from './sreServer';

/** Configuration for the provider factory. */
export interface ProviderConfig {
    /** Python interpreter path. */
    pythonPath: string;
    /** Explicit endpoint override (bypasses auto-start). */
    endpoint?: string;
    /** Optional bearer token for authenticated endpoints. */
    token?: string;
    /** Polling interval in ms (minimum 5000). */
    refreshIntervalMs?: number;
}

/** Bundle of all data providers used by the extension. */
export interface Providers {
    /** SLO data source. */
    slo: SLODataProvider;
    /** Agent topology data source. */
    topology: AgentTopologyDataProvider;
    /** Policy data source. */
    policy: PolicyDataProvider;
    /** LiveSREClient instance for event subscription (null if disconnected). */
    liveClient: LiveSREClient | null;
    /** Status message describing the connection state. */
    status: 'live' | 'disconnected' | 'not-installed';
    /** Release all resources (HTTP client + subprocess). */
    dispose(): void;
}

function emptySnapshot(): SLOSnapshot {
    return {
        availability: { currentPercent: 0, targetPercent: 0, errorBudgetRemainingPercent: 0, burnRate: 0 },
        latency: { p50Ms: 0, p95Ms: 0, p99Ms: 0, targetMs: 0, errorBudgetRemainingPercent: 0 },
        policyCompliance: { totalEvaluations: 0, violationsToday: 0, compliancePercent: 0, trend: 'stable' },
        trustScore: { meanScore: 0, minScore: 0, agentsBelowThreshold: 0, distribution: [0, 0, 0, 0] },
    };
}

function emptyPolicy(): PolicySnapshot {
    return { rules: [], recentViolations: [], totalEvaluationsToday: 0, totalViolationsToday: 0 };
}

/**
 * Create data providers. Attempts to start a local agent-failsafe server.
 *
 * @param config - Provider configuration with Python path.
 * @returns Providers bundle with status indicating live, disconnected, or not-installed.
 */
export async function createProviders(config: ProviderConfig): Promise<Providers> {
    // Explicit endpoint override — connect directly (for advanced users)
    if (config.endpoint) {
        return createLiveProviders(config.endpoint, config);
    }

    // Auto-detect agent-failsafe; offer to install if missing
    let available = await isAgentFailsafeAvailable(config.pythonPath);
    if (!available) {
        const installed = await promptAndInstall(config.pythonPath);
        if (!installed) {
            return createDisconnectedProviders('not-installed');
        }
        available = await isAgentFailsafeAvailable(config.pythonPath);
        if (!available) {
            return createDisconnectedProviders('not-installed');
        }
    }

    const server = new SREServerManager(config.pythonPath);
    const result = await server.start();
    if (!result.ok) {
        return createDisconnectedProviders('disconnected');
    }

    return createLiveProviders(result.endpoint, config, server);
}

function createDisconnectedProviders(status: 'disconnected' | 'not-installed'): Providers {
    return {
        slo: { getSnapshot: async () => emptySnapshot() },
        topology: { getAgents: () => [], getBridges: () => [], getDelegations: () => [] },
        policy: { getSnapshot: async () => emptyPolicy() },
        liveClient: null,
        status,
        dispose() { /* nothing to release */ },
    };
}

function createLiveProviders(
    endpoint: string,
    config: ProviderConfig,
    server?: SREServerManager,
): Providers {
    const client = new LiveSREClient({
        endpoint,
        token: config.token,
        refreshIntervalMs: config.refreshIntervalMs,
    });
    client.start();

    return {
        slo: {
            async getSnapshot(): Promise<SLOSnapshot> {
                const snap = client.getSnapshot();
                if (!snap.data || snap.stale) { return emptySnapshot(); }
                return translateSLO(snap.data) ?? emptySnapshot();
            },
        },
        topology: {
            getAgents(): AgentNode[] {
                const snap = client.getSnapshot();
                if (!snap.data || snap.stale) { return []; }
                return translateTopology(snap.data);
            },
            getBridges() { return []; },
            getDelegations() { return []; },
        },
        policy: {
            async getSnapshot(): Promise<PolicySnapshot> {
                const snap = client.getSnapshot();
                if (!snap.data || snap.stale) { return emptyPolicy(); }
                return translatePolicy(snap.data);
            },
        },
        liveClient: client,
        status: 'live',
        dispose() {
            client.dispose();
            server?.stop();
        },
    };
}
