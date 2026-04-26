// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import * as assert from 'assert';
import {
    deriveHub, fetchSLO, fetchTopology, fetchAudit,
    fetchPolicy, fetchStats, fetchKernel, fetchMemory,
} from '../../webviews/sidebar/dataAggregator';
import type { SidebarState } from '../../webviews/sidebar/types';
import { DEFAULT_SLOTS } from '../../webviews/sidebar/types';

function makeState(overrides?: Partial<SidebarState>): SidebarState {
    return {
        slots: DEFAULT_SLOTS, userSlots: DEFAULT_SLOTS, attentionMode: 'auto',
        slo: null, audit: null, topology: null, policy: null,
        stats: null, kernel: null, memory: null, hub: null,
        stalePanels: [],
        ...overrides,
    };
}

suite('deriveHub', () => {
    test('all nulls → healthy with zero alerts', () => {
        const hub = deriveHub(makeState());
        assert.strictEqual(hub.overallHealth, 'healthy');
        assert.strictEqual(hub.activeAlerts, 0);
    });

    test('violations=1 → warning', () => {
        const hub = deriveHub(makeState({
            audit: { totalToday: 5, violationsToday: 1, lastEventTime: null, lastEventAction: null },
        }));
        assert.strictEqual(hub.overallHealth, 'warning');
    });

    test('violations=6 → critical', () => {
        const hub = deriveHub(makeState({
            audit: { totalToday: 10, violationsToday: 3, lastEventTime: null, lastEventAction: null },
            kernel: { activeAgents: 1, policyViolations: 4, totalCheckpoints: 5, uptimeSeconds: 100 },
        }));
        assert.strictEqual(hub.overallHealth, 'critical');
        assert.strictEqual(hub.activeAlerts, 7);
    });

    test('compliance=94 → warning', () => {
        const hub = deriveHub(makeState({
            slo: { availability: 99.9, availabilityTarget: 99.5, latencyP99: 100, latencyTarget: 200, compliancePercent: 94, violationsToday: 0, trustMean: 800, agentsBelowThreshold: 0 },
        }));
        assert.strictEqual(hub.overallHealth, 'warning');
    });

    test('compliance=89 → critical', () => {
        const hub = deriveHub(makeState({
            slo: { availability: 99.9, availabilityTarget: 99.5, latencyP99: 100, latencyTarget: 200, compliancePercent: 89, violationsToday: 0, trustMean: 800, agentsBelowThreshold: 0 },
        }));
        assert.strictEqual(hub.overallHealth, 'critical');
    });

    test('agentCount from topology', () => {
        const hub = deriveHub(makeState({
            topology: { agentCount: 5, bridgeCount: 2, meanTrust: 700, delegationCount: 1 },
        }));
        assert.strictEqual(hub.agentCount, 5);
    });
});

suite('fetchSLO', () => {
    test('returns null when provider throws', async () => {
        const p = { slo: { getSnapshot: async () => { throw new Error('fail'); } } } as any;
        assert.strictEqual(await fetchSLO(p), null);
    });

    test('maps snapshot correctly', async () => {
        const p = {
            slo: {
                getSnapshot: async () => ({
                    availability: { currentPercent: 99.8, targetPercent: 99.5 },
                    latency: { p99Ms: 150, targetMs: 200 },
                    policyCompliance: { compliancePercent: 97, violationsToday: 2 },
                    trustScore: { meanScore: 720, agentsBelowThreshold: 1 },
                }),
            },
        } as any;
        const result = await fetchSLO(p);
        assert.ok(result);
        assert.strictEqual(result.availability, 99.8);
        assert.strictEqual(result.violationsToday, 2);
        assert.strictEqual(result.trustMean, 720);
    });
});

suite('fetchTopology', () => {
    test('returns null when provider throws', () => {
        const p = { topology: { getAgents: () => { throw new Error('fail'); } } } as any;
        assert.strictEqual(fetchTopology(p), null);
    });

    test('computes mean trust correctly', () => {
        const p = {
            topology: {
                getAgents: () => [{ trustScore: 600 }, { trustScore: 800 }],
                getBridges: () => [{ connected: true }, { connected: false }],
                getDelegations: () => [{}],
            },
        } as any;
        const result = fetchTopology(p);
        assert.ok(result);
        assert.strictEqual(result.meanTrust, 700);
        assert.strictEqual(result.bridgeCount, 1);
        assert.strictEqual(result.delegationCount, 1);
    });
});

suite('fetchAudit', () => {
    test('empty log returns zeros', () => {
        const p = { audit: { getAll: () => [] } } as any;
        const result = fetchAudit(p);
        assert.ok(result);
        assert.strictEqual(result.totalToday, 0);
        assert.strictEqual(result.violationsToday, 0);
        assert.strictEqual(result.lastEventTime, null);
    });

    test('counts today entries and violations', () => {
        const today = new Date();
        const p = {
            audit: {
                getAll: () => [
                    { timestamp: today, type: 'allowed' },
                    { timestamp: today, type: 'blocked' },
                    { timestamp: today, type: 'blocked' },
                ],
            },
        } as any;
        const result = fetchAudit(p);
        assert.ok(result);
        assert.strictEqual(result.totalToday, 3);
        assert.strictEqual(result.violationsToday, 2);
    });

    test('returns last event time and action', () => {
        const ts = new Date('2026-03-27T12:00:00Z');
        const p = {
            audit: { getAll: () => [{ timestamp: ts, type: 'warning' }] },
        } as any;
        const result = fetchAudit(p);
        assert.ok(result);
        assert.strictEqual(result.lastEventTime, ts.toISOString());
        assert.strictEqual(result.lastEventAction, 'warning');
    });
});

suite('fetchPolicy', () => {
    test('returns null when provider throws', async () => {
        const p = { policy: { getSnapshot: async () => { throw new Error('fail'); } } } as any;
        assert.strictEqual(await fetchPolicy(p), null);
    });
});

suite('fetchStats', () => {
    test('returns null when provider throws', () => {
        const p = { audit: { getStats: () => { throw new Error('fail'); } } } as any;
        assert.strictEqual(fetchStats(p), null);
    });
});

suite('fetchKernel', () => {
    test('returns null when provider throws', () => {
        const p = { kernel: { getKernelSummary: () => { throw new Error('fail'); } } } as any;
        assert.strictEqual(fetchKernel(p), null);
    });
});

suite('fetchMemory', () => {
    test('returns null when provider throws', () => {
        const p = { memory: { getVfsSummary: () => { throw new Error('fail'); } } } as any;
        assert.strictEqual(fetchMemory(p), null);
    });
});
