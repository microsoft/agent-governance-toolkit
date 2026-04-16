// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Unit tests for detail fetcher functions.
 *
 * Tests pure data mapping with no VS Code dependencies.
 * Mock providers are constructed inline to match DataProviders interface.
 */

import * as assert from 'assert';
import {
    fetchSLODetail,
    fetchTopologyDetail,
} from '../../webviews/sidebar/detailFetchers';

// ---------------------------------------------------------------------------
// Mock provider factory
// ---------------------------------------------------------------------------

function mockProviders(overrides?: Record<string, unknown>): any {
    return {
        slo: {
            getSnapshot: async () => ({
                availability: {
                    currentPercent: 99.8,
                    targetPercent: 99.5,
                    errorBudgetRemainingPercent: 42,
                    burnRate: 1.2,
                },
                latency: {
                    p50Ms: 10,
                    p95Ms: 50,
                    p99Ms: 150,
                    targetMs: 200,
                    errorBudgetRemainingPercent: 60,
                },
                policyCompliance: {
                    totalEvaluations: 500,
                    violationsToday: 3,
                    compliancePercent: 97,
                    trend: 'stable' as const,
                },
                trustScore: {
                    meanScore: 720,
                    minScore: 350,
                    agentsBelowThreshold: 1,
                    distribution: [2, 5, 8, 15] as [number, number, number, number],
                },
                fetchedAt: '2026-03-27T12:00:00Z',
            }),
        },
        topology: {
            getAgents: () => [
                {
                    did: 'did:mesh:abcdef1234567890abcdef1234567890',
                    trustScore: 800,
                    ring: 2,
                    registeredAt: '2026-01-01T00:00:00Z',
                    lastActivity: '2026-03-27T12:00:00Z',
                    capabilities: ['read', 'write'],
                },
                {
                    did: 'did:mesh:short',
                    trustScore: 400,
                    ring: 3,
                    registeredAt: '2026-02-01T00:00:00Z',
                    lastActivity: '2026-03-27T11:00:00Z',
                    capabilities: ['read'],
                },
            ],
            getBridges: () => [
                { protocol: 'A2A', connected: true, peerCount: 3 },
                { protocol: 'MCP', connected: false, peerCount: 0 },
            ],
            getDelegations: () => [
                {
                    fromDid: 'did:mesh:aaa',
                    toDid: 'did:mesh:bbb',
                    capability: 'file.write',
                    expiresIn: '2h',
                },
            ],
        },
        audit: {
            getAll: () => [
                { timestamp: new Date('2026-03-27T10:00:00Z'), type: 'blocked', agentDid: 'did:mesh:a', file: '/src/main.ts' },
                { timestamp: new Date('2026-03-27T10:05:00Z'), type: 'warned', agentDid: 'did:mesh:b', file: null },
                { timestamp: new Date('2026-03-27T10:10:00Z'), type: 'allowed', agentDid: null, file: '/src/lib.ts' },
            ],
            getStats: () => ({
                blockedToday: 1, blockedThisWeek: 5,
                warningsToday: 1, cmvkReviewsToday: 0, totalLogs: 3,
            }),
        },
        policy: {
            getSnapshot: async () => ({
                rules: [
                    { id: 'r1', name: 'Block secrets', action: 'BLOCK', pattern: '*.env', scope: 'file', enabled: true, evaluationsToday: 100, violationsToday: 2, description: '' },
                    { id: 'r2', name: 'Audit reads', action: 'AUDIT', pattern: '*', scope: 'global', enabled: true, evaluationsToday: 400, violationsToday: 0, description: '' },
                    { id: 'r3', name: 'Disabled rule', action: 'DENY', pattern: '*.tmp', scope: 'file', enabled: false, evaluationsToday: 0, violationsToday: 0, description: '' },
                ],
                recentViolations: [],
                totalEvaluationsToday: 500,
                totalViolationsToday: 2,
                fetchedAt: '2026-03-27T12:00:00Z',
            }),
        },
        kernel: {
            getKernelSummary: () => ({
                activeAgents: 4, policyViolations: 1,
                totalCheckpoints: 20, uptime: 3600,
            }),
        },
        memory: {
            getVfsSummary: () => ({
                directoryCount: 10, fileCount: 42, rootPaths: ['/workspace'],
            }),
        },
        ...overrides,
    };
}

// ---------------------------------------------------------------------------
// fetchSLODetail
// ---------------------------------------------------------------------------

suite('detailFetchers - fetchSLODetail', () => {
    test('returns complete SLODetailData shape from mock provider', async () => {
        const result = await fetchSLODetail(mockProviders());
        assert.ok(result, 'Expected non-null result');
        assert.strictEqual(result.availability, 99.8);
        assert.strictEqual(result.availabilityTarget, 99.5);
        assert.strictEqual(result.availabilityBudgetRemaining, 42);
        assert.strictEqual(result.burnRate, 1.2);
        assert.strictEqual(result.burnRateSeries.length, 24);
        assert.strictEqual(result.latencyP50, 10);
        assert.strictEqual(result.latencyP95, 50);
        assert.strictEqual(result.latencyP99, 150);
        assert.strictEqual(result.latencyTarget, 200);
        assert.strictEqual(result.latencyBudgetRemaining, 60);
        assert.strictEqual(result.compliancePercent, 97);
        assert.strictEqual(result.complianceTarget, 100);
        assert.strictEqual(result.violationsToday, 3);
        assert.strictEqual(result.complianceTrend, 'stable');
        assert.strictEqual(result.trustMean, 720);
        assert.strictEqual(result.trustMin, 350);
        assert.deepStrictEqual(result.trustDistribution, [2, 5, 8, 15]);
        assert.strictEqual(result.fetchedAt, '2026-03-27T12:00:00Z');
    });

    test('burn rate series contains 24 numeric points', async () => {
        const result = await fetchSLODetail(mockProviders());
        assert.ok(result);
        assert.strictEqual(result.burnRateSeries.length, 24);
        for (const point of result.burnRateSeries) {
            assert.strictEqual(typeof point, 'number');
            assert.ok(!isNaN(point), 'Burn rate point should not be NaN');
        }
    });

    test('returns null on provider error', async () => {
        const broken = mockProviders({
            slo: { getSnapshot: async () => { throw new Error('fail'); } },
        });
        const result = await fetchSLODetail(broken);
        assert.strictEqual(result, null);
    });
});

// ---------------------------------------------------------------------------
// fetchTopologyDetail
// ---------------------------------------------------------------------------

suite('detailFetchers - fetchTopologyDetail', () => {
    test('maps AgentNode array to TopologyNode array', () => {
        const result = fetchTopologyDetail(mockProviders());
        assert.ok(result);
        assert.strictEqual(result.nodes.length, 2);
        assert.strictEqual(result.nodes[0].id, 'did:mesh:abcdef1234567890abcdef1234567890');
        assert.strictEqual(result.nodes[0].trust, 800);
        assert.strictEqual(result.nodes[0].ring, 2);
        assert.strictEqual(result.nodes[1].trust, 400);
        assert.strictEqual(result.nodes[1].ring, 3);
    });

    test('truncates DIDs in node labels', () => {
        const result = fetchTopologyDetail(mockProviders());
        assert.ok(result);
        // Long DID should be truncated to 22 chars + '...'
        const longLabel = result.nodes[0].label;
        assert.ok(longLabel.endsWith('...'), `Expected truncation, got: ${longLabel}`);
        assert.strictEqual(longLabel.length, 25); // 22 + 3 for '...'

        // Short DID should remain unchanged
        const shortLabel = result.nodes[1].label;
        assert.strictEqual(shortLabel, 'did:mesh:short');
    });

    test('maps delegations to edges with capability', () => {
        const result = fetchTopologyDetail(mockProviders());
        assert.ok(result);
        assert.strictEqual(result.edges.length, 1);
        assert.strictEqual(result.edges[0].source, 'did:mesh:aaa');
        assert.strictEqual(result.edges[0].target, 'did:mesh:bbb');
        assert.strictEqual(result.edges[0].capability, 'file.write');
    });

    test('maps bridges with protocol and status', () => {
        const result = fetchTopologyDetail(mockProviders());
        assert.ok(result);
        assert.strictEqual(result.bridges.length, 2);
        assert.strictEqual(result.bridges[0].protocol, 'A2A');
        assert.strictEqual(result.bridges[0].connected, true);
        assert.strictEqual(result.bridges[1].connected, false);
    });

    test('returns null on provider error', () => {
        const broken = mockProviders({
            topology: { getAgents: () => { throw new Error('fail'); } },
        });
        assert.strictEqual(fetchTopologyDetail(broken), null);
    });
});

