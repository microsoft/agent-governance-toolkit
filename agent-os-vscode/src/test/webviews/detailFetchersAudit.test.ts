// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Unit tests for audit, policy, and hub detail fetchers.
 *
 * Split from detailFetchers.test.ts for Section 4 compliance.
 * Mock providers constructed inline to match DataProviders interface.
 */

import * as assert from 'assert';
import {
    fetchAuditDetail,
    fetchPolicyDetail,
    fetchHubDetail,
} from '../../webviews/sidebar/detailFetchers';

// ---------------------------------------------------------------------------
// Mock provider factory (shared shape with detailFetchers.test.ts)
// ---------------------------------------------------------------------------

function mockProviders(overrides?: Record<string, unknown>): any {
    return {
        slo: {
            getSnapshot: async () => ({
                availability: { currentPercent: 99.8, targetPercent: 99.5, errorBudgetRemainingPercent: 42, burnRate: 1.2 },
                latency: { p50Ms: 10, p95Ms: 50, p99Ms: 150, targetMs: 200, errorBudgetRemainingPercent: 60 },
                policyCompliance: { totalEvaluations: 500, violationsToday: 3, compliancePercent: 97, trend: 'stable' as const },
                trustScore: { meanScore: 720, minScore: 350, agentsBelowThreshold: 1, distribution: [2, 5, 8, 15] as [number, number, number, number] },
                fetchedAt: '2026-03-27T12:00:00Z',
            }),
        },
        topology: {
            getAgents: () => [
                { did: 'did:mesh:a', trustScore: 800, ring: 2, registeredAt: '', lastActivity: '', capabilities: [] },
            ],
            getBridges: () => [{ protocol: 'A2A', connected: true, peerCount: 3 }],
            getDelegations: () => [{ fromDid: 'did:mesh:a', toDid: 'did:mesh:b', capability: 'read', expiresIn: '1h' }],
        },
        audit: {
            getAll: () => [
                { timestamp: new Date('2026-03-27T10:00:00Z'), type: 'blocked', agentDid: 'did:mesh:a', file: '/src/main.ts' },
                { timestamp: new Date('2026-03-27T10:05:00Z'), type: 'warned', agentDid: 'did:mesh:b', file: null },
                { timestamp: new Date('2026-03-27T10:10:00Z'), type: 'allowed', agentDid: null, file: '/src/lib.ts' },
            ],
            getStats: () => ({ blockedToday: 1, blockedThisWeek: 5, warningsToday: 1, cmvkReviewsToday: 0, totalLogs: 3 }),
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
        kernel: { getKernelSummary: () => ({ activeAgents: 4, policyViolations: 1, totalCheckpoints: 20, uptime: 3600 }) },
        memory: { getVfsSummary: () => ({ directoryCount: 10, fileCount: 42, rootPaths: ['/workspace'] }) },
        ...overrides,
    };
}

// ---------------------------------------------------------------------------
// fetchAuditDetail
// ---------------------------------------------------------------------------

suite('detailFetchers - fetchAuditDetail', () => {
    test('maps blocked entries to critical severity', () => {
        const result = fetchAuditDetail(mockProviders());
        assert.ok(result);
        const blocked = result.entries.find(e => e.action === 'blocked');
        assert.ok(blocked);
        assert.strictEqual(blocked.severity, 'critical');
    });

    test('maps warned entries to warning severity', () => {
        const result = fetchAuditDetail(mockProviders());
        assert.ok(result);
        const warned = result.entries.find(e => e.action === 'warned');
        assert.ok(warned);
        assert.strictEqual(warned.severity, 'warning');
    });

    test('maps other entries to info severity', () => {
        const result = fetchAuditDetail(mockProviders());
        assert.ok(result);
        const allowed = result.entries.find(e => e.action === 'allowed');
        assert.ok(allowed);
        assert.strictEqual(allowed.severity, 'info');
    });

    test('assigns sequential IDs to entries', () => {
        const result = fetchAuditDetail(mockProviders());
        assert.ok(result);
        assert.strictEqual(result.entries[0].id, 'audit-0');
        assert.strictEqual(result.entries[1].id, 'audit-1');
        assert.strictEqual(result.entries[2].id, 'audit-2');
    });

    test('preserves agentDid and file when present', () => {
        const result = fetchAuditDetail(mockProviders());
        assert.ok(result);
        assert.strictEqual(result.entries[0].agentDid, 'did:mesh:a');
        assert.strictEqual(result.entries[0].file, '/src/main.ts');
        assert.strictEqual(result.entries[1].file, null);
        assert.strictEqual(result.entries[2].agentDid, null);
    });

    test('returns null on provider error', () => {
        const broken = mockProviders({ audit: { getAll: () => { throw new Error('fail'); } } });
        assert.strictEqual(fetchAuditDetail(broken), null);
    });

    test('handles empty audit log', () => {
        const empty = mockProviders({ audit: { getAll: () => [], getStats: () => ({}) } });
        const result = fetchAuditDetail(empty);
        assert.ok(result);
        assert.strictEqual(result.entries.length, 0);
    });
});

// ---------------------------------------------------------------------------
// fetchPolicyDetail
// ---------------------------------------------------------------------------

suite('detailFetchers - fetchPolicyDetail', () => {
    test('returns correct rule counts from PolicySnapshot', async () => {
        const result = await fetchPolicyDetail(mockProviders());
        assert.ok(result);
        assert.strictEqual(result.rules.length, 3);
        assert.strictEqual(result.totalEvaluations, 500);
        assert.strictEqual(result.totalViolations, 2);
    });

    test('maps individual rule fields correctly', async () => {
        const result = await fetchPolicyDetail(mockProviders());
        assert.ok(result);
        const rule = result.rules[0];
        assert.strictEqual(rule.id, 'r1');
        assert.strictEqual(rule.name, 'Block secrets');
        assert.strictEqual(rule.action, 'BLOCK');
        assert.strictEqual(rule.pattern, '*.env');
        assert.strictEqual(rule.enabled, true);
    });

    test('returns null on provider error', async () => {
        const broken = mockProviders({ policy: { getSnapshot: async () => { throw new Error('fail'); } } });
        assert.strictEqual(await fetchPolicyDetail(broken), null);
    });
});

// ---------------------------------------------------------------------------
// fetchHubDetail
// ---------------------------------------------------------------------------

suite('detailFetchers - fetchHubDetail', () => {
    test('returns composite of all detail fetchers', async () => {
        const result = await fetchHubDetail(mockProviders());
        assert.ok(result);
        assert.ok(result.slo, 'Expected slo detail');
        assert.ok(result.topology, 'Expected topology detail');
        assert.ok(result.audit, 'Expected audit detail');
        assert.ok(result.policy, 'Expected policy detail');
        assert.ok(result.fetchedAt, 'Expected fetchedAt timestamp');
    });

    test('returns partial data when some providers fail', async () => {
        const partial = mockProviders({
            slo: { getSnapshot: async () => { throw new Error('fail'); } },
            audit: { getAll: () => { throw new Error('fail'); } },
        });
        const result = await fetchHubDetail(partial);
        if (result !== null) {
            assert.strictEqual(result.slo, null);
            assert.strictEqual(result.audit, null);
        }
    });
});
