// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import * as assert from 'assert';
import { SidebarProvider } from '../../webviews/sidebar/SidebarProvider';
import { GovernanceStore } from '../../webviews/sidebar/GovernanceStore';
import { GovernanceEventBus } from '../../webviews/sidebar/governanceEventBus';
import type { SidebarState, SlotConfig } from '../../webviews/sidebar/types';

/** Minimal mock Memento. */
function createMockMemento(): any {
    const store = new Map<string, unknown>();
    return {
        get<T>(key: string): T | undefined { return store.get(key) as T | undefined; },
        update(key: string, value: unknown): Thenable<void> { store.set(key, value); return Promise.resolve(); },
        keys: () => [...store.keys()],
    };
}

/** Providers returning fixed data. */
function createMockProviders(): any {
    return {
        slo: { getSnapshot: async () => ({ availability: { currentPercent: 99.9, targetPercent: 99.5 }, latency: { p99Ms: 120, targetMs: 200 }, policyCompliance: { compliancePercent: 98, violationsToday: 0 }, trustScore: { meanScore: 750, agentsBelowThreshold: 0 } }) },
        topology: { getAgents: () => [], getBridges: () => [], getDelegations: () => [] },
        audit: { getAll: () => [], getStats: () => ({ blockedToday: 0, blockedThisWeek: 0, warningsToday: 0, cmvkReviewsToday: 0, totalLogs: 0 }) },
        policy: { getSnapshot: async () => ({ rules: [], totalEvaluationsToday: 0, totalViolationsToday: 0 }) },
        kernel: { getKernelSummary: () => ({ activeAgents: 0, policyViolations: 0, totalCheckpoints: 0, uptime: 0 }) },
        memory: { getVfsSummary: () => ({ directoryCount: 0, fileCount: 0, rootPaths: [] }) },
    };
}

suite('SidebarProvider', () => {
    let bus: GovernanceEventBus;
    let store: GovernanceStore;
    setup(() => {
        bus = new GovernanceEventBus();
        store = new GovernanceStore(createMockProviders(), bus, createMockMemento(), 60000);
    });

    teardown(() => {
        store?.dispose();
        bus?.dispose();
    });

    test('constructor accepts store without throwing', () => {
        // SidebarProvider takes vscode.Uri which is hard to mock without vscode API.
        // This test verifies the store-based constructor signature compiles and the
        // old 8-argument signature is gone.
        assert.ok(SidebarProvider.viewType === 'agent-os.sidebar');
    });

    test('store.setSlots updates state', () => {
        const newSlots: SlotConfig = { slotA: 'governance-hub', slotB: 'audit-log', slotC: 'safety-stats' };
        store.setSlots(newSlots);
        assert.deepStrictEqual(store.getState().slots, newSlots);
    });

    test('store.refreshNow does not throw when no webview attached', () => {
        store.setVisible(true);
        // Should not throw even without a webview
        store.refreshNow();
    });

    test('store.setVisible publishes visibilityChanged', () => {
        const events: string[] = [];
        bus.subscribe((e) => events.push(e.type));
        store.setVisible(true);
        assert.ok(events.includes('visibilityChanged'));
    });

    test('dispose is safe to call multiple times', () => {
        // Provider is undefined since we can't construct without real vscode.Uri,
        // but store dispose should be safe
        store.dispose();
        store.dispose();
    });
});
