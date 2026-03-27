// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import * as assert from 'assert';
import { GovernanceStore } from '../../webviews/sidebar/GovernanceStore';
import { GovernanceEventBus } from '../../webviews/sidebar/governanceEventBus';
import type { GovernanceEvent, SidebarState, SlotConfig } from '../../webviews/sidebar/types';

/** Minimal mock Memento for workspace state. */
function createMockMemento(): { get: <T>(key: string) => T | undefined; update: (key: string, value: unknown) => Thenable<void>; keys: () => readonly string[] } {
    const store = new Map<string, unknown>();
    return {
        get<T>(key: string): T | undefined { return store.get(key) as T | undefined; },
        update(key: string, value: unknown): Thenable<void> { store.set(key, value); return Promise.resolve(); },
        keys(): readonly string[] { return [...store.keys()]; },
    };
}

/** Providers that return fixed data. */
function createMockProviders(overrides?: Partial<Record<string, unknown>>) {
    return {
        slo: {
            getSnapshot: async () => ({
                availability: { currentPercent: 99.9, targetPercent: 99.5 },
                latency: { p99Ms: 120, targetMs: 200 },
                policyCompliance: { compliancePercent: 98, violationsToday: 0 },
                trustScore: { meanScore: 750, agentsBelowThreshold: 0 },
            }),
        },
        topology: {
            getAgents: () => [{ trustScore: 800 }],
            getBridges: () => [{ connected: true }],
            getDelegations: () => [],
        },
        audit: {
            getAll: () => [],
            getStats: () => ({ blockedToday: 0, blockedThisWeek: 0, warningsToday: 0, cmvkReviewsToday: 0, totalLogs: 0 }),
        },
        policy: {
            getSnapshot: async () => ({
                rules: [{ enabled: true, action: 'ALLOW' }],
                totalEvaluationsToday: 10,
                totalViolationsToday: 0,
            }),
        },
        kernel: {
            getKernelSummary: () => ({ activeAgents: 1, policyViolations: 0, totalCheckpoints: 5, uptime: 3600 }),
        },
        memory: {
            getVfsSummary: () => ({ directoryCount: 2, fileCount: 10, rootPaths: ['/a'] }),
        },
    } as any;
}

suite('GovernanceStore', () => {
    let bus: GovernanceEventBus;
    let store: GovernanceStore;

    setup(() => {
        bus = new GovernanceEventBus();
    });

    teardown(() => {
        store?.dispose();
        bus?.dispose();
    });

    test('initial state has empty stalePanels', () => {
        store = new GovernanceStore(createMockProviders(), bus, createMockMemento() as any, 60000);
        const state = store.getState();
        assert.deepStrictEqual(state.stalePanels, []);
        assert.strictEqual(state.slo, null);
    });

    test('refreshNow triggers fetch and emits stateChanged when visible', async () => {
        store = new GovernanceStore(createMockProviders(), bus, createMockMemento() as any, 60000);
        store.setVisible(true);

        const events: GovernanceEvent[] = [];
        bus.subscribe((e) => events.push(e));

        store.refreshNow();
        // Allow async fetches to complete
        await new Promise(r => setTimeout(r, 50));

        const stateEvents = events.filter(e => e.type === 'stateChanged');
        assert.ok(stateEvents.length >= 1, 'Should have emitted at least one stateChanged');
    });

    test('duplicate state does not emit stateChanged', async () => {
        store = new GovernanceStore(createMockProviders(), bus, createMockMemento() as any, 60000);
        store.setVisible(true);

        store.refreshNow();
        await new Promise(r => setTimeout(r, 50));

        const events: GovernanceEvent[] = [];
        bus.subscribe((e) => events.push(e));

        // Second refresh with same data
        store.refreshNow();
        await new Promise(r => setTimeout(r, 50));

        const stateEvents = events.filter(e => e.type === 'stateChanged');
        assert.strictEqual(stateEvents.length, 0, 'Should not re-emit for identical state');
    });

    test('setSlots persists and emits slotConfigChanged', async () => {
        const memento = createMockMemento();
        store = new GovernanceStore(createMockProviders(), bus, memento as any, 60000);

        const events: GovernanceEvent[] = [];
        bus.subscribe((e) => events.push(e));

        const newSlots: SlotConfig = { slotA: 'governance-hub', slotB: 'slo-dashboard', slotC: 'audit-log' };
        store.setSlots(newSlots);

        const slotEvents = events.filter(e => e.type === 'slotConfigChanged');
        assert.strictEqual(slotEvents.length, 1);
        assert.strictEqual(memento.get('agentOS.slotConfig'), newSlots);
        assert.deepStrictEqual(store.getState().slots, newSlots);
    });

    test('setVisible(false) suppresses stateChanged events', async () => {
        store = new GovernanceStore(createMockProviders(), bus, createMockMemento() as any, 60000);
        store.setVisible(false);

        const events: GovernanceEvent[] = [];
        bus.subscribe((e) => events.push(e));

        store.refreshNow();
        await new Promise(r => setTimeout(r, 50));

        const stateEvents = events.filter(e => e.type === 'stateChanged');
        assert.strictEqual(stateEvents.length, 0, 'Should not emit stateChanged when hidden');
    });

    test('setVisible(true) emits current state after hidden fetch', async () => {
        store = new GovernanceStore(createMockProviders(), bus, createMockMemento() as any, 60000);

        // Fetch while hidden — state changes internally but no event emitted
        store.refreshNow();
        await new Promise(r => setTimeout(r, 50));

        // Now become visible — the changed state should be emitted
        const events: GovernanceEvent[] = [];
        bus.subscribe((e) => events.push(e));

        // Reset lastJson so emitIfChanged detects the diff on visibility flip
        // The store internally updated state but suppressed the event.
        // On setVisible(true), it calls emitIfChanged which compares to lastJson.
        // Since lastJson was never set (event was suppressed), the state IS different.
        store.setVisible(true);

        // emitIfChanged fires synchronously in setVisible
        const stateEvents = events.filter(e => e.type === 'stateChanged');
        assert.ok(stateEvents.length >= 1, 'Should emit stateChanged when becoming visible with pending state');
    });

    test('dispose clears interval', () => {
        store = new GovernanceStore(createMockProviders(), bus, createMockMemento() as any, 60000);
        // Should not throw
        store.dispose();
        store.dispose(); // double dispose safe
    });

    test('subscribe filters to stateChanged only', async () => {
        store = new GovernanceStore(createMockProviders(), bus, createMockMemento() as any, 60000);
        store.setVisible(true);

        const states: SidebarState[] = [];
        store.subscribe((s) => states.push(s));

        // Emit a non-stateChanged event
        bus.publish({ type: 'refreshRequested' });
        assert.strictEqual(states.length, 0, 'Should not forward non-stateChanged events');

        store.refreshNow();
        await new Promise(r => setTimeout(r, 50));
        assert.ok(states.length >= 1, 'Should forward stateChanged events');
    });

    test('setAttentionMode manual restores userSlots', () => {
        store = new GovernanceStore(createMockProviders(), bus, createMockMemento() as any, 60000);
        const originalSlots = store.getState().userSlots;
        // Simulate priority changing slots
        store.setVisible(true);
        store.setAttentionMode('manual');
        assert.deepStrictEqual(store.getState().slots, originalSlots);
        assert.strictEqual(store.getState().attentionMode, 'manual');
    });

    test('setAttentionMode auto captures current slots as userSlots', () => {
        const memento = createMockMemento();
        store = new GovernanceStore(createMockProviders(), bus, memento as any, 60000);
        const newSlots = { slotA: 'governance-hub' as const, slotB: 'audit-log' as const, slotC: 'safety-stats' as const };
        store.setSlots(newSlots);
        store.setAttentionMode('auto');
        assert.deepStrictEqual(store.getState().userSlots, newSlots);
    });

    test('setAttentionMode persists to workspace state', () => {
        const memento = createMockMemento();
        store = new GovernanceStore(createMockProviders(), bus, memento as any, 60000);
        store.setAttentionMode('manual');
        assert.strictEqual(memento.get('agentOS.attentionMode'), 'manual');
    });

    test('setSlots also updates userSlots', () => {
        store = new GovernanceStore(createMockProviders(), bus, createMockMemento() as any, 60000);
        const newSlots = { slotA: 'governance-hub' as const, slotB: 'slo-dashboard' as const, slotC: 'audit-log' as const };
        store.setSlots(newSlots);
        assert.deepStrictEqual(store.getState().userSlots, newSlots);
    });

    test('priority reorder does not persist to workspace state', async () => {
        const memento = createMockMemento();
        store = new GovernanceStore(createMockProviders(), bus, memento as any, 60000);
        store.setVisible(true);
        store.refreshNow();
        await new Promise(r => setTimeout(r, 50));
        // Priority may reorder slots, but workspace state should still have original
        const persisted = memento.get<any>('agentOS.slotConfig');
        // If persisted is undefined, that's fine — priority doesn't write it
        // If it exists, it should be the default (set only by setSlots)
        if (persisted) {
            assert.deepStrictEqual(persisted, store.getState().userSlots);
        }
    });
});
