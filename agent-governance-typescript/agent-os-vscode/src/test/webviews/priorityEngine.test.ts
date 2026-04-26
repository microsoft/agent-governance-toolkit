// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import * as assert from 'assert';
import { extractPanelHealth, rankPanelsByUrgency } from '../../webviews/sidebar/priorityEngine';
import type { SidebarState, SlotConfig } from '../../webviews/sidebar/types';
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

suite('extractPanelHealth', () => {
    test('null data returns unknown', () => {
        assert.strictEqual(extractPanelHealth('slo-dashboard', makeState()), 'unknown');
    });

    test('SLO critical when availability < target', () => {
        const state = makeState({
            slo: { availability: 98, availabilityTarget: 99.5, latencyP99: 100, latencyTarget: 200, compliancePercent: 95, violationsToday: 0, trustMean: 800, agentsBelowThreshold: 0 },
        });
        assert.strictEqual(extractPanelHealth('slo-dashboard', state), 'critical');
    });

    test('SLO warning when compliancePercent < 95', () => {
        const state = makeState({
            slo: { availability: 99.9, availabilityTarget: 99.5, latencyP99: 100, latencyTarget: 200, compliancePercent: 93, violationsToday: 0, trustMean: 800, agentsBelowThreshold: 0 },
        });
        assert.strictEqual(extractPanelHealth('slo-dashboard', state), 'warning');
    });

    test('SLO healthy when all metrics good', () => {
        const state = makeState({
            slo: { availability: 99.9, availabilityTarget: 99.5, latencyP99: 100, latencyTarget: 200, compliancePercent: 98, violationsToday: 0, trustMean: 800, agentsBelowThreshold: 0 },
        });
        assert.strictEqual(extractPanelHealth('slo-dashboard', state), 'healthy');
    });

    test('audit warning when violationsToday > 0', () => {
        const state = makeState({
            audit: { totalToday: 10, violationsToday: 2, lastEventTime: null, lastEventAction: null },
        });
        assert.strictEqual(extractPanelHealth('audit-log', state), 'warning');
    });

    test('audit critical when violationsToday > 10', () => {
        const state = makeState({
            audit: { totalToday: 20, violationsToday: 12, lastEventTime: null, lastEventAction: null },
        });
        assert.strictEqual(extractPanelHealth('audit-log', state), 'critical');
    });

    test('topology critical when meanTrust < 400', () => {
        const state = makeState({
            topology: { agentCount: 3, bridgeCount: 1, meanTrust: 350, delegationCount: 0 },
        });
        assert.strictEqual(extractPanelHealth('agent-topology', state), 'critical');
    });

    test('governance-hub maps overallHealth directly', () => {
        const state = makeState({
            hub: { overallHealth: 'critical', activeAlerts: 5, policyCompliance: 80, agentCount: 3 },
        });
        assert.strictEqual(extractPanelHealth('governance-hub', state), 'critical');
    });

    test('memory-browser always healthy when data present', () => {
        const state = makeState({
            memory: { directoryCount: 2, fileCount: 10, rootPaths: ['/a'] },
        });
        assert.strictEqual(extractPanelHealth('memory-browser', state), 'healthy');
    });
});

suite('rankPanelsByUrgency', () => {
    test('critical panel ranks above warning above healthy', () => {
        const state = makeState({
            slo: { availability: 98, availabilityTarget: 99.5, latencyP99: 100, latencyTarget: 200, compliancePercent: 85, violationsToday: 0, trustMean: 800, agentsBelowThreshold: 0 },
            audit: { totalToday: 5, violationsToday: 2, lastEventTime: null, lastEventAction: null },
            topology: { agentCount: 3, bridgeCount: 1, meanTrust: 800, delegationCount: 0 },
        });
        const result = rankPanelsByUrgency(state, DEFAULT_SLOTS);
        assert.strictEqual(result.slotA, 'slo-dashboard'); // critical
        assert.strictEqual(result.slotB, 'audit-log'); // warning
    });

    test('all-healthy preserves user config order', () => {
        const state = makeState({
            slo: { availability: 99.9, availabilityTarget: 99.5, latencyP99: 100, latencyTarget: 200, compliancePercent: 99, violationsToday: 0, trustMean: 800, agentsBelowThreshold: 0 },
            audit: { totalToday: 5, violationsToday: 0, lastEventTime: null, lastEventAction: null },
            topology: { agentCount: 3, bridgeCount: 1, meanTrust: 800, delegationCount: 0 },
            policy: { totalRules: 5, enabledRules: 5, denyRules: 0, blockRules: 0, evaluationsToday: 10, violationsToday: 0 },
            stats: { blockedToday: 0, blockedThisWeek: 0, warningsToday: 0, cmvkReviews: 0, totalLogs: 100 },
            kernel: { activeAgents: 2, policyViolations: 0, totalCheckpoints: 5, uptimeSeconds: 3600 },
            memory: { directoryCount: 2, fileCount: 10, rootPaths: ['/a'] },
            hub: { overallHealth: 'healthy', activeAlerts: 0, policyCompliance: 99, agentCount: 3 },
        });
        const userSlots: SlotConfig = { slotA: 'audit-log', slotB: 'slo-dashboard', slotC: 'agent-topology' };
        const result = rankPanelsByUrgency(state, userSlots);
        // User config panels should come first among equals
        assert.strictEqual(result.slotA, 'audit-log');
        assert.strictEqual(result.slotB, 'slo-dashboard');
        assert.strictEqual(result.slotC, 'agent-topology');
    });

    test('no duplicate panels in result', () => {
        const state = makeState();
        const result = rankPanelsByUrgency(state, DEFAULT_SLOTS);
        const ids = [result.slotA, result.slotB, result.slotC];
        assert.strictEqual(new Set(ids).size, 3);
    });

    test('null data panels rank as unknown (lowest)', () => {
        const state = makeState({
            audit: { totalToday: 5, violationsToday: 2, lastEventTime: null, lastEventAction: null },
        });
        const result = rankPanelsByUrgency(state, DEFAULT_SLOTS);
        // audit-log is warning, everything else is unknown — audit should be first
        assert.strictEqual(result.slotA, 'audit-log');
    });
});
