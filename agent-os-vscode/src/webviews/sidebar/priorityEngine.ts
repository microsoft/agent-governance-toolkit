// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Priority Engine
 *
 * Pure functions that rank panels by health urgency.
 * No React, no vscode, no side effects.
 */

import type { PanelId, SidebarState, SlotConfig, UrgencyLevel } from './types';

const ALL_PANELS: PanelId[] = [
    'governance-hub', 'slo-dashboard', 'audit-log', 'agent-topology',
    'active-policies', 'safety-stats', 'kernel-debugger', 'memory-browser',
];

const URGENCY_RANK: Record<UrgencyLevel, number> = {
    critical: 0, warning: 1, healthy: 2, unknown: 3,
};

/** Threshold-based health check: returns urgency from data or 'unknown' if null. */
function thresholdHealth(
    data: unknown, criticalIf: (d: any) => boolean, warningIf: (d: any) => boolean,
): UrgencyLevel {
    if (!data) { return 'unknown'; }
    if (criticalIf(data)) { return 'critical'; }
    if (warningIf(data)) { return 'warning'; }
    return 'healthy';
}

/** Per-panel health extractors. Each returns an UrgencyLevel from SidebarState. */
const HEALTH_EXTRACTORS: Record<PanelId, (s: SidebarState) => UrgencyLevel> = {
    'slo-dashboard': (s) => thresholdHealth(s.slo,
        d => d.availability < d.availabilityTarget || d.compliancePercent < 90,
        d => d.compliancePercent < 95 || d.violationsToday > 0),
    'audit-log': (s) => thresholdHealth(s.audit,
        d => d.violationsToday > 10, d => d.violationsToday > 0),
    'agent-topology': (s) => thresholdHealth(s.topology,
        d => d.meanTrust < 400, d => d.meanTrust < 600),
    'governance-hub': (s) => s.hub ? s.hub.overallHealth : 'unknown',
    'active-policies': (s) => thresholdHealth(s.policy,
        d => d.violationsToday > 5, d => d.violationsToday > 0),
    'safety-stats': (s) => thresholdHealth(s.stats,
        d => d.blockedToday > 10, d => d.blockedToday > 0),
    'kernel-debugger': (s) => thresholdHealth(s.kernel,
        d => d.policyViolations > 5, d => d.policyViolations > 0),
    'memory-browser': (s) => s.memory ? 'healthy' : 'unknown',
};

/** Extract the health urgency of a single panel from sidebar state. */
export function extractPanelHealth(panelId: PanelId, state: SidebarState): UrgencyLevel {
    return HEALTH_EXTRACTORS[panelId](state);
}

/** Rank all panels by urgency, return top 3 as SlotConfig. Tiebreaker: user config order. */
export function rankPanelsByUrgency(state: SidebarState, userSlots: SlotConfig): SlotConfig {
    const userOrder = [userSlots.slotA, userSlots.slotB, userSlots.slotC];

    const ranked = ALL_PANELS
        .map(id => ({ id, urgency: extractPanelHealth(id, state) }))
        .sort((a, b) => {
            const diff = URGENCY_RANK[a.urgency] - URGENCY_RANK[b.urgency];
            if (diff !== 0) { return diff; }
            const aIdx = userOrder.indexOf(a.id);
            const bIdx = userOrder.indexOf(b.id);
            return (aIdx >= 0 ? aIdx : ALL_PANELS.length) - (bIdx >= 0 ? bIdx : ALL_PANELS.length);
        });

    return { slotA: ranked[0].id, slotB: ranked[1].id, slotC: ranked[2].id };
}
