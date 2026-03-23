// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/** SLO Dashboard — Pure health assessment functions and category builders. */

import {
    SLOHealth, AvailabilitySLOData, LatencySLOData,
    PolicyComplianceSLOData, TrustScoreSLOData, SLOItem,
} from './sloTypes';

// -- Health assessment helpers ----------------------------------------------

/** Assess health by comparing a percentage value against a target. */
export function percentHealth(current: number, target: number): SLOHealth {
    if (current >= target) {
        return 'healthy';
    }
    if (current >= target - (target * 0.005)) {
        return 'warning';
    }
    return 'breached';
}

/** Assess health by remaining error-budget percentage. */
export function budgetHealth(remainingPercent: number): SLOHealth {
    if (remainingPercent > 30) {
        return 'healthy';
    }
    if (remainingPercent > 10) {
        return 'warning';
    }
    return 'breached';
}

/** Assess health by burn-rate multiplier. */
export function burnRateHealth(rate: number): SLOHealth {
    if (rate <= 1.0) {
        return 'healthy';
    }
    if (rate <= 2.0) {
        return 'warning';
    }
    return 'breached';
}

/** Assess health by comparing a latency value against a target. */
export function latencyHealth(valueMs: number, targetMs: number): SLOHealth {
    if (valueMs <= targetMs * 0.75) {
        return 'healthy';
    }
    if (valueMs <= targetMs) {
        return 'warning';
    }
    return 'breached';
}

/** Assess health of a trust score (0-1000 scale). */
export function trustScoreHealth(score: number): SLOHealth {
    if (score >= 700) {
        return 'healthy';
    }
    if (score >= 500) {
        return 'warning';
    }
    return 'breached';
}

/** Return a Unicode arrow character representing a trend direction. */
export function trendArrow(trend: 'up' | 'down' | 'stable'): string {
    switch (trend) {
        case 'up': return '\u2191';
        case 'down': return '\u2193';
        case 'stable': return '\u2192';
    }
}

/** Assess health by violation count (0 = healthy, 1-5 = warning, 6+ = breached). */
export function violationCountHealth(count: number): SLOHealth {
    if (count === 0) { return 'healthy'; }
    return count <= 5 ? 'warning' : 'breached';
}

/** Assess health by count of agents below threshold (0 = healthy, 1-2 = warning, 3+ = breached). */
export function thresholdCountHealth(count: number): SLOHealth {
    if (count === 0) { return 'healthy'; }
    return count <= 2 ? 'warning' : 'breached';
}

// -- Category builders ------------------------------------------------------

/** Build the Availability SLO category tree item. */
export function buildAvailability(data: AvailabilitySLOData): SLOItem {
    const health = percentHealth(data.currentPercent, data.targetPercent);
    const desc = `${data.currentPercent.toFixed(1)}% / ${data.targetPercent.toFixed(1)}% target`;
    const burnTip = data.burnRate <= 1.0
        ? 'budget is being consumed at or below the expected rate'
        : `budget is being consumed ${data.burnRate.toFixed(1)}x faster than sustainable`;
    return SLOItem.category(
        'Availability SLO', desc, health, 'pulse',
        `**Availability SLO**\n\nCurrent: ${data.currentPercent.toFixed(2)}%\nTarget: ${data.targetPercent.toFixed(2)}%\nStatus: ${health}`,
        [
            SLOItem.detail(
                'Current Value',
                `${data.currentPercent.toFixed(2)}%`,
                health,
                `Current availability: ${data.currentPercent.toFixed(2)}%`
            ),
            SLOItem.detail(
                'Target',
                `${data.targetPercent.toFixed(2)}%`,
                'healthy',
                `Target availability: ${data.targetPercent.toFixed(2)}%`
            ),
            SLOItem.detail(
                'Error Budget Remaining',
                `${data.errorBudgetRemainingPercent.toFixed(1)}%`,
                budgetHealth(data.errorBudgetRemainingPercent),
                `Error budget remaining: ${data.errorBudgetRemainingPercent.toFixed(1)}% of the 30-day window`
            ),
            SLOItem.detail(
                'Burn Rate',
                `${data.burnRate.toFixed(1)}x`,
                burnRateHealth(data.burnRate),
                `Burn rate: ${data.burnRate.toFixed(2)}x \u2014 ${burnTip}`
            ),
        ]
    );
}

/** Build the Latency SLO category tree item. */
export function buildLatency(data: LatencySLOData): SLOItem {
    const p99Health = latencyHealth(data.p99Ms, data.targetMs);
    const desc = `P99 ${data.p99Ms.toFixed(0)}ms / ${data.targetMs}ms target`;

    return SLOItem.category(
        'Latency SLO',
        desc,
        p99Health,
        'clock',
        `**Latency SLO**\n\nP99: ${data.p99Ms.toFixed(0)}ms\nTarget: ${data.targetMs}ms\nStatus: ${p99Health}`,
        [
            SLOItem.detail(
                'P50',
                `${data.p50Ms.toFixed(0)}ms`,
                latencyHealth(data.p50Ms, data.targetMs),
                `Median latency (P50): ${data.p50Ms.toFixed(1)}ms`
            ),
            SLOItem.detail(
                'P95',
                `${data.p95Ms.toFixed(0)}ms`,
                latencyHealth(data.p95Ms, data.targetMs),
                `95th percentile latency: ${data.p95Ms.toFixed(1)}ms`
            ),
            SLOItem.detail(
                'P99',
                `${data.p99Ms.toFixed(0)}ms`,
                p99Health,
                `99th percentile latency: ${data.p99Ms.toFixed(1)}ms`
            ),
            SLOItem.detail(
                'Budget Status',
                `${data.errorBudgetRemainingPercent.toFixed(1)}% remaining`,
                budgetHealth(data.errorBudgetRemainingPercent),
                `Latency error budget remaining: ${data.errorBudgetRemainingPercent.toFixed(1)}%`
            ),
        ]
    );
}

/** Build the Policy Compliance SLO category tree item. */
export function buildPolicyCompliance(data: PolicyComplianceSLOData): SLOItem {
    const health = percentHealth(data.compliancePercent, 99.0);
    const arrow = trendArrow(data.trend);
    const desc = `${data.compliancePercent.toFixed(1)}% pass rate ${arrow}`;
    const vHealth = violationCountHealth(data.violationsToday);
    return SLOItem.category(
        'Policy Compliance SLO', desc, health, 'shield',
        `**Policy Compliance SLO**\n\nCompliance: ${data.compliancePercent.toFixed(2)}%\nViolations today: ${data.violationsToday}\nTrend: ${data.trend} ${arrow}`,
        [
            SLOItem.detail(
                'Total Evaluations',
                data.totalEvaluations.toLocaleString(),
                'healthy',
                `Total policy evaluations in current window: ${data.totalEvaluations.toLocaleString()}`
            ),
            SLOItem.detail(
                'Violations Today',
                data.violationsToday.toString(),
                vHealth,
                `Policy violations recorded today: ${data.violationsToday}`
            ),
            SLOItem.detail(
                'Compliance Rate',
                `${data.compliancePercent.toFixed(2)}%`,
                health,
                `Current policy compliance rate: ${data.compliancePercent.toFixed(2)}%`
            ),
            SLOItem.detail(
                'Trend',
                `${arrow} ${data.trend}`,
                data.trend === 'down' ? 'warning' : 'healthy',
                `Compliance trend compared to previous window: ${data.trend}`
            ),
        ]
    );
}

/** Build the Trust Score SLO category tree item. */
export function buildTrustScore(data: TrustScoreSLOData): SLOItem {
    const health = trustScoreHealth(data.meanScore);
    const desc = `Mean ${data.meanScore} / 1000`;
    const bHealth = thresholdCountHealth(data.agentsBelowThreshold);
    return SLOItem.category(
        'Trust Score SLO', desc, health, 'verified',
        `**Trust Score SLO**\n\nMean: ${data.meanScore}\nMin: ${data.minScore}\nAgents below threshold: ${data.agentsBelowThreshold}`,
        [
            SLOItem.detail(
                'Mean Score',
                `${data.meanScore} / 1000`,
                health,
                `Mean trust score across all registered agents: ${data.meanScore}`
            ),
            SLOItem.detail(
                'Min Score',
                `${data.minScore} / 1000`,
                trustScoreHealth(data.minScore),
                `Lowest observed trust score: ${data.minScore}`
            ),
            SLOItem.detail(
                'Agents Below Threshold',
                data.agentsBelowThreshold.toString(),
                bHealth,
                `Agents scoring below the minimum acceptable trust threshold: ${data.agentsBelowThreshold}`
            ),
            SLOItem.detail(
                'Trust Distribution',
                `[${data.distribution.join(', ')}]`,
                'healthy',
                `Distribution (0-250 | 251-500 | 501-750 | 751-1000):\n${data.distribution[0]} | ${data.distribution[1]} | ${data.distribution[2]} | ${data.distribution[3]}`
            ),
        ]
    );
}
