// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Hub SLO Formatter
 *
 * Returns a JavaScript string containing SLO formatting functions
 * for injection into the Governance Hub webview.
 */

/** Returns JS source for SLO metric card builders and composer. */
export function hubSLOFormatterScript(): string {
    return `
    /** Get health class based on threshold comparison. */
    function getHealthClass(current, target, isLatency) {
        if (isLatency) {
            if (current <= target * 0.8) return 'health-ok';
            if (current <= target) return 'health-warn';
            return 'health-critical';
        }
        if (current >= target) return 'health-ok';
        if (current >= target * 0.98) return 'health-warn';
        return 'health-critical';
    }

    /** Render a single metric card. */
    function renderMetricCard(label, value, unit, healthClass) {
        return '<div class="metric-card">' +
            '<div class="label">' + label + '</div>' +
            '<div class="value ' + healthClass + '">' + value + unit + '</div>' +
        '</div>';
    }

    /** Render trust distribution as horizontal stacked bar. */
    function renderTrustDistribution(dist) {
        if (!dist || dist.length < 4) {
            dist = [0, 0, 0, 100];
        }
        var labels = ['low', 'medium', 'high', 'top'];
        var total = dist.reduce(function(a, b) { return a + b; }, 0) || 1;

        return '<div class="trust-distribution">' +
            dist.map(function(val, i) {
                var pct = (val / total) * 100;
                if (pct < 1) return '';
                return '<div class="segment ' + labels[i] + '" style="width:' + pct + '%">' +
                    (pct >= 10 ? Math.round(pct) + '%' : '') +
                '</div>';
            }).join('') +
        '</div>';
    }

    /** Build availability error budget bar. */
    function buildAvailabilityBudgetBar(d) {
        var budget = d.availability.errorBudgetRemainingPercent || 0;
        var cls = budget >= 50 ? 'healthy' : budget >= 20 ? 'warning' : 'critical';
        return '<div class="budget-bar">' +
            '<div class="label">' +
                '<span class="name">Availability Budget</span>' +
                '<span class="value">' + budget.toFixed(1) + '%</span>' +
            '</div>' +
            '<div class="track"><div class="fill ' + cls + '" style="width:' + Math.min(budget, 100) + '%"></div></div>' +
        '</div>';
    }

    /** Build latency error budget bar. */
    function buildLatencyBudgetBar(d) {
        var budget = d.latency.budgetRemainingPercent !== undefined
            ? d.latency.budgetRemainingPercent : 100;
        var cls = budget >= 50 ? 'healthy' : budget >= 20 ? 'warning' : 'critical';
        return '<div class="budget-bar">' +
            '<div class="label">' +
                '<span class="name">Latency Budget</span>' +
                '<span class="value">' + budget.toFixed(1) + '%</span>' +
            '</div>' +
            '<div class="track"><div class="fill ' + cls + '" style="width:' + Math.min(budget, 100) + '%"></div></div>' +
        '</div>';
    }

    /** Render error budget progress bars. */
    function renderErrorBudgetBars(d) {
        return buildAvailabilityBudgetBar(d) + buildLatencyBudgetBar(d);
    }

    /** Build the SLO detail rows section. */
    function buildSLODetailRows(d) {
        return '<div class="slo-details">' +
            buildDetailRow('Error Budget Remaining',
                d.availability.errorBudgetRemainingPercent + '%',
                d.availability.errorBudgetRemainingPercent > 50) +
            buildDetailRow('Burn Rate',
                d.availability.burnRate + 'x',
                d.availability.burnRate <= 1) +
            buildDetailRow('Violations Today',
                '' + d.policyCompliance.violationsToday,
                d.policyCompliance.violationsToday === 0) +
            buildDetailRow('Agents Below Threshold',
                '' + d.trustScore.agentsBelowThreshold,
                d.trustScore.agentsBelowThreshold === 0) +
        '</div>';
    }

    /** Render a single detail row with health coloring. */
    function buildDetailRow(label, value, isOk) {
        var cls = isOk ? 'health-ok' : 'health-warn';
        return '<div class="detail-row">' +
            '<span>' + label + '</span>' +
            '<span class="' + cls + '">' + value + '</span>' +
        '</div>';
    }

    /** Build the SLO metric cards row. */
    function buildSLOMetricCards(d) {
        var availHealth = getHealthClass(d.availability.currentPercent, d.availability.targetPercent, false);
        var latencyHealth = getHealthClass(d.latency.p99Ms, d.latency.targetMs, true);
        var complianceHealth = getHealthClass(d.policyCompliance.compliancePercent, 99.5, false);
        var trustHealth = d.trustScore.meanScore >= 700 ? 'health-ok'
            : d.trustScore.meanScore >= 400 ? 'health-warn' : 'health-critical';

        return '<div class="metric-row">' +
            renderMetricCard('Availability', d.availability.currentPercent, '%', availHealth) +
            renderMetricCard('P99 Latency', d.latency.p99Ms, 'ms', latencyHealth) +
            renderMetricCard('Compliance', d.policyCompliance.compliancePercent, '%', complianceHealth) +
            renderMetricCard('Mean Trust', d.trustScore.meanScore, '', trustHealth) +
        '</div>';
    }

    /** Format SLO dashboard with live metrics. */
    function formatSLOContent(d) {
        if (!d || !d.availability) {
            return '<div class="empty-state">No SLO data available</div>';
        }
        var trustDist = d.trustScore.distribution || [5, 15, 30, 50];
        return '<div class="slo-panel">' +
            buildSLOMetricCards(d) +
            buildSLODetailRows(d) +
            '<div class="slo-secondary">' +
                '<h4>Trust Distribution</h4>' +
                renderTrustDistribution(trustDist) +
                '<h4>Error Budgets</h4>' +
                renderErrorBudgetBars(d) +
            '</div>' +
        '</div>';
    }
    `;
}
