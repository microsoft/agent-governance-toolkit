// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Sidebar SLO Formatter
 *
 * Returns a JavaScript string containing compact SLO formatting
 * functions for injection into the sidebar hub webview.
 */

/** Returns JS source for compact SLO card builders and composer. */
export function sidebarSLOFormatterScript(): string {
    return `
    /** Build compact availability metric row. */
    function buildCompactAvailability(availability) {
        var pct = typeof availability.current === 'number'
            ? (availability.current * 100).toFixed(2) + '%' : '--';
        var status = getHealthStatus(availability.current, availability.target);
        return '<div class="metric-compact">' +
            '<span class="label">Availability</span>' +
            '<span class="value ' + status + '">' + pct + '</span></div>';
    }

    /** Build compact latency metric row. */
    function buildCompactLatency(latency) {
        var val = typeof latency.p99 === 'number' ? latency.p99.toFixed(0) + 'ms' : '--';
        var status = latency.p99 <= (latency.target || 500) ? 'healthy' : 'warning';
        return '<div class="metric-compact">' +
            '<span class="label">Latency (P99)</span>' +
            '<span class="value ' + status + '">' + val + '</span></div>';
    }

    /** Build compact trust score section with progress bar. */
    function buildCompactTrust(trustScore) {
        var val = typeof trustScore.current === 'number' ? trustScore.current : '--';
        var max = trustScore.max || 1000;
        var pct = typeof trustScore.current === 'number'
            ? ((trustScore.current / max) * 100).toFixed(0) : 0;
        var status = trustScore.current >= 800 ? 'healthy'
            : trustScore.current >= 500 ? 'warning' : 'critical';
        return '<div class="section-header">Trust Score</div>' +
            '<div class="metric-compact">' +
                '<span class="label">Current</span>' +
                '<span class="value ' + status + '">' + val + ' / ' + max + '</span>' +
            '</div>' +
            '<div class="progress-bar">' +
                '<div class="fill ' + status + '" style="width: ' + pct + '%"></div>' +
            '</div>';
    }

    /** Build compact error budget section with progress bar. */
    function buildCompactErrorBudget(errorBudget) {
        var pct = typeof errorBudget.remaining === 'number'
            ? (errorBudget.remaining * 100).toFixed(1) + '%' : '--';
        var status = errorBudget.remaining >= 0.5 ? 'healthy'
            : errorBudget.remaining >= 0.2 ? 'warning' : 'critical';
        var barWidth = typeof errorBudget.remaining === 'number'
            ? errorBudget.remaining * 100 : 0;
        return '<div class="section-header">Error Budget</div>' +
            '<div class="metric-compact">' +
                '<span class="label">Remaining</span>' +
                '<span class="value ' + status + '">' + pct + '</span>' +
            '</div>' +
            '<div class="progress-bar">' +
                '<div class="fill ' + status + '" style="width: ' + barWidth + '%"></div>' +
            '</div>';
    }

    /** Compose compact SLO view from sub-builders. */
    function formatCompactSLO(data) {
        if (!data) {
            return '<div class="empty-state">Loading SLO data...</div>';
        }
        var availability = data.availability || {};
        var latency = data.latency || {};
        var trustScore = data.trustScore || {};
        var errorBudget = data.errorBudget || {};

        return '<div class="section-header">Service Health</div>' +
            buildCompactAvailability(availability) +
            buildCompactLatency(latency) +
            buildCompactTrust(trustScore) +
            buildCompactErrorBudget(errorBudget);
    }
    `;
}
