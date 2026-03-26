// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * SLO Dashboard Template
 *
 * Produces the complete HTML document for the SLO Dashboard webview.
 * Composes styles from SLODashboardStyles and script from SLODashboardScript.
 */

import { sloStyles } from './SLODashboardStyles';
import { sloScript } from './SLODashboardScript';

/** SVG stroke width for gauge arcs. */
const STROKE_WIDTH = 8;

/** Gauge radius matching the script constants. */
const GAUGE_R = 48;

/** Circumference and 270-degree arc length. */
const CIRC = 2 * Math.PI * GAUGE_R;
const ARC_LEN = CIRC * (270 / 360);

/**
 * Build an inline SVG gauge with a background track and a value arc.
 * The value arc is identified by `${id}-arc` for script updates.
 */
function gaugeMarkup(id: string, label: string): string {
    const dashInit = `0 ${ARC_LEN}`;
    return `
        <div class="gauge-container">
            <svg width="120" height="120" viewBox="0 0 120 120">
                <circle class="gauge-track"
                    cx="60" cy="60" r="${GAUGE_R}"
                    stroke-width="${STROKE_WIDTH}"
                    stroke-dasharray="${ARC_LEN} ${CIRC - ARC_LEN}" />
                <circle class="gauge-arc stroke-ok"
                    id="${id}-arc"
                    cx="60" cy="60" r="${GAUGE_R}"
                    stroke-width="${STROKE_WIDTH}"
                    stroke-dasharray="${dashInit}" />
            </svg>
            <div class="gauge-label">
                <div class="gauge-value health-ok" id="${id}-value">--</div>
                <div class="gauge-unit">${label}</div>
            </div>
        </div>`;
}

/**
 * Build a metric card with label, value, and subtitle.
 */
function metricCard(
    id: string,
    label: string,
    defaultVal: string,
    subtitle: string
): string {
    return `
        <div class="metric-card">
            <div class="label">${label}</div>
            <div class="value health-ok" id="${id}">${defaultVal}</div>
            <div class="subtitle">${subtitle}</div>
        </div>`;
}

/**
 * Build a labeled budget bar with identified fill element.
 */
function budgetBarMarkup(id: string, label: string): string {
    return `
        <div class="budget-label">
            <span>${label}</span>
            <span id="${id}-pct">--</span>
        </div>
        <div class="budget-bar">
            <div class="fill fill-ok" id="${id}-fill" style="width: 0%"></div>
        </div>`;
}

/**
 * Build a single latency bar row.
 */
function latencyRow(label: string, id: string): string {
    return `
        <div class="latency-row">
            <span class="lat-label">${label}</span>
            <div class="latency-bar">
                <div class="fill fill-ok" id="${id}-fill" style="width: 0%"></div>
            </div>
            <span class="lat-value" id="${id}-val">--</span>
        </div>`;
}

/**
 * Returns the complete HTML document for the SLO Dashboard webview.
 *
 * @param nonce - Cryptographic nonce for CSP
 * @param cspSource - Webview CSP source string
 */
export function renderSLODashboard(nonce: string, cspSource: string): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src ${cspSource} 'nonce-${nonce}'; script-src 'nonce-${nonce}';">
    <title>SLO Dashboard</title>
    ${sloStyles(nonce)}
</head>
<body>

    <!-- Header -->
    <div class="dashboard-header">
        <h1>
            <span class="status-dot"></span>
            SLO Dashboard
        </h1>
        <span id="slo-staleness" style="font-size:11px;opacity:0.7"></span>
        <button class="refresh-btn" id="refresh-btn">Refresh</button>
    </div>

    <!-- Metric cards -->
    <div class="metric-grid">
        ${metricCard('card-avail', 'Availability', '--%', 'Current window')}
        ${metricCard('card-latency', 'Latency P99', '--ms', 'Policy check')}
        ${metricCard('card-compliance', 'Compliance', '--%', 'Policy adherence')}
        ${metricCard('card-trust', 'Trust Score', '--', 'Mean (0-1000)')}
    </div>

    <!-- Gauges and charts -->
    <div class="two-col">

        <!-- Left column: Gauges -->
        <div class="panel">
            <div class="section-title">Availability</div>
            ${gaugeMarkup('avail-gauge', 'Availability')}
            <div class="section-title" style="margin-top:16px">Compliance</div>
            ${gaugeMarkup('compliance-gauge', 'Compliance')}
        </div>

        <!-- Right column: Latency + Trust -->
        <div class="panel">
            <div class="section-title">Latency Breakdown</div>
            ${latencyRow('P50', 'lat-p50')}
            ${latencyRow('P95', 'lat-p95')}
            ${latencyRow('P99', 'lat-p99')}

            <div class="section-title" style="margin-top:16px">Trust Distribution</div>
            <div class="dist-bar" id="trust-dist">
                <div class="segment seg-critical" style="flex:1"></div>
                <div class="segment seg-low" style="flex:1"></div>
                <div class="segment seg-medium" style="flex:1"></div>
                <div class="segment seg-high" style="flex:1"></div>
            </div>
            <div class="dist-legend">
                <span><span class="swatch seg-critical"></span>0-250</span>
                <span><span class="swatch seg-low"></span>251-500</span>
                <span><span class="swatch seg-medium"></span>501-750</span>
                <span><span class="swatch seg-high"></span>751-1000</span>
            </div>
        </div>
    </div>

    <!-- Burn rate section -->
    <div class="section">
        <div class="panel">
            <div class="section-title">Burn Rate (24h Trend)</div>
            <div class="sparkline-container">
                <svg class="sparkline" id="burn-sparkline"
                    viewBox="0 0 200 40" preserveAspectRatio="none">
                    <polyline points="" />
                </svg>
            </div>
            <div class="burn-rate-value health-ok" id="burn-rate-val">--</div>
            <div class="budget-label">
                <span>Current burn rate multiplier</span>
                <span id="trend-indicator">--</span>
            </div>
        </div>
    </div>

    <!-- Error budget section -->
    <div class="section">
        <div class="panel">
            <div class="section-title">Error Budgets Remaining</div>
            ${budgetBarMarkup('budget-avail', 'Availability')}
            ${budgetBarMarkup('budget-latency', 'Latency')}
            ${budgetBarMarkup('budget-compliance', 'Compliance')}
        </div>
    </div>

    ${sloScript(nonce)}
</body>
</html>`;
}
