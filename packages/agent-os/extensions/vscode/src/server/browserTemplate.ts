// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Browser Dashboard Template
 *
 * Full HTML document for the browser-based governance dashboard.
 * Includes D3.js for topology graph, Chart.js for SLO sparklines,
 * and WebSocket client for real-time updates.
 */

import { buildBrowserStyles } from './browserStyles';
import { buildClientScript, buildTopologyScript } from './browserScripts';

/** Build the HTML structure for the dashboard body. */
function buildBodyContent(): string {
    return `
    <div class="container">
        <nav class="sidebar">
            <button class="toggle-btn" id="toggle-sidebar">&#9776;</button>
            <a class="nav-item" href="#slo" data-tab="slo">
                <span class="nav-icon">&#128200;</span>
                <span class="nav-label">SLO Dashboard</span>
            </a>
            <a class="nav-item" href="#topology" data-tab="topology">
                <span class="nav-icon">&#128301;</span>
                <span class="nav-label">Agent Topology</span>
            </a>
            <a class="nav-item" href="#audit" data-tab="audit">
                <span class="nav-icon">&#128221;</span>
                <span class="nav-label">Audit Log</span>
            </a>
        </nav>
        <main class="main">
            <div class="header">
                <h1>Agent OS Governance</h1>
                <div class="status-indicator">
                    <span class="status-dot disconnected" id="status-dot"></span>
                    <span>Live</span>
                </div>
            </div>
            ${buildSLOTab()}
            ${buildTopologyTab()}
            ${buildAuditTab()}
        </main>
    </div>`;
}

/** Build the SLO dashboard tab content. */
function buildSLOTab(): string {
    return `
    <div id="tab-slo" class="tab-content active">
        <div class="metric-grid">
            <div class="card metric">
                <div class="metric-value health-ok" id="avail-val">--</div>
                <div class="metric-label">Availability</div>
            </div>
            <div class="card metric">
                <div class="metric-value health-ok" id="latency-val">--</div>
                <div class="metric-label">P99 Latency</div>
            </div>
            <div class="card metric">
                <div class="metric-value health-ok" id="compliance-val">--</div>
                <div class="metric-label">Compliance</div>
            </div>
            <div class="card metric">
                <div class="metric-value health-ok" id="trust-val">--</div>
                <div class="metric-label">Mean Trust</div>
            </div>
        </div>
    </div>`;
}

/** Build the topology graph tab content. */
function buildTopologyTab(): string {
    return `
    <div id="tab-topology" class="tab-content">
        <div class="card" id="topology-graph">
            <svg id="topology-svg"></svg>
        </div>
    </div>`;
}

/** Build the audit log tab content. */
function buildAuditTab(): string {
    return `
    <div id="tab-audit" class="tab-content">
        <div class="card">
            <div class="card-title">Recent Events</div>
            <div class="audit-list" id="audit-list"></div>
        </div>
    </div>`;
}

/**
 * Render the complete browser dashboard HTML document.
 *
 * @param wsPort - WebSocket port for real-time updates
 * @returns Full HTML document string
 */
export function renderBrowserDashboard(wsPort: number): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Agent OS Governance Dashboard</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>${buildBrowserStyles()}</style>
</head>
<body>
    ${buildBodyContent()}
    <script>${buildTopologyScript()}</script>
    <script>${buildClientScript(wsPort)}</script>
</body>
</html>`;
}
