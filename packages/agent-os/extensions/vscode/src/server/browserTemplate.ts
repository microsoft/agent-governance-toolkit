// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Browser Dashboard Template
 *
 * Full HTML document for the browser-based governance dashboard.
 * Includes D3.js for topology graph visualization
 * and WebSocket client for real-time updates.
 */

import * as fs from 'fs';
import * as path from 'path';
import { buildBrowserStyles } from './browserStyles';
import { buildClientScript, buildTopologyScript, buildHelpContent } from './browserScripts';

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
                    <span id="staleness-badge" style="font-size:11px;opacity:0.7;margin-left:8px"></span>
                    <button id="help-toggle" class="help-btn" title="Help" aria-expanded="false" aria-controls="help-panel">?</button>
                </div>
            </div>
            ${buildSLOTab()}
            ${buildTopologyTab()}
            ${buildAuditTab()}
            <aside id="help-panel" class="help-panel" aria-label="Help panel">
                <div class="help-header">
                    <h2>Help</h2>
                    <button id="help-close" class="help-close-btn">&times;</button>
                </div>
                <input type="text" id="help-search" class="help-search" placeholder="Search help..." />
                <div id="help-content" class="help-body">${buildHelpContent()}</div>
            </aside>
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
 * @param sessionToken - Session token for WebSocket authentication
 * @param nonce - CSP nonce for inline script allowlisting
 * @param extensionPath - Root path of the extension for loading vendored assets
 * @returns Full HTML document string
 */
export function renderBrowserDashboard(
    wsPort: number,
    sessionToken: string,
    nonce: string,
    extensionPath: string,
): string {
    const d3Source = fs.readFileSync(path.join(extensionPath, 'assets', 'vendor', 'd3.v7.8.5.min.js'), 'utf8');
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy"
          content="default-src 'self'; script-src 'nonce-${nonce}'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws://127.0.0.1:*">
    <title>Agent OS Governance Dashboard</title>
    <script nonce="${nonce}">${d3Source}</script>
    <style>${buildBrowserStyles()}</style>
</head>
<body>
    ${buildBodyContent()}
    <script nonce="${nonce}">${buildTopologyScript()}</script>
    <script nonce="${nonce}">${buildClientScript(wsPort, sessionToken)}</script>
</body>
</html>`;
}
