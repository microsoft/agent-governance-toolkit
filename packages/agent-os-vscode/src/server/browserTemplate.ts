// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Browser Dashboard Template — Command Center
 *
 * Single-screen grid layout showing all 8 governance panels
 * simultaneously. Theme-aware, executive-grade.
 */

import * as fs from 'fs';
import * as path from 'path';
import { buildBrowserStyles } from './browserStyles';
import { buildClientScript, buildTopologyScript, buildHelpContent } from './browserScripts';
import { buildPolicyEditorScript, buildPolicyTemplatesJson } from './browserPolicyEditor';

/** Top bar with branding, theme selector, connection status, and help. */
function buildTopBar(): string {
    return `
    <div class="topbar">
        <div class="topbar-left">
            <div class="topbar-brand">
                <span class="topbar-title">Agent OS Governance</span>
            </div>
        </div>
        <div class="topbar-right">
            <span class="staleness" id="staleness-badge"></span>
            <span class="status-dot" id="status-dot"></span>
            <span class="status-label">Live</span>
            <select class="theme-selector" id="theme-select" title="Theme">
                <option value="slate">Corporate Slate</option>
                <option value="midnight">Midnight Blue</option>
                <option value="onyx">Onyx</option>
                <option value="azure">Azure Mist</option>
                <option value="hc-dark">High Contrast Dark</option>
                <option value="hc-light">High Contrast Light</option>
            </select>
            <button class="help-trigger" id="help-toggle" title="Help" aria-expanded="false" aria-controls="help-panel">?</button>
        </div>
    </div>`;
}

/** SLO banner — 4 metric cards with trend arrows, spanning full width. */
function buildSLOBanner(): string {
    return `
    <div class="panel slo-banner">
        <div class="panel-body" style="padding: 6px 10px;">
            <div class="metric-row">
                <div class="metric-card">
                    <div class="metric-val c-ok" id="avail-val">--<span class="metric-trend" id="avail-trend"></span></div>
                    <div class="metric-lbl">Availability</div>
                </div>
                <div class="metric-card">
                    <div class="metric-val c-ok" id="latency-val">--<span class="metric-trend" id="latency-trend"></span></div>
                    <div class="metric-lbl">P99 Latency</div>
                </div>
                <div class="metric-card">
                    <div class="metric-val c-ok" id="compliance-val">--<span class="metric-trend" id="compliance-trend"></span></div>
                    <div class="metric-lbl">Compliance</div>
                </div>
                <div class="metric-card">
                    <div class="metric-val c-ok" id="trust-val">--<span class="metric-trend" id="trust-trend"></span></div>
                    <div class="metric-lbl">Mean Trust</div>
                </div>
            </div>
        </div>
    </div>`;
}

/** Left compound panel — Stats + Kernel + Memory. */
function buildLeftPanel(): string {
    return `
    <div class="panel compound-panel">
        <div class="tab-strip">
            <button class="tab-btn active" data-group="left" data-target="tab-stats">Safety Stats</button>
            <button class="tab-btn" data-group="left" data-target="tab-kernel">Kernel</button>
            <button class="tab-btn" data-group="left" data-target="tab-memory">Memory</button>
        </div>
        <div class="tab-pane active panel-body" id="tab-stats">
            <div class="stat-row"><span class="stat-label">Blocked Today</span><span class="stat-value c-text" id="stat-blocked-today">0</span></div>
            <div class="stat-row"><span class="stat-label">Blocked This Week</span><span class="stat-value c-text" id="stat-blocked-week">0</span></div>
            <div class="stat-row"><span class="stat-label">Warnings Today</span><span class="stat-value c-text" id="stat-warnings">0</span></div>
            <div class="stat-row"><span class="stat-label">CMVK Reviews</span><span class="stat-value c-text" id="stat-cmvk">0</span></div>
            <div class="stat-row"><span class="stat-label">Total Logs</span><span class="stat-value c-text" id="stat-total">0</span></div>
        </div>
        <div class="tab-pane panel-body" id="tab-kernel">
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:4px;margin-bottom:6px;">
                <div class="metric-card" style="padding:5px 6px;border-top-width:0;">
                    <div class="stat-value c-text" id="kern-agents" style="font-size:14px;font-weight:700;">0</div>
                    <div class="metric-lbl">Agents</div>
                </div>
                <div class="metric-card" style="padding:5px 6px;border-top-width:0;">
                    <div class="stat-value c-text" id="kern-violations" style="font-size:14px;font-weight:700;">0</div>
                    <div class="metric-lbl">Violations</div>
                </div>
                <div class="metric-card" style="padding:5px 6px;border-top-width:0;">
                    <div class="stat-value c-text" id="kern-checkpoints" style="font-size:14px;font-weight:700;">0</div>
                    <div class="metric-lbl">Checkpoints</div>
                </div>
                <div class="metric-card" style="padding:5px 6px;border-top-width:0;">
                    <div class="stat-value c-text" id="kern-uptime" style="font-size:14px;font-weight:700;">--</div>
                    <div class="metric-lbl">Uptime</div>
                </div>
            </div>
            <div id="kern-agents-list"></div>
        </div>
        <div class="tab-pane panel-body" id="tab-memory">
            <div style="display:flex;gap:16px;margin-bottom:6px;">
                <div><span class="stat-value c-text" id="mem-dirs" style="font-size:14px;font-weight:700;">0</span><div class="metric-lbl">Dirs</div></div>
                <div><span class="stat-value c-text" id="mem-files" style="font-size:14px;font-weight:700;">0</span><div class="metric-lbl">Files</div></div>
            </div>
            <div id="mem-tree"></div>
        </div>
    </div>`;
}

/** Topology graph — center column. */
function buildTopologyPanel(): string {
    return `
    <div class="panel topology-panel">
        <div class="panel-hdr">
            <span class="panel-title">Agent Topology</span>
            <span class="stat-label" id="topo-count">0 agents / 0 bridges</span>
        </div>
        <div class="panel-body" style="padding:0;">
            <svg id="topology-svg"></svg>
        </div>
    </div>`;
}

/** Right compound panel — Policies + Audit + Editor. */
function buildRightPanel(): string {
    return `
    <div class="panel compound-panel">
        <div class="tab-strip">
            <button class="tab-btn active" data-group="right" data-target="tab-policies">Policies <span class="stat-label" id="policy-count"></span></button>
            <button class="tab-btn" data-group="right" data-target="tab-audit">Audit <span class="stat-label" id="audit-count"></span></button>
            <button class="tab-btn" data-group="right" data-target="tab-editor">Editor</button>
        </div>
        <div class="tab-pane active panel-body" id="tab-policies">
            <div class="filter-bar">
                <input class="filter-input" id="policy-filter" type="text" placeholder="Filter policies..." />
                <select class="filter-select" id="policy-action-filter">
                    <option value="">All actions</option>
                    <option value="DENY">DENY</option>
                    <option value="BLOCK">BLOCK</option>
                    <option value="AUDIT">AUDIT</option>
                    <option value="ALLOW">ALLOW</option>
                </select>
                <span class="filter-count" id="policy-filter-count"></span>
            </div>
            <div id="policy-list"><div class="empty">No policies loaded</div></div>
        </div>
        <div class="tab-pane panel-body" id="tab-audit">
            <div class="filter-bar">
                <input class="filter-input" id="audit-filter" type="text" placeholder="Filter audit events..." />
                <select class="filter-select" id="audit-sev-filter">
                    <option value="">All severity</option>
                    <option value="critical">Critical</option>
                    <option value="warning">Warning</option>
                    <option value="info">Info</option>
                </select>
                <span class="filter-count" id="audit-filter-count"></span>
            </div>
            <div id="audit-list"><div class="empty">No audit events</div></div>
        </div>
        <div class="tab-pane" id="tab-editor" style="padding:0;">
            <div class="pe-toolbar">
                <select id="pe-template" title="Template"><option value="">Select template...</option></select>
                <select id="pe-format" title="Format">
                    <option value="yaml">YAML</option>
                    <option value="json">JSON</option>
                    <option value="rego">Rego</option>
                </select>
                <button id="pe-validate">Validate</button>
                <button id="pe-test">Test</button>
                <button id="pe-download" class="secondary">Download</button>
                <button id="pe-import" class="secondary">Import</button>
                <input type="file" id="pe-file-input" accept=".yaml,.yml,.json,.rego" style="display:none;" />
            </div>
            <div class="pe-editor-wrap">
                <div class="pe-lines" id="pe-lines">1</div>
                <textarea class="pe-editor" id="pe-editor" spellcheck="false" placeholder="Select a template or start typing..."></textarea>
            </div>
            <div class="pe-results" id="pe-results"></div>
        </div>
    </div>`;
}

/** Help side panel (slides in from right). */
function buildHelpPanel(): string {
    return `
    <aside id="help-panel" class="help-panel" aria-label="Help panel">
        <div class="help-header">
            <h2>Help</h2>
            <button id="help-close" class="help-close-btn">&times;</button>
        </div>
        <input type="text" id="help-search" class="help-search" placeholder="Search help..." />
        <div id="help-content" class="help-body">${buildHelpContent()}</div>
    </aside>`;
}

/**
 * Render the complete command center HTML document.
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
          content="default-src 'self' blob:; script-src 'nonce-${nonce}'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws://127.0.0.1:*">
    <title>Agent OS Governance</title>
    <script nonce="${nonce}">${d3Source}</script>
    <style>${buildBrowserStyles()}</style>
</head>
<body>
    <script nonce="${nonce}">(function(){var t=localStorage.getItem('agent-os-theme');if(t){document.documentElement.dataset.theme=t;}})()</script>
    ${buildTopBar()}
    <div class="grid-shell">
        ${buildSLOBanner()}
        ${buildLeftPanel()}
        ${buildTopologyPanel()}
        ${buildRightPanel()}
    </div>
    ${buildHelpPanel()}
    <script nonce="${nonce}">window.__policyTemplates=${buildPolicyTemplatesJson()};</script>
    <script nonce="${nonce}">${buildTopologyScript()}</script>
    <script nonce="${nonce}">${buildClientScript(wsPort, sessionToken)}</script>
    <script nonce="${nonce}">${buildPolicyEditorScript()}</script>
</body>
</html>`;
}
