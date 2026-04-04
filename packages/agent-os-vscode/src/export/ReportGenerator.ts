// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Governance report generator.
 *
 * Produces self-contained HTML reports with embedded data and visualizations.
 */

import * as fs from 'fs';
import * as path from 'path';
import { SLOSnapshot } from '../views/sloTypes';
import { AgentNode, BridgeStatus, DelegationChain } from '../views/topologyTypes';

/** A single audit event entry. */
export interface AuditEntry {
    timestamp: Date;
    type: string;
    details: Record<string, unknown>;
}

/** Time range for the report. */
export interface TimeRange {
    start: Date;
    end: Date;
}

/** Input data for report generation. */
export interface ReportData {
    sloSnapshot: SLOSnapshot;
    agents: AgentNode[];
    bridges: BridgeStatus[];
    delegations: DelegationChain[];
    auditEvents: AuditEntry[];
    timeRange: TimeRange;
}

/**
 * Generate self-contained HTML governance reports.
 */
export class ReportGenerator {
    /**
     * Generate a complete HTML report.
     *
     * @param data - All report data inputs.
     * @returns Self-contained HTML string.
     */
    generate(data: ReportData): string {
        const jsonData = this.serializeData(data);
        const generatedAt = new Date().toISOString();

        return this.buildHtml(jsonData, generatedAt, data.timeRange);
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private serializeData(data: ReportData): string {
        const serializable = {
            sloSnapshot: data.sloSnapshot,
            agents: data.agents,
            bridges: data.bridges,
            delegations: data.delegations,
            auditEvents: data.auditEvents.map((e) => ({
                ...e,
                timestamp: e.timestamp.toISOString(),
            })),
            timeRange: {
                start: data.timeRange.start.toISOString(),
                end: data.timeRange.end.toISOString(),
            },
        };
        return JSON.stringify(serializable, null, 2);
    }

    private buildHtml(
        jsonData: string,
        generatedAt: string,
        timeRange: TimeRange
    ): string {
        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Governance Report</title>
    <script>${fs.readFileSync(path.resolve(__dirname, '..', '..', 'assets', 'vendor', 'chart.v4.4.1.umd.min.js'), 'utf8')}</script>
    <style>${this.getStyles()}</style>
</head>
<body>
    <header class="report-header">
        <h1>Agent Governance Report</h1>
        <div class="metadata">
            <span>Generated: ${generatedAt}</span>
            <span>Period: ${timeRange.start.toISOString()} - ${timeRange.end.toISOString()}</span>
        </div>
    </header>
    <main id="report-content">
        <section id="slo-section"><h2>SLO Metrics</h2></section>
        <section id="topology-section"><h2>Agent Topology</h2></section>
        <section id="audit-section"><h2>Audit Trail</h2></section>
    </main>
    <footer class="report-footer">
        <p>Agent Governance Toolkit - Microsoft</p>
    </footer>
    <script id="report-data" type="application/json">${jsonData.replace(/<\//g, '<\\/')}</script>
    <script>${this.getRenderScript()}</script>
</body>
</html>`;
    }

    private getStyles(): string {
        return `
:root { --primary: #0078d4; --success: #107c10; --warning: #ffb900; --error: #d13438; }
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; line-height: 1.6; padding: 2rem; max-width: 1200px; margin: 0 auto; }
.report-header { border-bottom: 2px solid var(--primary); padding-bottom: 1rem; margin-bottom: 2rem; }
.report-header h1 { color: var(--primary); }
.metadata { display: flex; gap: 2rem; color: #666; font-size: 0.9rem; margin-top: 0.5rem; }
section { margin-bottom: 2rem; padding: 1.5rem; background: #f9f9f9; border-radius: 8px; }
section h2 { color: #333; margin-bottom: 1rem; }
.metric-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; }
.metric-card { background: white; padding: 1rem; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
.metric-value { font-size: 2rem; font-weight: bold; }
.healthy { color: var(--success); }
.warning { color: var(--warning); }
.breached { color: var(--error); }
table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #ddd; }
th { background: #e8e8e8; }
.report-footer { text-align: center; color: #666; font-size: 0.8rem; margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #ddd; }
@media print { body { padding: 0; } section { break-inside: avoid; } }`;
    }

    private getRenderScript(): string {
        return `
(function() {
    var esc = function(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); };
    const data = JSON.parse(document.getElementById('report-data').textContent);
    renderSLO(data.sloSnapshot);
    renderTopology(data.agents, data.bridges, data.delegations);
    renderAudit(data.auditEvents);

    function renderSLO(slo) {
        const section = document.getElementById('slo-section');
        const health = (v, t) => v >= t ? 'healthy' : v >= t * 0.9 ? 'warning' : 'breached';
        section.innerHTML += '<div class="metric-grid">' +
            metricCard('Availability', slo.availability.currentPercent.toFixed(2) + '%', health(slo.availability.currentPercent, slo.availability.targetPercent)) +
            metricCard('P99 Latency', slo.latency.p99Ms + 'ms', health(slo.latency.targetMs, slo.latency.p99Ms)) +
            metricCard('Compliance', slo.policyCompliance.compliancePercent.toFixed(1) + '%', health(slo.policyCompliance.compliancePercent, 95)) +
            metricCard('Trust Score', slo.trustScore.meanScore, slo.trustScore.meanScore > 700 ? 'healthy' : slo.trustScore.meanScore > 400 ? 'warning' : 'breached') +
            '</div>';
    }

    function metricCard(label, value, status) {
        return '<div class="metric-card"><div class="metric-label">' + esc(label) + '</div><div class="metric-value ' + esc(status) + '">' + esc(value) + '</div></div>';
    }

    function renderTopology(agents, bridges, delegations) {
        const section = document.getElementById('topology-section');
        section.innerHTML += '<h3>Agents (' + agents.length + ')</h3><table><tr><th>DID</th><th>Trust</th><th>Ring</th></tr>' +
            agents.map(a => '<tr><td>' + esc(a.did) + '</td><td>' + esc(a.trustScore) + '</td><td>Ring ' + esc(a.ring) + '</td></tr>').join('') + '</table>';
        section.innerHTML += '<h3>Bridges</h3><table><tr><th>Protocol</th><th>Status</th><th>Peers</th></tr>' +
            bridges.map(b => '<tr><td>' + esc(b.protocol) + '</td><td>' + (b.connected ? 'Connected' : 'Disconnected') + '</td><td>' + esc(b.peerCount) + '</td></tr>').join('') + '</table>';
    }

    function renderAudit(events) {
        const section = document.getElementById('audit-section');
        section.innerHTML += '<table><tr><th>Timestamp</th><th>Type</th><th>Details</th></tr>' +
            events.map(e => '<tr><td>' + esc(e.timestamp) + '</td><td>' + esc(e.type) + '</td><td>' + esc(JSON.stringify(e.details)) + '</td></tr>').join('') + '</table>';
    }
})();`;
    }
}
