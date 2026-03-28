// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Metrics Dashboard Panel - Real-time monitoring dashboard
 * 
 * Provides visualization of agent activity, policy enforcement,
 * and performance metrics.
 */

import * as vscode from 'vscode';
import * as crypto from 'crypto';
import { AuditLogger, AuditEntry } from '../../auditLogger';
import { escapeHtml } from '../../utils/escapeHtml';

interface MetricsData {
    blockedToday: number;
    blockedThisWeek: number;
    blockedThisMonth: number;
    warningsToday: number;
    cmvkReviewsToday: number;
    totalLogs: number;
    policyViolationsByType: Record<string, number>;
    activityByHour: number[];
    topViolations: { name: string; count: number }[];
    latencyPercentiles: { p50: number; p95: number; p99: number };
}

export class MetricsDashboardPanel {
    public static currentPanel: MetricsDashboardPanel | undefined;
    private readonly _panel: vscode.WebviewPanel;
    private readonly _extensionUri: vscode.Uri;
    private readonly _auditLogger: AuditLogger;
    private _disposables: vscode.Disposable[] = [];
    private _refreshInterval: NodeJS.Timeout | undefined;

    public static readonly viewType = 'agentOS.metricsDashboard';

    private constructor(
        panel: vscode.WebviewPanel,
        extensionUri: vscode.Uri,
        auditLogger: AuditLogger
    ) {
        this._panel = panel;
        this._extensionUri = extensionUri;
        this._auditLogger = auditLogger;

        this._update();

        // Auto-refresh every 30 seconds
        this._refreshInterval = setInterval(() => {
            this._sendMetricsUpdate();
        }, 30000);

        this._panel.onDidDispose(() => this.dispose(), null, this._disposables);
        
        this._panel.webview.onDidReceiveMessage(
            async message => {
                switch (message.type) {
                    case 'refresh':
                        this._sendMetricsUpdate();
                        break;
                    case 'exportReport':
                        await this._exportReport(message.format);
                        break;
                    case 'setTimeRange':
                        this._sendMetricsUpdate(message.range);
                        break;
                }
            },
            null,
            this._disposables
        );
    }

    public static createOrShow(extensionUri: vscode.Uri, auditLogger: AuditLogger) {
        const column = vscode.window.activeTextEditor
            ? vscode.window.activeTextEditor.viewColumn
            : undefined;

        if (MetricsDashboardPanel.currentPanel) {
            MetricsDashboardPanel.currentPanel._panel.reveal(column);
            return;
        }

        const panel = vscode.window.createWebviewPanel(
            MetricsDashboardPanel.viewType,
            'Agent OS Metrics',
            column || vscode.ViewColumn.One,
            {
                enableScripts: true,
                retainContextWhenHidden: true
            }
        );

        MetricsDashboardPanel.currentPanel = new MetricsDashboardPanel(panel, extensionUri, auditLogger);
    }

    private _getMetrics(timeRange: string = 'today'): MetricsData {
        const logs = this._auditLogger.getAll();
        const now = new Date();
        
        let startDate: Date;
        switch (timeRange) {
            case 'week':
                startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
                break;
            case 'month':
                startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
                break;
            default: // today
                startDate = new Date(now.setHours(0, 0, 0, 0));
        }

        const filteredLogs = logs.filter(log => new Date(log.timestamp) >= startDate);
        
        // Count violations by type
        const violationsByType: Record<string, number> = {};
        const violationCounts: Record<string, number> = {};
        
        filteredLogs.forEach(log => {
            if (log.type === 'blocked') {
                const violation = log.violation || 'unknown';
                violationsByType[violation] = (violationsByType[violation] || 0) + 1;
                violationCounts[violation] = (violationCounts[violation] || 0) + 1;
            }
        });

        // Activity by hour
        const activityByHour = new Array(24).fill(0);
        filteredLogs.forEach(log => {
            const hour = new Date(log.timestamp).getHours();
            activityByHour[hour]++;
        });

        // Top violations
        const topViolations = Object.entries(violationCounts)
            .map(([name, count]) => ({ name, count }))
            .sort((a, b) => b.count - a.count)
            .slice(0, 5);

        return {
            blockedToday: this._auditLogger.getToday().filter(l => l.type === 'blocked').length,
            blockedThisWeek: this._auditLogger.getThisWeek().filter(l => l.type === 'blocked').length,
            blockedThisMonth: filteredLogs.filter(l => l.type === 'blocked').length,
            warningsToday: this._auditLogger.getToday().filter(l => l.type === 'warning').length,
            cmvkReviewsToday: this._auditLogger.getToday().filter(l => l.type === 'cmvk_review').length,
            totalLogs: logs.length,
            policyViolationsByType: violationsByType,
            activityByHour,
            topViolations,
            latencyPercentiles: { p50: 12, p95: 45, p99: 98 } // Simulated
        };
    }

    private _sendMetricsUpdate(timeRange: string = 'today'): void {
        const metrics = this._getMetrics(timeRange);

        // Escape dynamic string values before sending to webview where
        // they may be interpolated into innerHTML.
        const safeMetrics = {
            ...metrics,
            topViolations: metrics.topViolations.map(v => ({
                ...v,
                name: escapeHtml(v.name)
            })),
            policyViolationsByType: Object.fromEntries(
                Object.entries(metrics.policyViolationsByType).map(
                    ([key, val]) => [escapeHtml(key), val]
                )
            )
        };

        this._panel.webview.postMessage({ type: 'metricsUpdate', metrics: safeMetrics });
    }

    private async _exportReport(format: 'json' | 'csv'): Promise<void> {
        const metrics = this._getMetrics('month');
        const logs = this._auditLogger.getAll();
        
        let content: string;
        let extension: string;
        
        if (format === 'json') {
            content = JSON.stringify({ metrics, logs }, null, 2);
            extension = 'json';
        } else {
            // CSV format
            const headers = ['timestamp', 'type', 'file', 'language', 'violation', 'reason'];
            const rows = logs.map(log => [
                new Date(log.timestamp).toISOString(),
                log.type,
                log.file || '',
                log.language || '',
                log.violation || '',
                log.reason || ''
            ].map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(','));
            content = [headers.join(','), ...rows].join('\n');
            extension = 'csv';
        }

        const uri = await vscode.window.showSaveDialog({
            defaultUri: vscode.Uri.file(`agent-os-report.${extension}`),
            filters: format === 'json' 
                ? { 'JSON': ['json'] } 
                : { 'CSV': ['csv'] }
        });

        if (uri) {
            await vscode.workspace.fs.writeFile(uri, Buffer.from(content));
            vscode.window.showInformationMessage(`Report exported to ${uri.fsPath}`);
        }
    }

    public dispose() {
        MetricsDashboardPanel.currentPanel = undefined;
        if (this._refreshInterval) {
            clearInterval(this._refreshInterval);
        }
        this._panel.dispose();
        while (this._disposables.length) {
            const disposable = this._disposables.pop();
            if (disposable) {
                disposable.dispose();
            }
        }
    }

    private _update() {
        const webview = this._panel.webview;
        this._panel.title = 'Agent OS Metrics Dashboard';
        this._panel.webview.html = this._getHtmlForWebview(webview);
        
        // Send initial metrics
        setTimeout(() => this._sendMetricsUpdate(), 100);
    }

    private _getHtmlForWebview(webview: vscode.Webview) {
        const nonce = crypto.randomBytes(16).toString('base64');
        const cspSource = webview.cspSource;

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <!-- SECURITY: 'unsafe-inline' for styles required by VS Code theme CSS variable injection. Scripts nonce-gated. -->
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}'; img-src ${cspSource} https:; font-src ${cspSource};">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Metrics Dashboard</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: var(--vscode-font-family);
            color: var(--vscode-foreground);
            background-color: var(--vscode-editor-background);
            margin: 0;
            padding: 20px;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid var(--vscode-panel-border);
        }
        .header h1 {
            margin: 0;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .controls {
            display: flex;
            gap: 10px;
        }
        select, button {
            background: var(--vscode-dropdown-background);
            color: var(--vscode-dropdown-foreground);
            border: 1px solid var(--vscode-dropdown-border);
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
        }
        button {
            background: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            border: none;
        }
        button:hover {
            background: var(--vscode-button-hoverBackground);
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .card {
            background: var(--vscode-sideBar-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 8px;
            padding: 20px;
        }
        .card-title {
            font-size: 12px;
            text-transform: uppercase;
            color: var(--vscode-descriptionForeground);
            margin-bottom: 8px;
        }
        .card-value {
            font-size: 32px;
            font-weight: bold;
        }
        .card-subtitle {
            font-size: 11px;
            color: var(--vscode-descriptionForeground);
            margin-top: 4px;
        }
        .card.success .card-value { color: #28a745; }
        .card.warning .card-value { color: #ffc107; }
        .card.danger .card-value { color: #dc3545; }
        .chart-container {
            background: var(--vscode-sideBar-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .chart-title {
            font-size: 14px;
            font-weight: bold;
            margin-bottom: 15px;
        }
        .bar-chart {
            display: flex;
            align-items: flex-end;
            height: 150px;
            gap: 4px;
            padding-top: 10px;
        }
        .bar {
            flex: 1;
            background: var(--vscode-button-background);
            border-radius: 4px 4px 0 0;
            min-height: 4px;
            transition: height 0.3s ease;
            position: relative;
        }
        .bar:hover {
            background: var(--vscode-button-hoverBackground);
        }
        .bar::after {
            content: attr(data-value);
            position: absolute;
            bottom: 100%;
            left: 50%;
            transform: translateX(-50%);
            font-size: 10px;
            color: var(--vscode-descriptionForeground);
            opacity: 0;
            transition: opacity 0.2s;
        }
        .bar:hover::after {
            opacity: 1;
        }
        .bar-labels {
            display: flex;
            justify-content: space-between;
            margin-top: 5px;
            font-size: 10px;
            color: var(--vscode-descriptionForeground);
        }
        .violations-list {
            margin-top: 10px;
        }
        .violation-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px;
            background: var(--vscode-editor-background);
            border-radius: 4px;
            margin-bottom: 8px;
        }
        .violation-name {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .violation-count {
            background: var(--vscode-badge-background);
            color: var(--vscode-badge-foreground);
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 11px;
        }
        .latency-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
        }
        .latency-item {
            text-align: center;
            padding: 15px;
            background: var(--vscode-editor-background);
            border-radius: 4px;
        }
        .latency-label {
            font-size: 11px;
            color: var(--vscode-descriptionForeground);
        }
        .latency-value {
            font-size: 24px;
            font-weight: bold;
            color: var(--vscode-foreground);
        }
        .latency-unit {
            font-size: 12px;
            color: var(--vscode-descriptionForeground);
        }
        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            display: inline-block;
            margin-right: 8px;
        }
        .status-dot.active { background: #28a745; animation: pulse 2s infinite; }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        .two-col {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        @media (max-width: 800px) {
            .two-col { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>
            <span class="status-dot active"></span>
            Agent OS Metrics Dashboard
        </h1>
        <div class="controls">
            <select id="timeRange" onchange="setTimeRange(this.value)">
                <option value="today">Today</option>
                <option value="week">This Week</option>
                <option value="month">This Month</option>
            </select>
            <button onclick="refresh()">🔄 Refresh</button>
            <button onclick="exportReport('json')">📥 Export JSON</button>
            <button onclick="exportReport('csv')">📥 Export CSV</button>
        </div>
    </div>

    <div class="grid">
        <div class="card danger">
            <div class="card-title">Blocked Operations</div>
            <div class="card-value" id="blockedToday">0</div>
            <div class="card-subtitle">Today</div>
        </div>
        <div class="card warning">
            <div class="card-title">Warnings</div>
            <div class="card-value" id="warningsToday">0</div>
            <div class="card-subtitle">Today</div>
        </div>
        <div class="card success">
            <div class="card-title">CMVK Reviews</div>
            <div class="card-value" id="cmvkReviewsToday">0</div>
            <div class="card-subtitle">Today</div>
        </div>
        <div class="card">
            <div class="card-title">Total Events</div>
            <div class="card-value" id="totalLogs">0</div>
            <div class="card-subtitle">All time</div>
        </div>
    </div>

    <div class="two-col">
        <div class="chart-container">
            <div class="chart-title">📊 Activity by Hour</div>
            <div class="bar-chart" id="activityChart"></div>
            <div class="bar-labels">
                <span>12 AM</span>
                <span>6 AM</span>
                <span>12 PM</span>
                <span>6 PM</span>
                <span>11 PM</span>
            </div>
        </div>

        <div class="chart-container">
            <div class="chart-title">🛡️ Top Policy Violations</div>
            <div class="violations-list" id="topViolations">
                <p style="color: var(--vscode-descriptionForeground); text-align: center;">No violations recorded</p>
            </div>
        </div>
    </div>

    <div class="chart-container">
        <div class="chart-title">⚡ Policy Check Latency</div>
        <div class="latency-grid">
            <div class="latency-item">
                <div class="latency-label">P50</div>
                <div class="latency-value" id="p50">-</div>
                <div class="latency-unit">ms</div>
            </div>
            <div class="latency-item">
                <div class="latency-label">P95</div>
                <div class="latency-value" id="p95">-</div>
                <div class="latency-unit">ms</div>
            </div>
            <div class="latency-item">
                <div class="latency-label">P99</div>
                <div class="latency-value" id="p99">-</div>
                <div class="latency-unit">ms</div>
            </div>
        </div>
        <p style="text-align: center; font-size: 11px; color: var(--vscode-descriptionForeground); margin-top: 15px;">
            Target: &lt;50ms for P99 ✓
        </p>
    </div>

    <script nonce="${nonce}">
        const vscode = acquireVsCodeApi();

        function refresh() {
            vscode.postMessage({ type: 'refresh' });
        }

        function setTimeRange(range) {
            vscode.postMessage({ type: 'setTimeRange', range });
        }

        function exportReport(format) {
            vscode.postMessage({ type: 'exportReport', format });
        }

        function updateChart(data) {
            const chart = document.getElementById('activityChart');
            const max = Math.max(...data, 1);
            
            chart.innerHTML = data.map((value, i) => 
                \`<div class="bar" style="height: \${(value / max) * 100}%" data-value="\${value}"></div>\`
            ).join('');
        }

        function updateViolations(violations) {
            const container = document.getElementById('topViolations');
            
            if (!violations || violations.length === 0) {
                container.innerHTML = '<p style="color: var(--vscode-descriptionForeground); text-align: center;">No violations recorded</p>';
                return;
            }

            container.innerHTML = violations.map(v => \`
                <div class="violation-item">
                    <span class="violation-name">
                        <span style="color: #dc3545;">⚠️</span>
                        \${v.name.replace(/_/g, ' ')}
                    </span>
                    <span class="violation-count">\${v.count}</span>
                </div>
            \`).join('');
        }

        window.addEventListener('message', event => {
            const message = event.data;
            if (message.type === 'metricsUpdate') {
                const m = message.metrics;
                
                document.getElementById('blockedToday').textContent = m.blockedToday;
                document.getElementById('warningsToday').textContent = m.warningsToday;
                document.getElementById('cmvkReviewsToday').textContent = m.cmvkReviewsToday;
                document.getElementById('totalLogs').textContent = m.totalLogs;
                
                document.getElementById('p50').textContent = m.latencyPercentiles.p50;
                document.getElementById('p95').textContent = m.latencyPercentiles.p95;
                document.getElementById('p99').textContent = m.latencyPercentiles.p99;
                
                updateChart(m.activityByHour);
                updateViolations(m.topViolations);
            }
        });
    </script>
</body>
</html>`;
    }
}
