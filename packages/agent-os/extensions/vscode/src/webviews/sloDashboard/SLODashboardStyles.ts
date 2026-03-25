// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * SLO Dashboard Styles
 *
 * CSS styles for the SLO Dashboard webview panel.
 * Uses exclusively VS Code theme tokens for full light/dark theme compatibility.
 */

/**
 * Returns a complete `<style>` block for the SLO Dashboard.
 * All colors use `var(--vscode-*)` tokens — zero hardcoded values.
 */
export function sloStyles(nonce: string): string {
    return `<style nonce="${nonce}">
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: var(--vscode-font-family);
            font-size: var(--vscode-font-size);
            color: var(--vscode-foreground);
            background-color: var(--vscode-editor-background);
            padding: 20px; line-height: 1.4;
        }
        .dashboard-header {
            display: flex; justify-content: space-between; align-items: center;
            padding-bottom: 16px; margin-bottom: 20px;
            border-bottom: 1px solid var(--vscode-panel-border);
        }
        .dashboard-header h1 {
            font-size: 18px; font-weight: 600;
            display: flex; align-items: center; gap: 10px;
        }
        .status-dot {
            width: 10px; height: 10px; border-radius: 50%; display: inline-block;
            background: var(--vscode-charts-green, var(--vscode-testing-iconPassed));
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        .refresh-btn {
            background: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            border: none; padding: 6px 14px; border-radius: 4px;
            cursor: pointer; font-size: 12px;
        }
        .refresh-btn:hover { background: var(--vscode-button-hoverBackground); }
        .section { margin-bottom: 20px; }
        .section-title {
            font-size: 13px; font-weight: 600; text-transform: uppercase;
            letter-spacing: 0.5px; color: var(--vscode-descriptionForeground);
            margin-bottom: 12px;
        }
        .metric-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px; margin-bottom: 20px;
        }
        .metric-card {
            background: var(--vscode-sideBar-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 6px; padding: 16px;
            transition: border-color 0.2s ease;
        }
        .metric-card:hover { border-color: var(--vscode-focusBorder); }
        .metric-card .label {
            font-size: 11px; text-transform: uppercase;
            color: var(--vscode-descriptionForeground); margin-bottom: 6px;
        }
        .metric-card .value { font-size: 28px; font-weight: 700; transition: color 0.3s ease; }
        .metric-card .subtitle {
            font-size: 11px; color: var(--vscode-descriptionForeground); margin-top: 4px;
        }
        .two-col {
            display: grid; grid-template-columns: 1fr 1fr;
            gap: 16px; margin-bottom: 20px;
        }
        @media (max-width: 700px) { .two-col { grid-template-columns: 1fr; } }
        .panel {
            background: var(--vscode-sideBar-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 6px; padding: 16px;
        }
        .gauge-container {
            position: relative; width: 120px; height: 120px; margin: 8px auto;
        }
        .gauge-container svg { transform: rotate(-225deg); }
        .gauge-label {
            position: absolute; top: 50%; left: 50%;
            transform: translate(-50%, -50%); text-align: center;
        }
        .gauge-label .gauge-value {
            font-size: 22px; font-weight: 700;
            color: var(--vscode-foreground); transition: color 0.3s ease;
        }
        .gauge-label .gauge-unit { font-size: 10px; color: var(--vscode-descriptionForeground); }
        .gauge-track {
            fill: none;
            stroke: var(--vscode-editorWidget-border, var(--vscode-panel-border));
            opacity: 0.3;
        }
        .gauge-arc {
            fill: none; stroke-linecap: round;
            transition: stroke-dasharray 0.6s ease, stroke 0.3s ease;
        }
        .sparkline-container { margin: 8px 0; }
        .sparkline { width: 100%; height: 40px; }
        .sparkline polyline {
            fill: none; stroke-width: 1.5; stroke-linejoin: round; stroke-linecap: round;
            stroke: var(--vscode-charts-blue, var(--vscode-textLink-foreground));
        }
        .budget-bar {
            height: 8px; border-radius: 4px; overflow: hidden; margin: 6px 0 12px 0;
            background: var(--vscode-editorWidget-border, var(--vscode-panel-border));
        }
        .budget-bar .fill {
            height: 100%; border-radius: 4px;
            transition: width 0.5s ease, background-color 0.3s ease;
        }
        .latency-row {
            display: flex; align-items: center; gap: 10px; margin-bottom: 8px;
        }
        .latency-row .lat-label {
            width: 36px; font-size: 11px; font-weight: 600;
            color: var(--vscode-descriptionForeground); text-align: right;
        }
        .latency-bar {
            flex: 1; height: 14px; border-radius: 3px; overflow: hidden;
            background: var(--vscode-editorWidget-border, var(--vscode-panel-border));
        }
        .latency-bar .fill {
            height: 100%; border-radius: 3px;
            transition: width 0.5s ease, background-color 0.3s ease;
        }
        .latency-row .lat-value { width: 50px; font-size: 11px; color: var(--vscode-foreground); }
        .dist-bar {
            display: flex; height: 18px; border-radius: 4px;
            overflow: hidden; margin: 8px 0;
        }
        .dist-bar .segment { transition: flex 0.5s ease; min-width: 2px; }
        .dist-bar .seg-critical { background: var(--vscode-charts-red, var(--vscode-errorForeground)); }
        .dist-bar .seg-low { background: var(--vscode-charts-orange, var(--vscode-list-warningForeground)); }
        .dist-bar .seg-medium { background: var(--vscode-charts-yellow, var(--vscode-editorWarning-foreground)); }
        .dist-bar .seg-high { background: var(--vscode-charts-green, var(--vscode-testing-iconPassed)); }
        .dist-legend {
            display: flex; gap: 12px; flex-wrap: wrap; margin-top: 6px;
        }
        .dist-legend span {
            font-size: 10px; color: var(--vscode-descriptionForeground);
            display: flex; align-items: center; gap: 4px;
        }
        .dist-legend .swatch {
            width: 8px; height: 8px; border-radius: 2px; display: inline-block;
        }
        .health-ok { color: var(--vscode-charts-green, var(--vscode-testing-iconPassed)); }
        .health-warn { color: var(--vscode-charts-yellow, var(--vscode-editorWarning-foreground)); }
        .health-breach { color: var(--vscode-charts-red, var(--vscode-errorForeground)); }
        .fill-ok { background: var(--vscode-charts-green, var(--vscode-testing-iconPassed)); }
        .fill-warn { background: var(--vscode-charts-yellow, var(--vscode-editorWarning-foreground)); }
        .fill-breach { background: var(--vscode-charts-red, var(--vscode-errorForeground)); }
        .stroke-ok { stroke: var(--vscode-charts-green, var(--vscode-testing-iconPassed)); }
        .stroke-warn { stroke: var(--vscode-charts-yellow, var(--vscode-editorWarning-foreground)); }
        .stroke-breach { stroke: var(--vscode-charts-red, var(--vscode-errorForeground)); }
        .burn-rate-value {
            font-size: 20px; font-weight: 700; text-align: center; margin-top: 4px;
        }
        .budget-label {
            display: flex; justify-content: space-between;
            font-size: 11px; color: var(--vscode-descriptionForeground);
        }
    </style>`;
}
