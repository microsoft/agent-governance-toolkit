// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Governance Hub Styles
 *
 * CSS styles for the unified Governance Hub webview.
 * Provides a tabbed interface combining SLO, Topology, and Audit views.
 */

export function governanceHubStyles(nonce: string): string {
    return `<style nonce="${nonce}">
        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: var(--vscode-font-family);
            font-size: var(--vscode-font-size);
            color: var(--vscode-foreground);
            background: var(--vscode-editor-background);
            height: 100vh;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }

        /* Header */
        .hub-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 12px 16px;
            background: var(--vscode-sideBar-background);
            border-bottom: 1px solid var(--vscode-panel-border);
            flex-shrink: 0;
        }

        .hub-title {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 14px;
            font-weight: 600;
        }

        .hub-title .status-indicator {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--vscode-charts-green, #4caf50);
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.6; transform: scale(0.9); }
        }

        .hub-actions {
            display: flex;
            gap: 8px;
        }

        .hub-actions button {
            background: transparent;
            border: 1px solid var(--vscode-button-border, var(--vscode-panel-border));
            color: var(--vscode-foreground);
            padding: 4px 8px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 11px;
            display: flex;
            align-items: center;
            gap: 4px;
        }

        .hub-actions button:hover {
            background: var(--vscode-button-secondaryHoverBackground);
        }

        /* Tab bar */
        .tab-bar {
            display: flex;
            background: var(--vscode-sideBar-background);
            border-bottom: 1px solid var(--vscode-panel-border);
            flex-shrink: 0;
        }

        .tab {
            padding: 10px 16px;
            cursor: pointer;
            border: none;
            background: transparent;
            color: var(--vscode-foreground);
            font-size: 12px;
            font-weight: 500;
            position: relative;
            opacity: 0.7;
            transition: opacity 0.2s, background 0.2s;
        }

        .tab:hover {
            opacity: 1;
            background: var(--vscode-list-hoverBackground);
        }

        .tab.active {
            opacity: 1;
        }

        .tab.active::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: var(--vscode-focusBorder, var(--vscode-textLink-foreground));
        }

        .tab .badge {
            background: var(--vscode-badge-background);
            color: var(--vscode-badge-foreground);
            padding: 2px 6px;
            border-radius: 10px;
            font-size: 10px;
            margin-left: 6px;
        }

        .tab .badge.alert {
            background: var(--vscode-errorForeground);
            color: white;
        }

        /* Content panels */
        .tab-content {
            flex: 1;
            overflow: auto;
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        /* SLO Panel Styles */
        .slo-panel {
            padding: 16px;
        }

        .metric-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 12px;
            margin-bottom: 16px;
        }

        .metric-card {
            background: var(--vscode-input-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 6px;
            padding: 12px;
            text-align: center;
        }

        .metric-card .label {
            font-size: 10px;
            text-transform: uppercase;
            color: var(--vscode-descriptionForeground);
            margin-bottom: 4px;
        }

        .metric-card .value {
            font-size: 24px;
            font-weight: 700;
        }

        .metric-card .trend {
            font-size: 10px;
            margin-top: 4px;
        }

        .health-ok { color: var(--vscode-charts-green, #4caf50); }
        .health-warn { color: var(--vscode-charts-yellow, #ff9800); }
        .health-critical { color: var(--vscode-charts-red, #f44336); }

        /* Mini gauge */
        .mini-gauge {
            width: 60px;
            height: 60px;
            margin: 0 auto 8px;
        }

        .mini-gauge svg {
            transform: rotate(-90deg);
        }

        .mini-gauge .track {
            fill: none;
            stroke: var(--vscode-panel-border);
            stroke-width: 6;
        }

        .mini-gauge .fill {
            fill: none;
            stroke-width: 6;
            stroke-linecap: round;
            transition: stroke-dasharray 0.5s ease;
        }

        /* Topology Panel Styles */
        .topology-panel {
            height: 100%;
            position: relative;
        }

        .topology-svg {
            width: 100%;
            height: 100%;
            background: var(--vscode-editor-background);
        }

        .agent-node {
            cursor: pointer;
        }

        .agent-node circle {
            stroke-width: 2;
            transition: r 0.2s;
        }

        .agent-node:hover circle {
            stroke-width: 3;
        }

        .agent-node text {
            font-size: 9px;
            fill: var(--vscode-foreground);
            text-anchor: middle;
        }

        .delegation-edge {
            stroke: var(--vscode-panel-border);
            stroke-width: 1;
            opacity: 0.5;
        }

        .topology-tooltip {
            position: absolute;
            background: var(--vscode-editorWidget-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 4px;
            padding: 8px 12px;
            font-size: 11px;
            pointer-events: none;
            z-index: 100;
            box-shadow: 0 2px 8px rgba(0,0,0,0.2);
        }

        /* Audit Panel Styles */
        .audit-panel {
            padding: 0;
        }

        .audit-list {
            list-style: none;
        }

        .audit-item {
            display: flex;
            align-items: flex-start;
            gap: 12px;
            padding: 12px 16px;
            border-bottom: 1px solid var(--vscode-panel-border);
            transition: background 0.2s;
        }

        .audit-item:hover {
            background: var(--vscode-list-hoverBackground);
        }

        .audit-icon {
            width: 24px;
            height: 24px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
            flex-shrink: 0;
        }

        .audit-icon.blocked {
            background: var(--vscode-inputValidation-errorBackground);
            color: var(--vscode-errorForeground);
        }

        .audit-icon.allowed {
            background: rgba(76, 175, 80, 0.2);
            color: var(--vscode-charts-green, #4caf50);
        }

        .audit-icon.warning {
            background: rgba(255, 152, 0, 0.2);
            color: var(--vscode-charts-yellow, #ff9800);
        }

        .audit-content {
            flex: 1;
            min-width: 0;
        }

        .audit-title {
            font-weight: 500;
            margin-bottom: 2px;
        }

        .audit-details {
            font-size: 11px;
            color: var(--vscode-descriptionForeground);
        }

        .audit-time {
            font-size: 10px;
            color: var(--vscode-descriptionForeground);
            flex-shrink: 0;
        }

        .empty-state {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 200px;
            color: var(--vscode-descriptionForeground);
            text-align: center;
            padding: 20px;
        }

        .empty-state .icon {
            font-size: 32px;
            margin-bottom: 12px;
            opacity: 0.5;
        }

        /* Footer status */
        .hub-footer {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 16px;
            background: var(--vscode-sideBar-background);
            border-top: 1px solid var(--vscode-panel-border);
            font-size: 11px;
            color: var(--vscode-descriptionForeground);
            flex-shrink: 0;
        }

        .connection-status {
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .connection-dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: var(--vscode-charts-green, #4caf50);
        }

        .connection-dot.disconnected {
            background: var(--vscode-charts-red, #f44336);
        }
    </style>`;
}
