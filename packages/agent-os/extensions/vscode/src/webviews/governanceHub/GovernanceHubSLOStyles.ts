// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Governance Hub SLO Styles
 *
 * CSS for SLO metric cards, gauges, error budgets, and trust distribution.
 */

/** Returns SLO panel CSS including metrics, gauges, and budgets. */
export function sloStyles(): string {
    return `
        /* SLO Panel Styles */
        .slo-panel { padding: 16px; }

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

        .metric-card .value { font-size: 24px; font-weight: 700; }
        .metric-card .trend { font-size: 10px; margin-top: 4px; }

        .health-ok { color: var(--vscode-charts-green, #4caf50); }
        .health-warn { color: var(--vscode-charts-yellow, #ff9800); }
        .health-critical { color: var(--vscode-charts-red, #f44336); }

        /* SLO Details Section */
        .slo-details {
            background: var(--vscode-input-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 6px;
            padding: 12px;
            margin-top: 12px;
        }

        .detail-row {
            display: flex;
            justify-content: space-between;
            padding: 6px 0;
            border-bottom: 1px solid var(--vscode-panel-border);
            font-size: 12px;
        }

        .detail-row:last-child { border-bottom: none; }

        /* Mini gauge */
        .mini-gauge { width: 60px; height: 60px; margin: 0 auto 8px; }
        .mini-gauge svg { transform: rotate(-90deg); }
        .mini-gauge .track { fill: none; stroke: var(--vscode-panel-border); stroke-width: 6; }
        .mini-gauge .fill {
            fill: none;
            stroke-width: 6;
            stroke-linecap: round;
            transition: stroke-dasharray 0.5s ease;
        }

        /* Two-Column Layout for Wide Panels */
        @media (min-width: 600px) {
            .slo-panel {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 16px;
            }
            .slo-panel .metric-row { grid-column: 1 / -1; }
            .slo-panel .slo-details { grid-column: 1; }
            .slo-panel .slo-secondary { grid-column: 2; }
        }

        /* Trust Distribution Bar */
        .trust-distribution {
            display: flex;
            height: 24px;
            border-radius: 4px;
            overflow: hidden;
            margin-bottom: 12px;
        }
        .trust-distribution .segment {
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 10px;
            font-weight: 600;
            color: white;
            min-width: 20px;
        }
        .trust-distribution .segment.low { background: var(--vscode-charts-red, #f44336); }
        .trust-distribution .segment.medium { background: var(--vscode-charts-yellow, #ff9800); }
        .trust-distribution .segment.high { background: var(--vscode-charts-blue, #2196f3); }
        .trust-distribution .segment.top { background: var(--vscode-charts-green, #4caf50); }

        /* Error Budget Progress Bars */
        .budget-bar { margin-bottom: 12px; }
        .budget-bar .label {
            display: flex;
            justify-content: space-between;
            font-size: 11px;
            margin-bottom: 4px;
        }
        .budget-bar .label .name { color: var(--vscode-foreground); }
        .budget-bar .label .value {
            font-weight: 600;
            font-variant-numeric: tabular-nums;
        }
        .budget-bar .track {
            height: 8px;
            background: var(--vscode-input-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 4px;
            overflow: hidden;
        }
        .budget-bar .fill { height: 100%; transition: width 0.3s; }
        .budget-bar .fill.healthy { background: var(--vscode-charts-green, #4caf50); }
        .budget-bar .fill.warning { background: var(--vscode-charts-yellow, #ff9800); }
        .budget-bar .fill.critical { background: var(--vscode-charts-red, #f44336); }

        /* Secondary Section Styling */
        .slo-secondary {
            background: var(--vscode-input-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 6px;
            padding: 12px;
            margin-top: 12px;
        }
        .slo-secondary h4 {
            font-size: 11px;
            text-transform: uppercase;
            color: var(--vscode-descriptionForeground);
            margin-bottom: 8px;
            letter-spacing: 0.5px;
        }
        .slo-secondary h4:not(:first-child) { margin-top: 16px; }
    `;
}
