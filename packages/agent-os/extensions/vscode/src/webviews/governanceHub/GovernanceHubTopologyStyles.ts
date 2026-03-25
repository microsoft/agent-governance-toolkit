// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Governance Hub Topology Styles
 *
 * CSS for agent nodes, bridges, delegation edges, and topology drill-down.
 */

/** Returns topology panel CSS including agent rows and trust tiers. */
export function topologyStyles(): string {
    return `
        /* Topology Panel Styles */
        .topology-panel { height: 100%; position: relative; }

        .topology-svg {
            width: 100%;
            height: 100%;
            background: var(--vscode-editor-background);
        }

        .agent-node { cursor: pointer; }
        .agent-node circle { stroke-width: 2; transition: r 0.2s; }
        .agent-node:hover circle { stroke-width: 3; }
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

        /* Agent Topology Drill-Down Styles */
        .agents-list { display: flex; flex-direction: column; gap: 4px; padding: 16px; }
        .agent-row {
            display: flex; align-items: center; gap: 12px;
            padding: 8px 12px;
            background: var(--vscode-input-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 4px;
            cursor: pointer;
            transition: background 0.2s;
        }
        .agent-row:hover { background: var(--vscode-list-hoverBackground); }
        .agent-trust {
            font-weight: 600; min-width: 40px; text-align: center;
            padding: 2px 6px; border-radius: 4px; font-size: 11px;
        }
        .trust-high { background: rgba(76, 175, 80, 0.2); color: var(--vscode-charts-green); }
        .trust-medium { background: rgba(255, 193, 7, 0.2); color: var(--vscode-charts-yellow); }
        .trust-low { background: rgba(244, 67, 54, 0.2); color: var(--vscode-charts-red); }
        .agent-did { flex: 1; font-family: monospace; font-size: 11px; }
        .agent-ring { font-size: 10px; color: var(--vscode-descriptionForeground); }
    `;
}
