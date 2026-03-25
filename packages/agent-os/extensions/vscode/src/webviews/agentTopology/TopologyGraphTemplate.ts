// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Topology Graph Template
 *
 * Composes the full HTML document for the agent topology graph webview.
 * Combines the style sheet, SVG container, interactive controls, trust
 * legend, statistics bar, and force-simulation script into a single
 * Content-Security-Policy-compliant page.
 */

import { topologyStyles } from './TopologyGraphStyles';
import { topologyScript } from './TopologyGraphScript';

/**
 * Build the CSP meta tag content for the webview.
 *
 * @param nonce     - Unique nonce for inline style/script blocks.
 * @param cspSource - The webview CSP source URI scheme.
 * @returns The full content attribute value.
 */
function buildCsp(nonce: string, cspSource: string): string {
    return [
        `default-src 'none'`,
        `style-src ${cspSource} 'nonce-${nonce}'`,
        `script-src 'nonce-${nonce}'`,
        `img-src ${cspSource}`,
    ].join('; ');
}

/**
 * Render the trust-tier legend HTML.
 *
 * Shows the three trust color bands and edge/delegation meanings so users
 * can interpret the graph at a glance.
 */
function renderLegend(): string {
    return `<div class="legend">
        <div style="font-weight:bold; margin-bottom:6px;">Trust Tiers</div>
        <div class="legend-item">
            <span class="legend-dot"
                  style="background:var(--vscode-charts-green);"></span>
            High (&gt;700)
        </div>
        <div class="legend-item">
            <span class="legend-dot"
                  style="background:var(--vscode-charts-yellow);"></span>
            Medium (400-700)
        </div>
        <div class="legend-item">
            <span class="legend-dot"
                  style="background:var(--vscode-charts-red);"></span>
            Low (&lt;400)
        </div>
        <div style="margin-top:6px; font-weight:bold; margin-bottom:4px;">
            Edges
        </div>
        <div class="legend-item">
            <svg width="20" height="10">
                <line x1="0" y1="5" x2="20" y2="5"
                      stroke="var(--vscode-editorWidget-border)"
                      stroke-width="1.5" opacity="0.6"/>
            </svg>
            Delegation
        </div>
    </div>`;
}

/**
 * Render the zoom / reset control buttons.
 */
function renderControls(): string {
    return `<div class="controls">
        <button id="zoom-in" title="Zoom In">+</button>
        <button id="zoom-out" title="Zoom Out">&minus;</button>
        <button id="reset" title="Reset Layout">&#8634;</button>
    </div>`;
}

/**
 * Render the complete HTML page for the agent topology graph webview.
 *
 * @param nonce     - Unique nonce to satisfy CSP for inline style/script.
 * @param cspSource - The webview CSP source URI scheme.
 * @returns A full HTML document string.
 */
export function renderTopologyGraph(
    nonce: string,
    cspSource: string,
): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy"
          content="${buildCsp(nonce, cspSource)}">
    ${topologyStyles(nonce)}
</head>
<body>
    <div class="graph-container">
        <svg id="topology-svg"></svg>
        <div class="tooltip" id="tooltip" style="display:none;"></div>
    </div>

    ${renderControls()}

    ${renderLegend()}

    <div class="stats-bar" id="stats-bar">
        Agents: 0 | Mean Trust: 0 | Bridges: 0/0
    </div>

    ${topologyScript(nonce)}
</body>
</html>`;
}
