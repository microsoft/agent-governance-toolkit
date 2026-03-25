// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Topology Graph Styles
 *
 * Returns a complete <style> block for the force-directed agent topology
 * graph webview. All colors reference VS Code CSS custom properties to
 * integrate seamlessly with any theme (light, dark, high-contrast).
 */

/** Generate the topology graph stylesheet wrapped in a nonced style tag. */
export function topologyStyles(nonce: string): string {
    return `<style nonce="${nonce}">
    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
        background-color: var(--vscode-editor-background);
        color: var(--vscode-foreground);
        font-family: var(--vscode-font-family);
        margin: 0;
        overflow: hidden;
        width: 100vw;
        height: 100vh;
    }

    .graph-container {
        position: relative;
        width: 100vw;
        height: 100vh;
    }

    svg {
        width: 100%;
        height: 100%;
        background: transparent;
        display: block;
    }

    .node {
        cursor: grab;
        transition: transform 0.1s ease;
    }
    .node:active { cursor: grabbing; }
    .node:hover { transform: scale(1.15); }

    .node-trust-high { fill: var(--vscode-charts-green); }
    .node-trust-mid  { fill: var(--vscode-charts-yellow); }
    .node-trust-low  { fill: var(--vscode-charts-red); }

    .node-label {
        font-size: 10px;
        fill: var(--vscode-foreground);
        text-anchor: middle;
        pointer-events: none;
        user-select: none;
    }

    .edge {
        stroke: var(--vscode-editorWidget-border);
        stroke-width: 1.5;
        opacity: 0.6;
    }

    .edge-label {
        font-size: 9px;
        fill: var(--vscode-descriptionForeground);
        text-anchor: middle;
        pointer-events: none;
    }

    .bridge-badge rect {
        fill: var(--vscode-badge-background);
        stroke: var(--vscode-badge-foreground);
        stroke-width: 0.5;
        rx: 4;
        ry: 4;
    }
    .bridge-badge text {
        font-size: 8px;
        fill: var(--vscode-badge-foreground);
        text-anchor: middle;
        dominant-baseline: central;
    }

    .tooltip {
        position: absolute;
        display: none;
        background: var(--vscode-editorWidget-background);
        border: 1px solid var(--vscode-editorWidget-border);
        border-radius: 6px;
        padding: 10px 14px;
        z-index: 100;
        max-width: 280px;
        font-size: 12px;
        color: var(--vscode-foreground);
        line-height: 1.5;
        pointer-events: none;
        box-shadow: 0 2px 8px var(--vscode-widget-shadow);
    }
    .tooltip strong {
        display: block;
        margin-bottom: 4px;
        color: var(--vscode-foreground);
    }
    .tooltip .detail {
        color: var(--vscode-descriptionForeground);
    }

    .legend {
        position: fixed;
        bottom: 12px;
        right: 12px;
        background: var(--vscode-sideBar-background);
        border: 1px solid var(--vscode-panel-border);
        padding: 10px 14px;
        border-radius: 6px;
        font-size: 11px;
        line-height: 1.8;
        color: var(--vscode-foreground);
    }
    .legend-item {
        display: flex;
        align-items: center;
        gap: 6px;
    }
    .legend-dot {
        width: 10px;
        height: 10px;
        border-radius: 50%;
        display: inline-block;
        flex-shrink: 0;
    }

    .controls {
        position: fixed;
        top: 12px;
        right: 12px;
        display: flex;
        flex-direction: column;
        gap: 4px;
    }
    .controls button {
        width: 28px;
        height: 28px;
        display: flex;
        align-items: center;
        justify-content: center;
        background: var(--vscode-button-secondaryBackground);
        color: var(--vscode-button-secondaryForeground);
        border: 1px solid var(--vscode-button-border, transparent);
        border-radius: 4px;
        cursor: pointer;
        font-size: 14px;
        padding: 0;
    }
    .controls button:hover {
        background: var(--vscode-button-secondaryHoverBackground);
    }

    .stats-bar {
        position: fixed;
        bottom: 12px;
        left: 12px;
        font-size: 11px;
        color: var(--vscode-descriptionForeground);
        background: var(--vscode-sideBar-background);
        border: 1px solid var(--vscode-panel-border);
        padding: 6px 12px;
        border-radius: 6px;
    }
    </style>`;
}
