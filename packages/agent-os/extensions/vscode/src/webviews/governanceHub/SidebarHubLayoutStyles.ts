// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Sidebar Hub Layout Styles
 *
 * CSS for sidebar layout, header, icon tabs, footer, and variables.
 */

/** Returns sidebar layout CSS including header, tabs, and footer. */
export function sidebarLayoutStyles(): string {
    return `
:root {
    --hub-spacing-xs: 4px;
    --hub-spacing-sm: 8px;
    --hub-spacing-md: 12px;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
    font-family: var(--vscode-font-family);
    font-size: var(--vscode-font-size);
    color: var(--vscode-foreground);
    background: var(--vscode-sideBar-background);
}

/* Compact Header */
.compact-header {
    display: flex;
    align-items: center;
    gap: var(--hub-spacing-sm);
    padding: var(--hub-spacing-sm) var(--hub-spacing-md);
    border-bottom: 1px solid var(--vscode-panel-border);
}

.compact-header .status-dot {
    width: 8px; height: 8px; border-radius: 50%;
    background: var(--vscode-charts-green);
}

.compact-header .title {
    flex: 1; font-weight: 600; font-size: 11px;
    text-transform: uppercase; letter-spacing: 0.5px;
}

.compact-header button {
    background: transparent; border: none; cursor: pointer;
    color: var(--vscode-foreground); opacity: 0.7;
    font-size: 14px; padding: 2px 4px;
}

.compact-header button:hover {
    opacity: 1; background: var(--vscode-toolbar-hoverBackground);
}

/* Icon Tabs */
.icon-tabs {
    display: flex;
    border-bottom: 1px solid var(--vscode-panel-border);
}

.icon-tabs .tab {
    flex: 1; padding: var(--hub-spacing-sm); text-align: center;
    background: transparent; border: none;
    border-bottom: 2px solid transparent;
    cursor: pointer; font-size: 16px; opacity: 0.5;
    transition: opacity 0.15s, border-color 0.15s;
}

.icon-tabs .tab:hover {
    opacity: 0.8; background: var(--vscode-list-hoverBackground);
}

.icon-tabs .tab.active {
    opacity: 1; border-bottom-color: var(--vscode-focusBorder);
}

/* Main Content */
#content {
    padding: var(--hub-spacing-md);
    overflow-y: auto;
    max-height: calc(100vh - 120px);
}

/* Empty State */
.empty-state {
    text-align: center;
    padding: var(--hub-spacing-md);
    color: var(--vscode-descriptionForeground);
    font-size: 11px;
}

/* Compact Footer */
.compact-footer {
    display: flex; align-items: center; justify-content: space-between;
    padding: var(--hub-spacing-sm) var(--hub-spacing-md);
    border-top: 1px solid var(--vscode-panel-border);
    font-size: 10px; color: var(--vscode-descriptionForeground);
}

.compact-footer button {
    background: transparent; border: none; cursor: pointer;
    color: var(--vscode-foreground); opacity: 0.7;
    font-size: 14px; padding: 2px 4px;
}

.compact-footer button:hover {
    opacity: 1; background: var(--vscode-toolbar-hoverBackground);
}
    `;
}
