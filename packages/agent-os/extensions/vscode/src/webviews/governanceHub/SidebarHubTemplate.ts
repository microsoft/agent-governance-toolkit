// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Sidebar Hub Template
 *
 * Compact HTML template for the sidebar-embedded Governance Hub view.
 * Uses icon-based tabs optimized for narrow viewports.
 */

import { sidebarHubStyles } from './SidebarHubStyles';
import { sidebarHubScript } from './SidebarHubScript';
import { HubConfig, HubTabId } from './governanceHubTypes';

/** Icon mappings for each tab (HTML entities). */
const TAB_ICONS: Record<HubTabId, string> = {
    slo: '&#x1F4CA;',       // 📊 chart
    topology: '&#x1F517;',  // 🔗 link
    audit: '&#x1F4DD;',     // 📝 memo
    policies: '&#x2699;',   // ⚙ gear
};

/** Tab labels for title/tooltip. */
const TAB_LABELS: Record<HubTabId, string> = {
    slo: 'SLO Dashboard',
    topology: 'Agent Topology',
    audit: 'Audit Log',
    policies: 'Policies',
};

/**
 * Render icon-based tab buttons.
 */
function renderIconTabs(tabs: HubTabId[], defaultTab: HubTabId): string {
    return tabs.map(id => {
        const activeClass = id === defaultTab ? ' active' : '';
        return `<button class="tab${activeClass}" data-tab="${id}" title="${TAB_LABELS[id]}">${TAB_ICONS[id]}</button>`;
    }).join('');
}

/**
 * Render the complete sidebar hub HTML.
 */
export function renderSidebarHub(nonce: string, cspSource: string, config: HubConfig): string {
    const defaultTab = config.defaultTab || 'slo';
    const enabledTabs = config.enabledTabs || ['slo', 'topology', 'audit'];

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src ${cspSource} 'nonce-${nonce}'; script-src 'nonce-${nonce}';">
    ${sidebarHubStyles(nonce)}
</head>
<body>
    <header class="compact-header">
        <span class="status-dot"></span>
        <span class="title">Governance</span>
        <button id="refresh-btn" title="Refresh">&#x21BB;</button>
    </header>
    <nav class="icon-tabs">${renderIconTabs(enabledTabs, defaultTab)}</nav>
    <main id="content"></main>
    <footer class="compact-footer">
        <span id="last-updated">--</span>
        <button id="expand-btn" title="Open Full Dashboard">&#x2197;</button>
    </footer>
    ${sidebarHubScript(nonce)}
</body>
</html>`;
}
