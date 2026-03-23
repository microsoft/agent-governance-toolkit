// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Governance Hub Template
 *
 * Generates the complete HTML document for the Governance Hub webview.
 * Composes styles from GovernanceHubStyles and script from GovernanceHubScript.
 */

import { governanceHubStyles } from './GovernanceHubStyles';
import { governanceHubScript } from './GovernanceHubScript';
import { HubConfig, HubTabId } from './governanceHubTypes';

/** Tab display labels. */
const TAB_LABELS: Record<HubTabId, string> = {
    slo: 'SLO Dashboard',
    topology: 'Agent Topology',
    audit: 'Audit Log',
    policies: 'Policies',
};

/** Build header with status indicator and action buttons. */
function renderHeader(): string {
    return `
    <header class="hub-header">
        <div class="hub-title">
            <span class="status-indicator"></span>
            <span>Governance Hub</span>
        </div>
        <div class="hub-actions">
            <button id="refresh-btn" title="Refresh all data">Refresh</button>
            <button id="browser-btn" title="Open in browser">Open</button>
            <button id="export-btn" title="Export report">Export</button>
        </div>
    </header>`;
}

/** Build tab bar from enabled tabs. */
function renderTabBar(enabledTabs: HubTabId[]): string {
    const tabs = enabledTabs.map(tabId => {
        const label = TAB_LABELS[tabId];
        return `<button class="tab" data-tab="${tabId}">${label}</button>`;
    });
    return `<nav class="tab-bar">${tabs.join('')}</nav>`;
}

/** Build content panels for each tab. */
function renderContentPanels(enabledTabs: HubTabId[]): string {
    return enabledTabs.map(tabId => renderPanel(tabId)).join('');
}

/** Build a single content panel. */
function renderPanel(tabId: HubTabId): string {
    return `
    <section id="${tabId}-panel" class="tab-content">
        <div id="${tabId}-content" class="${tabId}-panel">
            ${renderEmptyState(tabId)}
        </div>
    </section>`;
}

/** Build empty state placeholder for a panel. */
function renderEmptyState(tabId: HubTabId): string {
    const messages: Record<HubTabId, string> = {
        slo: 'Loading SLO metrics...',
        topology: 'Loading agent topology...',
        audit: 'Loading audit events...',
        policies: 'Loading policy status...',
    };
    return `
    <div class="empty-state">
        <div class="icon">&#8987;</div>
        <p>${messages[tabId]}</p>
    </div>`;
}

/** Build footer with connection status and timestamp. */
function renderFooter(): string {
    return `
    <footer class="hub-footer">
        <div class="connection-status">
            <span class="connection-dot"></span>
            <span>Connected</span>
        </div>
        <span id="last-updated">Last updated: --</span>
    </footer>`;
}

/**
 * Returns the complete HTML document for the Governance Hub webview.
 *
 * @param nonce - Cryptographic nonce for CSP
 * @param cspSource - Webview CSP source string
 * @param config - Hub configuration with enabled tabs
 */
export function renderGovernanceHub(
    nonce: string,
    cspSource: string,
    config: HubConfig
): string {
    const tabs = config.enabledTabs;

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src ${cspSource} 'nonce-${nonce}'; script-src 'nonce-${nonce}';">
    <title>Governance Hub</title>
    ${governanceHubStyles(nonce)}
</head>
<body>
    ${renderHeader()}
    ${renderTabBar(tabs)}
    <main class="hub-main">
        ${renderContentPanels(tabs)}
    </main>
    ${renderFooter()}
    ${governanceHubScript(nonce)}
</body>
</html>`;
}
