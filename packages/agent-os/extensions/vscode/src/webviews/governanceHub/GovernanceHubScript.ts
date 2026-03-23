// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Governance Hub Script
 *
 * Client-side JavaScript for the Governance Hub webview.
 * Handles tab switching, message passing, and UI interactions.
 */

/**
 * Returns the complete script block for the Governance Hub.
 *
 * @param nonce - CSP nonce for inline script security
 */
export function governanceHubScript(nonce: string): string {
    return `<script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    const STORAGE_KEY = 'governanceHub.activeTab';

    /** Initialize tab state from localStorage or default. */
    function initTabs() {
        const saved = localStorage.getItem(STORAGE_KEY);
        const tabs = document.querySelectorAll('.tab');
        const defaultTab = saved || tabs[0]?.dataset.tab || 'slo';
        activateTab(defaultTab);
    }

    /** Activate a tab by ID and persist to localStorage. */
    function activateTab(tabId) {
        const tabs = document.querySelectorAll('.tab');
        const panels = document.querySelectorAll('.tab-content');

        tabs.forEach(t => t.classList.toggle('active', t.dataset.tab === tabId));
        panels.forEach(p => p.classList.toggle('active', p.id === tabId + '-panel'));

        localStorage.setItem(STORAGE_KEY, tabId);
        vscode.postMessage({ type: 'tabChange', activeTab: tabId });
    }

    /** Bind click handlers to all tab buttons. */
    function bindTabClicks() {
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => activateTab(tab.dataset.tab));
        });
    }

    /** Bind action button handlers. */
    function bindActions() {
        const refreshBtn = document.getElementById('refresh-btn');
        const browserBtn = document.getElementById('browser-btn');
        const exportBtn = document.getElementById('export-btn');

        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                vscode.postMessage({ type: 'refresh' });
            });
        }
        if (browserBtn) {
            browserBtn.addEventListener('click', () => {
                vscode.postMessage({ type: 'openInBrowser' });
            });
        }
        if (exportBtn) {
            exportBtn.addEventListener('click', () => {
                vscode.postMessage({ type: 'export' });
            });
        }
    }

    /** Handle incoming messages from the extension. */
    window.addEventListener('message', event => {
        const msg = event.data;
        if (msg.type === 'sloUpdate') { updateSLOPanel(msg.payload); }
        if (msg.type === 'topologyUpdate') { updateTopologyPanel(msg.payload); }
        if (msg.type === 'auditUpdate') { updateAuditPanel(msg.payload); }
        if (msg.type === 'configUpdate') { applyConfig(msg.payload); }
    });

    function updateSLOPanel(data) {
        const el = document.getElementById('slo-content');
        if (el && data) { el.innerHTML = formatSLOContent(data); }
    }

    function updateTopologyPanel(data) {
        const el = document.getElementById('topology-content');
        if (el && data) { el.innerHTML = formatTopologyContent(data); }
    }

    function updateAuditPanel(data) {
        const el = document.getElementById('audit-content');
        if (el && data) { el.innerHTML = formatAuditContent(data); }
    }

    function applyConfig(config) {
        if (config?.defaultTab) { activateTab(config.defaultTab); }
    }

    function formatSLOContent(d) { return '<div class="slo-panel">SLO data loaded</div>'; }
    function formatTopologyContent(d) { return '<div class="topology-panel">Topology loaded</div>'; }
    function formatAuditContent(d) { return '<div class="audit-panel">Audit loaded</div>'; }

    document.addEventListener('DOMContentLoaded', () => {
        initTabs();
        bindTabClicks();
        bindActions();
    });
    </script>`;
}
