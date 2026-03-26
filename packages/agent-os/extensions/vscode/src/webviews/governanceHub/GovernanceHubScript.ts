// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Governance Hub Script
 *
 * Client-side JavaScript for the Governance Hub webview.
 * Composes formatter modules and provides tab switching,
 * message passing, and UI initialization.
 */

import { hubSLOFormatterScript } from './hubSLOFormatter';
import { hubTopologyFormatterScript } from './hubTopologyFormatter';
import { hubAuditFormatterScript, hubPolicyFormatterScript } from './hubAuditFormatter';

/**
 * Returns the complete script block for the Governance Hub.
 *
 * @param nonce - CSP nonce for inline script security
 */
export function governanceHubScript(nonce: string): string {
    return `<script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    const STORAGE_KEY = 'governanceHub.activeTab';
    let auditData = [];

    /** Escape HTML entities to prevent XSS. */
    function esc(s) {
        var d = document.createElement('div');
        d.textContent = String(s);
        return d.innerHTML;
    }

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
        var refreshBtn = document.getElementById('refresh-btn');
        var browserBtn = document.getElementById('browser-btn');
        var exportBtn = document.getElementById('export-btn');
        if (refreshBtn) { refreshBtn.addEventListener('click', function() { vscode.postMessage({ type: 'refresh' }); }); }
        if (browserBtn) { browserBtn.addEventListener('click', function() { vscode.postMessage({ type: 'openInBrowser' }); }); }
        if (exportBtn) { exportBtn.addEventListener('click', function() { vscode.postMessage({ type: 'export' }); }); }
    }

    /** Format staleness as a human-readable string. Uses textContent, never innerHTML. */
    function formatStaleness(fetchedAt) {
        if (!fetchedAt) { return ''; }
        var ageMs = Date.now() - new Date(fetchedAt).getTime();
        if (isNaN(ageMs) || ageMs < 0) { return ''; }
        var ageSec = Math.round(ageMs / 1000);
        if (ageSec < 10) { return ''; }
        if (ageSec < 60) { return 'Last updated: ' + ageSec + 's ago'; }
        return 'Last updated: ' + Math.round(ageSec / 60) + 'm ago';
    }

    function updateStalenessIndicator(fetchedAt) {
        var el = document.getElementById('staleness-indicator');
        if (!el) { return; }
        var text = formatStaleness(fetchedAt);
        el.textContent = text;
        var ageSec = fetchedAt ? Math.round((Date.now() - new Date(fetchedAt).getTime()) / 1000) : 0;
        el.className = 'staleness' + (ageSec > 60 ? ' stale-error' : ageSec > 30 ? ' stale-warning' : '');
    }

    /** Handle incoming messages from the extension. */
    window.addEventListener('message', function(event) {
        var msg = event.data;
        if (msg.type === 'sloUpdate') { updateSLOPanel(msg.payload); updateStalenessIndicator(msg.payload && msg.payload.fetchedAt); }
        if (msg.type === 'topologyUpdate') { updateTopologyPanel(msg.payload); }
        if (msg.type === 'auditUpdate') { updateAuditPanel(msg.payload); }
        if (msg.type === 'policyUpdate') { updatePoliciesPanel(msg.payload); updateStalenessIndicator(msg.payload && msg.payload.fetchedAt); }
        if (msg.type === 'configUpdate') { applyConfig(msg.payload); }
    });

    function updateSLOPanel(data) {
        var el = document.getElementById('slo-content');
        if (el && data) { el.innerHTML = formatSLOContent(data); }
    }
    function updateTopologyPanel(data) {
        var el = document.getElementById('topology-content');
        if (el && data) { el.innerHTML = formatTopologyContent(data); }
    }
    function updateAuditPanel(data) {
        var el = document.getElementById('audit-content');
        if (el && data) { el.innerHTML = formatAuditContent(data); }
    }
    function updatePoliciesPanel(data) {
        var el = document.getElementById('policies-content');
        if (el && data) { el.innerHTML = formatPoliciesContent(data); }
    }
    function applyConfig(config) {
        if (config && config.defaultTab) { activateTab(config.defaultTab); }
    }

    ${hubSLOFormatterScript()}
    ${hubTopologyFormatterScript()}
    ${hubAuditFormatterScript()}
    ${hubPolicyFormatterScript()}

    (function init() {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', init);
            return;
        }
        initTabs();
        bindTabClicks();
        bindActions();
    })();
    </script>`;
}
