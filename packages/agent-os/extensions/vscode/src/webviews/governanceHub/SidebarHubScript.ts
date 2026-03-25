// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Sidebar Hub Script
 *
 * Compact JavaScript for the sidebar-embedded Governance Hub view.
 * Composes formatter modules and provides tab switching and messaging.
 */

import { sidebarSLOFormatterScript } from './sidebarSLOFormatter';
import { sidebarTopologyFormatterScript } from './sidebarTopologyFormatter';

/**
 * Returns the complete script block for the sidebar hub.
 *
 * @param nonce - CSP nonce for inline script security
 */
export function sidebarHubScript(nonce: string): string {
    return `<script nonce="${nonce}">
(function() {
    const vscode = acquireVsCodeApi();

    let currentTab = 'slo';
    let sloData = null;
    let topologyData = null;
    let auditData = [];

    (function init() {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', init);
            return;
        }
        bindTabClicks();
        bindActions();
        activateTab('slo');
    })();

    function bindTabClicks() {
        document.querySelectorAll('.icon-tabs .tab').forEach(function(tab) {
            tab.addEventListener('click', function() {
                var tabId = tab.getAttribute('data-tab');
                if (tabId) activateTab(tabId);
            });
        });
    }

    function bindActions() {
        var refreshBtn = document.getElementById('refresh-btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', function() {
                vscode.postMessage({ type: 'refresh' });
            });
        }
        var expandBtn = document.getElementById('expand-btn');
        if (expandBtn) {
            expandBtn.addEventListener('click', function() {
                vscode.postMessage({ type: 'openFullDashboard' });
            });
        }
    }

    function activateTab(tabId) {
        currentTab = tabId;
        document.querySelectorAll('.icon-tabs .tab').forEach(function(tab) {
            tab.classList.toggle('active', tab.getAttribute('data-tab') === tabId);
        });
        renderContent();
    }

    function renderContent() {
        var content = document.getElementById('content');
        if (!content) return;
        switch (currentTab) {
            case 'slo': content.innerHTML = formatCompactSLO(sloData); break;
            case 'topology': content.innerHTML = formatCompactTopology(topologyData); break;
            case 'audit': content.innerHTML = formatCompactAudit(auditData); break;
            default: content.innerHTML = '';
        }
    }

    function getHealthStatus(current, target) {
        if (typeof current !== 'number') return '';
        if (typeof target !== 'number') target = 0.999;
        if (current >= target) return 'healthy';
        if (current >= target * 0.99) return 'warning';
        return 'critical';
    }

    function updateLastUpdated() {
        var el = document.getElementById('last-updated');
        if (el) { el.textContent = new Date().toLocaleTimeString(); }
    }

    function formatCompactAudit(entries) {
        if (!entries || entries.length === 0) {
            return '<div class="empty-state">No audit entries</div>';
        }
        var recent = entries.slice(-5).reverse();
        var html = '<div class="section-header">Recent Activity</div>';
        recent.forEach(function(entry) {
            var timestamp = entry.timestamp
                ? new Date(entry.timestamp).toLocaleTimeString() : '--';
            var typeClass = entry.type === 'violation' ? 'violation'
                : entry.type === 'warning' ? 'warning' : 'info';
            var typeLabel = entry.type || 'event';
            var file = entry.file || '';
            html += '<div class="audit-entry">' +
                '<span class="timestamp">' + timestamp + '</span>' +
                '<span class="type-badge ' + typeClass + '">' + typeLabel + '</span>' +
                (file ? '<div class="file" title="' + file + '">' + file + '</div>' : '') +
            '</div>';
        });
        if (entries.length > 5) {
            html += '<div class="empty-state">' + (entries.length - 5) + ' older entries</div>';
        }
        return html;
    }

    ${sidebarSLOFormatterScript()}
    ${sidebarTopologyFormatterScript()}

    window.addEventListener('message', function(event) {
        var message = event.data;
        switch (message.type) {
            case 'sloUpdate':
                sloData = message.payload;
                if (currentTab === 'slo') renderContent();
                updateLastUpdated();
                break;
            case 'topologyUpdate':
                topologyData = message.payload;
                if (currentTab === 'topology') renderContent();
                updateLastUpdated();
                break;
            case 'auditUpdate':
                auditData = message.payload || [];
                if (currentTab === 'audit') renderContent();
                updateLastUpdated();
                break;
            case 'configUpdate':
                if (message.payload && message.payload.lastUpdated) {
                    var el = document.getElementById('last-updated');
                    if (el) el.textContent = message.payload.lastUpdated;
                }
                break;
        }
    });
})();
</script>`;
}
