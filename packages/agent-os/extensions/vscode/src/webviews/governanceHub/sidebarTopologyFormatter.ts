// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Sidebar Topology Formatter
 *
 * Returns a JavaScript string containing compact topology formatting
 * functions for injection into the sidebar hub webview.
 */

/** Returns JS source for compact topology builders and composer. */
export function sidebarTopologyFormatterScript(): string {
    return `
    /** Build compact overview metrics for topology. */
    function buildCompactOverview(nodes, bridges) {
        var activeCount = nodes.filter(function(n) { return n.status === 'active'; }).length;
        return '<div class="section-header">Overview</div>' +
            '<div class="metric-compact">' +
                '<span class="label">Total Agents</span>' +
                '<span class="value">' + nodes.length + '</span></div>' +
            '<div class="metric-compact">' +
                '<span class="label">Active</span>' +
                '<span class="value healthy">' + activeCount + '</span></div>' +
            '<div class="metric-compact">' +
                '<span class="label">Bridges</span>' +
                '<span class="value">' + bridges.length + '</span></div>';
    }

    /** Build compact agent list (top 5). */
    function buildCompactAgentList(nodes) {
        var display = nodes.slice(0, 5);
        if (display.length === 0) {
            return '<div class="empty-state">No agents</div>';
        }
        var html = '';
        display.forEach(function(node) {
            var statusClass = node.status === 'active' ? 'active'
                : node.status === 'idle' ? 'idle' : 'offline';
            var tierLabel = (node.trustTier || 'low').substring(0, 3).toUpperCase();
            var name = node.name || node.did || 'Unknown';
            html += '<div class="agent-item">' +
                '<span class="tier-badge">' + tierLabel + '</span>' +
                '<span class="name" title="' + name + '">' + name + '</span>' +
                '<span class="status-indicator ' + statusClass + '"></span>' +
            '</div>';
        });
        if (nodes.length > 5) {
            html += '<div class="empty-state">+' + (nodes.length - 5) + ' more agents</div>';
        }
        return html;
    }

    /** Compose compact topology view from sub-builders. */
    function formatCompactTopology(data) {
        if (!data || !data.nodes || data.nodes.length === 0) {
            return '<div class="empty-state">No agents registered</div>';
        }
        var nodes = data.nodes || [];
        var bridges = data.bridges || [];
        return buildCompactOverview(nodes, bridges) +
            '<div class="section-header">Agents</div>' +
            buildCompactAgentList(nodes);
    }
    `;
}
