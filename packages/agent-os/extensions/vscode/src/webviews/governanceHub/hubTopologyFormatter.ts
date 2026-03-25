// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Hub Topology Formatter
 *
 * Returns a JavaScript string containing topology formatting functions
 * for injection into the Governance Hub webview.
 */

/** Returns JS source for topology builders and composer. */
export function hubTopologyFormatterScript(): string {
    return `
    /** Build a list of clickable agent rows. */
    function buildAgentList(nodes) {
        return nodes.map(function(a) {
            var tierClass = getTrustTier(a.trustScore);
            return '<div class="agent-row" data-agent-did="' + esc(a.did) + '">' +
                '<span class="agent-trust trust-' + tierClass + '">' + esc(a.trustScore) + '</span>' +
                '<span class="agent-did">' + esc(truncateDid(a.did)) + '</span>' +
                '<span class="agent-ring">Ring ' + esc(a.ring) + '</span>' +
            '</div>';
        }).join('');
    }

    /** Attach delegated click handler for agent rows. */
    function attachAgentClickHandler() {
        setTimeout(function() {
            var list = document.getElementById('agents-list');
            if (list) {
                list.addEventListener('click', function(ev) {
                    var row = ev.target.closest('.agent-row');
                    if (row && row.dataset.agentDid) {
                        selectAgent(row.dataset.agentDid);
                    }
                });
            }
        }, 0);
    }

    /** Post agent selection to extension. */
    function selectAgent(did) {
        vscode.postMessage({ type: 'agentSelected', did: did });
    }

    /** Get trust tier for styling. */
    function getTrustTier(score) {
        if (score > 700) return 'high';
        if (score >= 400) return 'medium';
        return 'low';
    }

    /** Truncate long DIDs for display. */
    function truncateDid(did) {
        return did.length > 24 ? did.slice(0, 24) + '...' : did;
    }

    /** Render topology with clickable agent rows. */
    function formatTopologyContent(data) {
        if (!data || !data.nodes) {
            return '<div class="empty-state">No topology data</div>';
        }
        var agentsHtml = buildAgentList(data.nodes);
        var html = '<div class="topology-panel">' +
            '<h3>Agents (' + data.nodes.length + ')</h3>' +
            '<div class="agents-list" id="agents-list">' + agentsHtml + '</div>' +
        '</div>';
        attachAgentClickHandler();
        return html;
    }
    `;
}
