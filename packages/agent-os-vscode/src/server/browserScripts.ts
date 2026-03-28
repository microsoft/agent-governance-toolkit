// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Browser Dashboard Scripts
 *
 * Client-side JavaScript for WebSocket connection, routing, and D3.js topology.
 */

/** Build the WebSocket client script. */
export function buildClientScript(wsPort: number, sessionToken: string): string {
    return `
    /** Escape HTML entities to prevent XSS (string-based, no DOM allocation). */
    function esc(s) {
        return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
    }

    let ws;
    let reconnectTimer;
    const statusDot = document.getElementById('status-dot');

    function connect() {
        // Intentionally ws:// (not wss://): server binds to 127.0.0.1 only, TLS unnecessary for loopback
        ws = new WebSocket('ws://127.0.0.1:${wsPort}?token=${sessionToken}');
        ws.onopen = () => { statusDot.classList.remove('disconnected'); };
        ws.onclose = () => { statusDot.classList.add('disconnected'); scheduleReconnect(); };
        ws.onerror = () => { ws.close(); };
        ws.onmessage = (event) => { handleMessage(JSON.parse(event.data)); };
    }

    function scheduleReconnect() {
        if (reconnectTimer) { clearTimeout(reconnectTimer); }
        reconnectTimer = setTimeout(connect, 3000);
    }

    function handleMessage(msg) {
        if (msg.type === 'sloUpdate') { updateSLO(msg.data); }
        else if (msg.type === 'topologyUpdate') { updateTopology(msg.data); }
        else if (msg.type === 'auditUpdate') { updateAudit(msg.data); }
    }

    function updateStaleness(fetchedAt) {
        var el = document.getElementById('staleness-badge');
        if (!el) { return; }
        if (!fetchedAt) { el.textContent = ''; return; }
        var ageSec = Math.round((Date.now() - new Date(fetchedAt).getTime()) / 1000);
        if (isNaN(ageSec) || ageSec < 0 || ageSec < 10) { el.textContent = ''; return; }
        el.textContent = ageSec < 60 ? ageSec + 's ago' : Math.round(ageSec / 60) + 'm ago';
        el.style.color = ageSec > 30 ? '#cca700' : '';
    }

    function updateSLO(snapshot) {
        if (!snapshot) { return; }
        setMetric('avail-val', snapshot.availability?.currentPercent, '%');
        setMetric('latency-val', snapshot.latency?.p99Ms, 'ms');
        setMetric('compliance-val', snapshot.policyCompliance?.compliancePercent, '%');
        setMetric('trust-val', snapshot.trustScore?.meanScore, '');
        updateStaleness(snapshot.fetchedAt);
    }

    function setMetric(id, value, suffix) {
        const el = document.getElementById(id);
        if (el && value !== undefined) { el.textContent = value.toFixed(1) + suffix; }
    }

    function updateTopology(data) {
        if (!data || !window.renderTopologyGraph) { return; }
        window.renderTopologyGraph(data.agents || [], data.delegations || []);
    }

    function updateAudit(entries) {
        const list = document.getElementById('audit-list');
        if (!list || !Array.isArray(entries)) { return; }
        list.innerHTML = entries.slice(0, 50).map(e => buildAuditItem(e)).join('');
    }

    function buildAuditItem(entry) {
        const time = new Date(entry.timestamp).toLocaleTimeString();
        const cls = entry.type === 'blocked' ? 'health-breach' : 'health-ok';
        return '<div class="audit-item"><span class="audit-type ' + cls + '">' +
            esc(entry.type) + '</span><span class="audit-time">' + esc(time) +
            '</span><span>' + esc(entry.reason || entry.violation || '-') + '</span></div>';
    }

    function handleRoute() {
        const hash = window.location.hash.slice(1) || 'slo';
        document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        const tab = document.getElementById('tab-' + hash);
        const nav = document.querySelector('[data-tab="' + hash + '"]');
        if (tab) { tab.classList.add('active'); }
        if (nav) { nav.classList.add('active'); }
    }

    window.addEventListener('hashchange', handleRoute);
    document.addEventListener('DOMContentLoaded', () => { handleRoute(); connect(); });

    document.getElementById('toggle-sidebar')?.addEventListener('click', () => {
        document.querySelector('.sidebar').classList.toggle('collapsed');
    });

    var helpToggle = document.getElementById('help-toggle');
    var helpPanel = document.getElementById('help-panel');
    var helpClose = document.getElementById('help-close');
    var helpSearch = document.getElementById('help-search');

    if (helpToggle) {
        helpToggle.addEventListener('click', function() {
            if (!helpPanel) { return; }
            var isOpen = helpPanel.classList.toggle('visible');
            helpToggle.setAttribute('aria-expanded', String(isOpen));
            if (isOpen && helpSearch) { helpSearch.focus(); }
        });
    }
    if (helpClose) {
        helpClose.addEventListener('click', function() {
            if (!helpPanel) { return; }
            helpPanel.classList.remove('visible');
            if (helpToggle) { helpToggle.setAttribute('aria-expanded', 'false'); helpToggle.focus(); }
        });
    }
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && helpPanel && helpPanel.classList.contains('visible')) {
            helpPanel.classList.remove('visible');
            if (helpToggle) { helpToggle.setAttribute('aria-expanded', 'false'); helpToggle.focus(); }
        }
    });
    if (helpSearch) {
        helpSearch.addEventListener('input', function(e) {
            var q = e.target.value.toLowerCase();
            var sections = helpPanel ? helpPanel.querySelectorAll('section') : [];
            sections.forEach(function(s) {
                s.style.display = (s.textContent || '').toLowerCase().indexOf(q) !== -1 ? '' : 'none';
            });
        });
    }`;
}

/** Build static help content as HTML sections for the browser dashboard. */
export function buildHelpContent(): string {
    return `
<section data-help="overview"><h2>Overview</h2>
<p>Agent OS provides kernel-level safety for AI coding assistants. It intercepts tool calls, enforces policies, and produces tamper-proof audit trails.</p></section>
<section data-help="slo"><h2>SLO Dashboard</h2>
<p><strong>Availability</strong>: Percentage of successful governance evaluations in the current window.</p>
<p><strong>Latency P99</strong>: 99th-percentile response time for policy evaluation calls.</p>
<p><strong>Burn Rate</strong>: Ratio of actual error consumption to budgeted rate. Values above 1.0 indicate the budget is depleting faster than planned.</p>
<p><strong>Error Budgets</strong>: Remaining tolerance for failures before the SLO is breached.</p>
<p><strong>Trust Distribution</strong>: Histogram of agent trust scores across four buckets (0-250, 251-500, 501-750, 751-1000).</p></section>
<section data-help="topology"><h2>Agent Topology</h2>
<p><strong>Agents</strong>: Registered AI agents identified by DID (Decentralized Identifier).</p>
<p><strong>Bridges</strong>: Protocol connectors (A2A, MCP, IATP) linking agents across trust boundaries.</p>
<p><strong>Trust Score</strong>: Mean trust across all agents (0-1000 scale).</p></section>
<section data-help="audit"><h2>Audit Log</h2>
<p>Chronological record of governance decisions. Filter by severity (info, warning, critical) or search by action, DID, or file path.</p></section>
<section data-help="policy"><h2>Active Policies</h2>
<p><strong>DENY</strong>: Rejects the tool call and returns an error to the agent.</p>
<p><strong>BLOCK</strong>: Silently prevents execution without notifying the agent.</p>
<p><strong>AUDIT</strong>: Allows execution but logs a compliance event.</p>
<p><strong>ALLOW</strong>: Permits execution with no additional overhead.</p></section>
<section data-help="glossary"><h2>Glossary</h2>
<table><tr><th>Term</th><th>Definition</th></tr>
<tr><td>SLO</td><td>Service Level Objective - a target reliability metric</td></tr>
<tr><td>SLI</td><td>Service Level Indicator - measured value tracking an SLO</td></tr>
<tr><td>DID</td><td>Decentralized Identifier for agent identity</td></tr>
<tr><td>Burn Rate</td><td>Speed at which error budget is consumed</td></tr>
<tr><td>Trust Score</td><td>0-1000 composite reliability rating</td></tr></table></section>
<section data-help="troubleshooting"><h2>Troubleshooting</h2>
<table><tr><th>Symptom</th><th>Fix</th></tr>
<tr><td>Dashboard shows no data</td><td>Check that the governance backend is running and agentOS.governance settings are configured.</td></tr>
<tr><td>WebSocket disconnected</td><td>Verify the server is running on the expected port. The client auto-reconnects every 3 seconds.</td></tr>
<tr><td>Stale data warning</td><td>Increase agentOS.governance.refreshIntervalMs or check backend health.</td></tr></table></section>
<section data-help="security"><h2>Security Design Decisions</h2>
<table><tr><th>Decision</th><th>Rationale</th></tr>
<tr><td>CSP nonce-gated scripts</td><td>Prevents injection of unauthorized scripts into webviews.</td></tr>
<tr><td>Session token on WebSocket</td><td>Authenticates browser clients to the local governance server.</td></tr>
<tr><td>Loopback-only binding</td><td>Server binds to 127.0.0.1, not exposed to network.</td></tr></table></section>`;
}

/** Build the D3.js topology graph script. */
export function buildTopologyScript(): string {
    return `
    window.renderTopologyGraph = function(agents, delegations) {
        const svg = d3.select('#topology-svg');
        svg.selectAll('*').remove();
        const width = svg.node().parentElement.clientWidth;
        const height = 500;
        svg.attr('viewBox', [0, 0, width, height]);

        const nodes = agents.map(a => ({ id: a.did, trustScore: a.trustScore, ...a }));
        const links = delegations.map(d => ({
            source: d.fromDid,
            target: d.toDid,
            capability: d.capability
        }));

        const simulation = d3.forceSimulation(nodes)
            .force('link', d3.forceLink(links).id(d => d.id).distance(100))
            .force('charge', d3.forceManyBody().strength(-200))
            .force('center', d3.forceCenter(width / 2, height / 2));

        const link = svg.append('g').selectAll('line').data(links).join('line')
            .attr('class', 'link');
        const node = svg.append('g').selectAll('g').data(nodes).join('g')
            .attr('class', 'node');
        node.append('circle').attr('r', 20).attr('fill', d => trustColor(d.trustScore));
        node.append('text').attr('class', 'node-label').attr('dy', 30)
            .attr('text-anchor', 'middle').text(d => d.did.slice(-8));

        simulation.on('tick', () => {
            link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
            node.attr('transform', d => 'translate(' + d.x + ',' + d.y + ')');
        });
    };

    function trustColor(score) {
        if (score > 700) { return '#4ec9b0'; }
        if (score >= 400) { return '#dcdcaa'; }
        return '#f14c4c';
    }`;
}
