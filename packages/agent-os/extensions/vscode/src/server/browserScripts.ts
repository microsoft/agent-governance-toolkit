// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Browser Dashboard Scripts
 *
 * Client-side JavaScript for WebSocket connection, routing, and D3.js topology.
 */

/** Build the WebSocket client script. */
export function buildClientScript(wsPort: number): string {
    return `
    let ws;
    let reconnectTimer;
    const statusDot = document.getElementById('status-dot');

    function connect() {
        ws = new WebSocket('ws://localhost:${wsPort}');
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

    function updateSLO(snapshot) {
        if (!snapshot) { return; }
        setMetric('avail-val', snapshot.availability?.currentPercent, '%');
        setMetric('latency-val', snapshot.latency?.p99Ms, 'ms');
        setMetric('compliance-val', snapshot.policyCompliance?.compliancePercent, '%');
        setMetric('trust-val', snapshot.trustScore?.meanScore, '');
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
            entry.type + '</span><span class="audit-time">' + time +
            '</span><span>' + (entry.reason || entry.violation || '-') + '</span></div>';
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
    });`;
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
