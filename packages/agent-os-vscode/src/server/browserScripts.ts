// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Browser Dashboard Scripts — Command Center
 *
 * Client-side JavaScript for WebSocket connection, real-time updates
 * to all visible panels, and D3.js topology graph.
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
    var statusDot = document.getElementById('status-dot');

    function connect() {
        ws = new WebSocket('ws://127.0.0.1:${wsPort}', ['governance-v1', '${sessionToken}']);
        ws.onopen = function() { statusDot.classList.remove('disconnected'); };
        ws.onclose = function() { statusDot.classList.add('disconnected'); scheduleReconnect(); };
        ws.onerror = function() { ws.close(); };
        ws.onmessage = function(event) { handleMessage(JSON.parse(event.data)); };
    }

    function scheduleReconnect() {
        if (reconnectTimer) { clearTimeout(reconnectTimer); }
        reconnectTimer = setTimeout(connect, 3000);
    }

    function handleMessage(msg) {
        if (msg.type === 'sloUpdate') { updateSLO(msg.data); }
        else if (msg.type === 'topologyUpdate') { updateTopology(msg.data); }
        else if (msg.type === 'auditUpdate') { updateAudit(msg.data); }
        else if (msg.type === 'policyUpdate') { updatePolicies(msg.data); }
    }

    /* --- Staleness --- */
    function updateStaleness(fetchedAt) {
        var el = document.getElementById('staleness-badge');
        if (!el || !fetchedAt) { if (el) { el.textContent = ''; } return; }
        var ageSec = Math.round((Date.now() - new Date(fetchedAt).getTime()) / 1000);
        if (isNaN(ageSec) || ageSec < 0 || ageSec < 10) { el.textContent = ''; return; }
        el.textContent = ageSec < 60 ? ageSec + 's ago' : Math.round(ageSec / 60) + 'm ago';
        el.style.color = ageSec > 30 ? 'var(--warning)' : '';
    }

    /* --- SLO Banner --- */
    function updateSLO(snapshot) {
        if (!snapshot) { return; }
        var avail = snapshot.availability?.currentPercent;
        var latency = snapshot.latency?.p99Ms;
        var compliance = snapshot.policyCompliance?.compliancePercent;
        var trust = snapshot.trustScore?.meanScore;

        setMetric('avail-val', avail, '%', 99.5);
        setMetric('latency-val', latency, 'ms', null, true);
        setMetric('compliance-val', compliance, '%', 95);
        setMetric('trust-val', trust, '', 500);

        /* Trends vs previous */
        if (prevSLO) {
            setTrend('avail-trend', avail, prevSLO.avail, false);
            setTrend('latency-trend', latency, prevSLO.latency, true);
            setTrend('compliance-trend', compliance, prevSLO.compliance, false);
            setTrend('trust-trend', trust, prevSLO.trust, false);
        }
        prevSLO = { avail: avail, latency: latency, compliance: compliance, trust: trust };

        /* Stats from SLO snapshot */
        var violations = snapshot.policyCompliance?.violationsToday || 0;
        setStatVal('stat-blocked-today', violations, violations > 0 ? 'c-err' : 'c-text');
        updateStaleness(snapshot.fetchedAt);
    }

    function setMetric(id, value, suffix, threshold, invertThreshold) {
        var el = document.getElementById(id);
        if (!el || value === undefined) { return; }
        el.textContent = value.toFixed(1) + suffix;
        if (threshold !== null && threshold !== undefined) {
            var ok = invertThreshold ? value <= threshold : value >= threshold;
            el.className = 'metric-val ' + (ok ? 'c-ok' : 'c-err');
        }
    }

    function setStatVal(id, value, cls) {
        var el = document.getElementById(id);
        if (el) { el.textContent = value; el.className = 'stat-value ' + (cls || 'c-text'); }
    }

    /* --- Topology --- */
    function updateTopology(data) {
        if (!data) { return; }
        var agents = data.agents || [];
        var bridges = data.bridges || [];
        var delegations = data.delegations || [];
        window._lastTopologyData = { agents: agents, delegations: delegations };
        var countEl = document.getElementById('topo-count');
        if (countEl) {
            var connected = bridges.filter(function(b) { return b.connected; }).length;
            countEl.textContent = agents.length + ' agents / ' + connected + ' bridges';
        }
        if (window.renderTopologyGraph) {
            window.renderTopologyGraph(agents, delegations);
        }
        /* Kernel agent count */
        setStatVal('kern-agents', agents.length, 'c-text');
    }

    /* --- Audit --- */
    var _rawAuditEntries = [];
    function updateAudit(entries) {
        if (!Array.isArray(entries)) { return; }
        _rawAuditEntries = entries;
        renderAuditFiltered();
        /* Stats derived from audit */
        var blocked = entries.filter(function(e) { return e.type === 'blocked'; });
        var warned = entries.filter(function(e) { return e.type === 'warned'; });
        setStatVal('stat-blocked-today', blocked.length, blocked.length > 0 ? 'c-err' : 'c-text');
        setStatVal('stat-warnings', warned.length, warned.length > 0 ? 'c-warn' : 'c-text');
        setStatVal('stat-total', entries.length, 'c-text');
    }
    function renderAuditFiltered() {
        var list = document.getElementById('audit-list');
        if (!list) { return; }
        var textFilter = (document.getElementById('audit-filter') || {}).value || '';
        var sevFilter = (document.getElementById('audit-sev-filter') || {}).value || '';
        var q = textFilter.toLowerCase();
        var filtered = _rawAuditEntries.filter(function(e) {
            if (sevFilter) {
                var sev = e.type === 'blocked' ? 'critical' : e.type === 'warned' ? 'warning' : 'info';
                if (sev !== sevFilter) { return false; }
            }
            if (q) {
                var haystack = ((e.type || '') + ' ' + (e.reason || '') + ' ' + (e.violation || '') + ' ' + (e.file || '')).toLowerCase();
                if (haystack.indexOf(q) === -1) { return false; }
            }
            return true;
        });
        var countEl = document.getElementById('audit-count');
        if (countEl) { countEl.textContent = _rawAuditEntries.length + ' events'; }
        var fcEl = document.getElementById('audit-filter-count');
        if (fcEl) { fcEl.textContent = (q || sevFilter) ? filtered.length + '/' + _rawAuditEntries.length : ''; }
        if (filtered.length === 0) {
            list.innerHTML = '<div class="empty">' + (q || sevFilter ? 'No matching events' : 'No audit events') + '</div>';
            return;
        }
        list.innerHTML = filtered.slice(0, 50).map(function(e) { return buildAuditRow(e); }).join('');
    }

    function buildAuditRow(entry) {
        var time = new Date(entry.timestamp).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
        var sev = entry.type === 'blocked' ? 'critical' : entry.type === 'warned' ? 'warning' : 'info';
        return '<div class="audit-row">' +
            '<span class="sev-badge sev-' + sev + '">' + esc(sev) + '</span>' +
            '<span class="audit-action">' + esc(entry.type) + '</span>' +
            '<span class="audit-detail">' + esc(entry.reason || entry.violation || entry.file || '-') + '</span>' +
            '<span class="audit-time">' + esc(time) + '</span>' +
            '</div>';
    }

    /* --- Policies --- */
    var _rawPolicyRules = [];
    function updatePolicies(data) {
        var rules = [];
        if (Array.isArray(data)) { rules = data; }
        else if (data && data.rules) { rules = data.rules; }
        _rawPolicyRules = rules;
        renderPoliciesFiltered();
    }
    function renderPoliciesFiltered() {
        var list = document.getElementById('policy-list');
        if (!list) { return; }
        var textFilter = (document.getElementById('policy-filter') || {}).value || '';
        var actionFilter = (document.getElementById('policy-action-filter') || {}).value || '';
        var q = textFilter.toLowerCase();
        var filtered = _rawPolicyRules.filter(function(r) {
            if (actionFilter && r.action !== actionFilter) { return false; }
            if (q) {
                var haystack = ((r.name || '') + ' ' + (r.pattern || '')).toLowerCase();
                if (haystack.indexOf(q) === -1) { return false; }
            }
            return true;
        });
        var countEl = document.getElementById('policy-count');
        if (countEl) {
            var enabled = _rawPolicyRules.filter(function(r) { return r.enabled; }).length;
            countEl.textContent = enabled + '/' + _rawPolicyRules.length + ' rules';
        }
        var fcEl = document.getElementById('policy-filter-count');
        if (fcEl) { fcEl.textContent = (q || actionFilter) ? filtered.length + '/' + _rawPolicyRules.length : ''; }
        if (filtered.length === 0) {
            list.innerHTML = '<div class="empty">' + (q || actionFilter ? 'No matching rules' : 'No policies loaded') + '</div>';
            return;
        }
        list.innerHTML = filtered.map(function(r) {
            var cls = 'badge-' + r.action.toLowerCase().replace(/[^a-z0-9-]/g, '');
            return '<div class="policy-row">' +
                '<span class="action-badge ' + cls + '">' + esc(r.action) + '</span>' +
                '<span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text-bright);">' + esc(r.name) + '</span>' +
                '<span style="color:var(--text-muted);font-size:10px;">' + esc(r.evaluationsToday) + ' evals</span>' +
                (r.violationsToday > 0 ? '<span style="color:var(--error);font-size:10px;font-weight:600;">' + esc(r.violationsToday) + '</span>' : '') +
                '</div>';
        }).join('');
    }

    /* --- Help panel --- */
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
    }

    /* --- Theme switching --- */
    var themeSelect = document.getElementById('theme-select');
    var savedTheme = localStorage.getItem('agent-os-theme') || 'slate';
    if (themeSelect) {
        themeSelect.value = savedTheme;
        themeSelect.addEventListener('change', function() {
            var theme = themeSelect.value;
            document.documentElement.dataset.theme = theme;
            localStorage.setItem('agent-os-theme', theme);
            /* Re-render topology with new theme colors */
            if (window._lastTopologyData && window.renderTopologyGraph) {
                window.renderTopologyGraph(window._lastTopologyData.agents, window._lastTopologyData.delegations);
            }
        });
    }

    /* --- Trend tracking --- */
    var prevSLO = null;
    function setTrend(id, current, previous, invert) {
        var el = document.getElementById(id);
        if (!el || previous === null || previous === undefined || current === undefined) { return; }
        var delta = current - previous;
        if (Math.abs(delta) < 0.01) { el.textContent = ''; return; }
        var isGood = invert ? delta < 0 : delta > 0;
        var arrow = delta > 0 ? '\u25B2' : '\u25BC';
        el.textContent = arrow + Math.abs(delta).toFixed(1);
        el.style.color = isGood ? 'var(--success)' : 'var(--error)';
    }

    /* --- Tab switching --- */
    document.addEventListener('click', function(e) {
        var btn = e.target.closest('.tab-btn');
        if (!btn) { return; }
        var group = btn.getAttribute('data-group');
        var target = btn.getAttribute('data-target');
        if (!group || !target) { return; }
        /* Deactivate siblings */
        var siblings = document.querySelectorAll('.tab-btn[data-group="' + group + '"]');
        siblings.forEach(function(b) { b.classList.remove('active'); });
        btn.classList.add('active');
        /* Show/hide panes */
        var parent = btn.closest('.compound-panel');
        if (parent) {
            parent.querySelectorAll('.tab-pane').forEach(function(p) { p.classList.remove('active'); });
            var pane = parent.querySelector('#' + target);
            if (pane) { pane.classList.add('active'); }
        }
    });

    /* --- Filter event listeners --- */
    document.addEventListener('DOMContentLoaded', function() {
        var auditFilter = document.getElementById('audit-filter');
        var auditSevFilter = document.getElementById('audit-sev-filter');
        var policyFilter = document.getElementById('policy-filter');
        var policyActionFilter = document.getElementById('policy-action-filter');
        if (auditFilter) { auditFilter.addEventListener('input', renderAuditFiltered); }
        if (auditSevFilter) { auditSevFilter.addEventListener('change', renderAuditFiltered); }
        if (policyFilter) { policyFilter.addEventListener('input', renderPoliciesFiltered); }
        if (policyActionFilter) { policyActionFilter.addEventListener('change', renderPoliciesFiltered); }
    });

    /* --- Init --- */
    document.addEventListener('DOMContentLoaded', function() { connect(); });
    `;
}

/** Build static help content as HTML sections for the browser dashboard. */
export function buildHelpContent(): string {
    return `
<section data-help="overview"><h2>Overview</h2>
<p>Agent OS provides kernel-level safety for AI coding assistants. It intercepts tool calls, enforces policies, and produces tamper-proof audit trails.</p></section>
<section data-help="slo"><h2>SLO Dashboard</h2>
<p><strong>Availability</strong>: Percentage of successful governance evaluations in the current window.</p>
<p><strong>Latency P99</strong>: 99th-percentile response time for policy evaluation calls.</p>
<p><strong>Compliance</strong>: Percentage of tool calls compliant with active policies.</p>
<p><strong>Mean Trust</strong>: Average trust score across all registered agents (0-1000).</p></section>
<section data-help="topology"><h2>Agent Topology</h2>
<p><strong>Agents</strong>: Registered AI agents identified by DID (Decentralized Identifier).</p>
<p><strong>Bridges</strong>: Protocol connectors (A2A, MCP, IATP) linking agents across trust boundaries.</p>
<p><strong>Trust Score</strong>: Color-coded by trust level. Green (700+), Yellow (400-699), Red (below 400).</p></section>
<section data-help="audit"><h2>Audit Log</h2>
<p>Chronological record of governance decisions. Severity: critical (blocked), warning (flagged), info (allowed).</p></section>
<section data-help="policy"><h2>Active Policies</h2>
<p><strong>DENY</strong>: Rejects the tool call with error. <strong>BLOCK</strong>: Silently prevents execution.</p>
<p><strong>AUDIT</strong>: Allows but logs compliance event. <strong>ALLOW</strong>: Permits with no overhead.</p></section>
<section data-help="kernel"><h2>Kernel Debugger</h2>
<p>Real-time view of the governance kernel. Shows active agent count, policy violations, checkpoint count, and uptime.</p></section>
<section data-help="glossary"><h2>Glossary</h2>
<table><tr><th>Term</th><th>Definition</th></tr>
<tr><td>SLO</td><td>Service Level Objective - a target reliability metric</td></tr>
<tr><td>SLI</td><td>Service Level Indicator - measured value tracking an SLO</td></tr>
<tr><td>DID</td><td>Decentralized Identifier for agent identity</td></tr>
<tr><td>CMVK</td><td>Constitutional Model Verification Kernel</td></tr>
<tr><td>Trust Score</td><td>0-1000 composite reliability rating</td></tr></table></section>`;
}

/** Build the D3.js topology graph script. */
export function buildTopologyScript(): string {
    return `
    window.renderTopologyGraph = function(agents, delegations) {
        var svg = d3.select('#topology-svg');
        svg.selectAll('*').remove();
        var container = svg.node().parentElement;
        var width = container.clientWidth;
        var height = container.clientHeight;
        if (width < 10 || height < 10) { return; }
        svg.attr('viewBox', [0, 0, width, height]);

        var nodes = agents.map(function(a) { return { id: a.did, trustScore: a.trustScore, ring: a.ring }; });
        var links = delegations.map(function(d) {
            return { source: d.fromDid, target: d.toDid, capability: d.capability };
        });

        var simulation = d3.forceSimulation(nodes)
            .force('link', d3.forceLink(links).id(function(d) { return d.id; }).distance(80))
            .force('charge', d3.forceManyBody().strength(-150))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collide', d3.forceCollide(30));

        var link = svg.append('g').selectAll('line').data(links).join('line')
            .attr('class', 'link');
        var node = svg.append('g').selectAll('g').data(nodes).join('g')
            .attr('class', 'node');
        node.append('circle').attr('r', 18).attr('fill', function(d) { return trustColor(d.trustScore); })
            .attr('stroke', function(d) { return trustColor(d.trustScore); }).attr('stroke-opacity', 0.3).attr('stroke-width', 4);
        node.append('text').attr('class', 'node-label').attr('dy', 28)
            .text(function(d) { return d.id.slice(-8); });

        simulation.on('tick', function() {
            link.attr('x1', function(d) { return d.source.x; }).attr('y1', function(d) { return d.source.y; })
                .attr('x2', function(d) { return d.target.x; }).attr('y2', function(d) { return d.target.y; });
            node.attr('transform', function(d) { return 'translate(' + d.x + ',' + d.y + ')'; });
        });
    };

    function trustColor(score) {
        var s = getComputedStyle(document.documentElement);
        if (score > 700) { return s.getPropertyValue('--success').trim() || '#22c55e'; }
        if (score >= 400) { return s.getPropertyValue('--warning').trim() || '#eab308'; }
        return s.getPropertyValue('--error').trim() || '#ef4444';
    }`;
}
