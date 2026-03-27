// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Topology Graph Script
 *
 * Pure-JS force-directed graph simulation for the agent topology webview.
 * Settles after 120 frames. No external dependencies.
 */

/** Generate the topology graph script wrapped in a nonced script tag. */
export function topologyScript(nonce: string): string {
    return `<script nonce="${nonce}">
    (function () {
        var vscode = acquireVsCodeApi();
        var svgEl = document.getElementById('topology-svg');
        var tooltipEl = document.getElementById('tooltip');
        var statsBar = document.getElementById('stats-bar');
        var nodes = [], edges = [], bridges = [];
        var frame = 0, dragIndex = -1, animId = 0, zoomLevel = 1;

        function esc(s) {
            return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
        }
        function trustClass(s) {
            return s > 700 ? 'node-trust-high' : s >= 400 ? 'node-trust-mid' : 'node-trust-low';
        }
        function nodeRadius(s) { return 8 + (s / 1000) * 12; }
        function truncDid(d) { return d.length <= 22 ? d : d.slice(0, 22) + '...'; }
        function vw() { return svgEl.clientWidth || 800; }
        function vh() { return svgEl.clientHeight || 600; }

        function initGraph(rawNodes, rawEdges, rawBridges) {
            cancelAnimationFrame(animId);
            bridges = rawBridges || [];
            var cx = vw() / 2, cy = vh() / 2;
            nodes = rawNodes.map(function (n, i) {
                var a = (2 * Math.PI * i) / rawNodes.length;
                var sp = Math.min(cx, cy) * 0.4;
                return { id: n.did, x: cx + Math.cos(a) * sp, y: cy + Math.sin(a) * sp,
                    vx: 0, vy: 0, radius: nodeRadius(n.trustScore),
                    trustScore: n.trustScore, label: truncDid(n.did),
                    ring: n.ring, did: n.did, capabilities: n.capabilities || [] };
            });
            edges = buildEdges(rawEdges);
            updateStatsBar();
            frame = 0;
            simulate();
        }

        function buildEdges(raw) {
            var m = {};
            nodes.forEach(function (n, i) { m[n.did] = i; });
            return (raw || []).filter(function (e) {
                return m[e.fromDid] !== undefined && m[e.toDid] !== undefined;
            }).map(function (e) {
                return { source: m[e.fromDid], target: m[e.toDid],
                    capability: e.capability, expiresIn: e.expiresIn };
            });
        }

        function updateStatsBar() {
            if (!statsBar) { return; }
            var mean = nodes.length === 0 ? 0 : Math.round(
                nodes.reduce(function (s, n) { return s + n.trustScore; }, 0) / nodes.length);
            var conn = bridges.filter(function (b) { return b.connected; }).length;
            statsBar.textContent = 'Agents: ' + nodes.length +
                ' | Mean Trust: ' + mean + ' | Bridges: ' + conn + '/' + bridges.length;
        }

        function applyRepulsion() {
            for (var i = 0; i < nodes.length; i++) {
                for (var j = i + 1; j < nodes.length; j++) {
                    var dx = nodes[j].x - nodes[i].x, dy = nodes[j].y - nodes[i].y;
                    var d2 = dx * dx + dy * dy; if (d2 < 1) { d2 = 1; }
                    var f = 2000 / d2, d = Math.sqrt(d2);
                    var fx = (dx / d) * f, fy = (dy / d) * f;
                    nodes[i].vx -= fx; nodes[i].vy -= fy;
                    nodes[j].vx += fx; nodes[j].vy += fy;
                }
            }
        }

        function applyAttraction() {
            edges.forEach(function (e) {
                var a = nodes[e.source], b = nodes[e.target];
                var dx = b.x - a.x, dy = b.y - a.y;
                var d = Math.sqrt(dx * dx + dy * dy) || 1;
                var f = (d - 100) * 0.005;
                var fx = (dx / d) * f, fy = (dy / d) * f;
                a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
            });
        }

        function applyGravity() {
            var cx = vw() / 2, cy = vh() / 2;
            nodes.forEach(function (n) {
                n.vx += (cx - n.x) * 0.01; n.vy += (cy - n.y) * 0.01;
            });
        }

        function applyVelocities() {
            var w = vw(), h = vh();
            nodes.forEach(function (n, i) {
                if (i === dragIndex) { return; }
                n.vx *= 0.9; n.vy *= 0.9;
                n.vx = Math.max(-15, Math.min(15, n.vx));
                n.vy = Math.max(-15, Math.min(15, n.vy));
                n.x += n.vx; n.y += n.vy;
                n.x = Math.max(n.radius, Math.min(w - n.radius, n.x));
                n.y = Math.max(n.radius, Math.min(h - n.radius, n.y));
            });
        }

        function simulate() {
            applyRepulsion(); applyAttraction(); applyGravity(); applyVelocities();
            renderAll();
            frame++;
            if (frame < 120) { animId = requestAnimationFrame(simulate); }
        }

        function renderAll() {
            svgEl.innerHTML = '<g transform="scale(' + zoomLevel + ')">' +
                renderEdges() + renderNodes() + renderBridgeBadges() + '</g>';
            attachNodeListeners();
        }

        function renderEdges() {
            return edges.map(function (e) {
                var a = nodes[e.source], b = nodes[e.target];
                var mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
                return '<line class="edge" x1="' + a.x + '" y1="' + a.y +
                    '" x2="' + b.x + '" y2="' + b.y + '"/>' +
                    '<text class="edge-label" x="' + mx + '" y="' + (my - 4) +
                    '">' + esc(e.capability) + '</text>';
            }).join('');
        }

        function renderNodes() {
            return nodes.map(function (n, i) {
                return '<circle class="node ' + trustClass(n.trustScore) +
                    '" cx="' + n.x + '" cy="' + n.y + '" r="' + n.radius +
                    '" data-idx="' + i + '"/><text class="node-label" x="' +
                    n.x + '" y="' + (n.y + n.radius + 12) + '">' + esc(n.label) + '</text>';
            }).join('');
        }

        function renderBridgeBadges() {
            if (bridges.length === 0 || nodes.length === 0) { return ''; }
            return bridges.filter(function (b) { return b.connected; })
                .map(function (b, i) {
                    var x = 50, y = 20 + i * 22, w = b.protocol.length * 7 + 16;
                    return '<g class="bridge-badge"><rect x="' + x + '" y="' + (y - 8) +
                        '" width="' + w + '" height="16"/><text x="' +
                        (x + w / 2) + '" y="' + y + '">' + esc(b.protocol) +
                        ' (' + b.peerCount + ')</text></g>';
                }).join('');
        }

        function attachNodeListeners() {
            svgEl.querySelectorAll('circle.node').forEach(function (el) {
                el.addEventListener('mousedown', onNodeMouseDown);
                el.addEventListener('mouseover', onNodeMouseOver);
                el.addEventListener('mouseout', function () { tooltipEl.style.display = 'none'; });
                el.addEventListener('click', onNodeClick);
            });
        }

        function onNodeMouseDown(evt) {
            dragIndex = parseInt(evt.target.getAttribute('data-idx'), 10);
            evt.preventDefault();
        }

        function onNodeMouseOver(evt) {
            var idx = parseInt(evt.target.getAttribute('data-idx'), 10);
            var n = nodes[idx]; if (!n) { return; }
            tooltipEl.innerHTML = '<strong>' + esc(n.did) + '</strong>' +
                '<div class="detail">Trust: ' + n.trustScore + '/1000</div>' +
                '<div class="detail">Ring: ' + esc(n.ring) + '</div>' +
                '<div class="detail">Capabilities: ' +
                (n.capabilities.length ? esc(n.capabilities.join(', ')) : 'none') + '</div>';
            tooltipEl.style.display = 'block';
            tooltipEl.style.left = evt.clientX + 12 + 'px';
            tooltipEl.style.top = evt.clientY + 12 + 'px';
        }

        function onNodeClick(evt) {
            var idx = parseInt(evt.target.getAttribute('data-idx'), 10);
            if (nodes[idx]) { vscode.postMessage({ type: 'selectAgent', did: nodes[idx].did }); }
        }

        document.addEventListener('mousemove', function (evt) {
            if (dragIndex < 0) { return; }
            var rect = svgEl.getBoundingClientRect();
            nodes[dragIndex].x = (evt.clientX - rect.left) / zoomLevel;
            nodes[dragIndex].y = (evt.clientY - rect.top) / zoomLevel;
            renderAll();
        });
        document.addEventListener('mouseup', function () {
            if (dragIndex >= 0) { dragIndex = -1; frame = 0; simulate(); }
        });

        document.getElementById('zoom-in').addEventListener('click', function () {
            zoomLevel = Math.min(3, zoomLevel + 0.15); renderAll();
        });
        document.getElementById('zoom-out').addEventListener('click', function () {
            zoomLevel = Math.max(0.3, zoomLevel - 0.15); renderAll();
        });
        document.getElementById('reset').addEventListener('click', function () {
            zoomLevel = 1; vscode.postMessage({ type: 'refresh' });
        });

        window.addEventListener('message', function (evt) {
            if (evt.data.type === 'topologyUpdate') {
                initGraph(evt.data.nodes, evt.data.edges, evt.data.bridges);
            }
        });
    })();
    </script>`;
}
