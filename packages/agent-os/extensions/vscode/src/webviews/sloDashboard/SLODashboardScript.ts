// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * SLO Dashboard Script
 *
 * Client-side rendering logic for the SLO Dashboard webview.
 * All functions render into pre-existing DOM elements by ID.
 */

/**
 * Returns a complete `<script>` block for the SLO Dashboard.
 * Handles message passing, gauge rendering, sparklines, and bar charts.
 */
export function sloScript(nonce: string): string {
    return `<script nonce="${nonce}">
    const vscode = acquireVsCodeApi();

    /** 270-degree arc constants for gauge SVGs. */
    const GAUGE_RADIUS = 48;
    const GAUGE_CIRCUMFERENCE = 2 * Math.PI * GAUGE_RADIUS;
    const ARC_FRACTION = 270 / 360;
    const ARC_LENGTH = GAUGE_CIRCUMFERENCE * ARC_FRACTION;

    /**
     * Determine health class from value vs target.
     * Green if at or above target, yellow if within 1%, red otherwise.
     */
    function healthClass(value, target) {
        if (value >= target) { return 'ok'; }
        if (value >= target - 1) { return 'warn'; }
        return 'breach';
    }

    /**
     * Render a 270-degree arc gauge into an SVG element.
     * Sets stroke-dasharray on the value arc and updates the label.
     */
    function renderGauge(id, value, target) {
        var arc = document.getElementById(id + '-arc');
        var valEl = document.getElementById(id + '-value');
        if (!arc || !valEl) { return; }

        var clamped = Math.max(0, Math.min(100, value));
        var filled = (clamped / 100) * ARC_LENGTH;
        var remainder = ARC_LENGTH - filled;
        arc.setAttribute('stroke-dasharray', filled + ' ' + remainder);

        var h = healthClass(value, target);
        arc.classList.remove('stroke-ok', 'stroke-warn', 'stroke-breach');
        arc.classList.add('stroke-' + h);

        valEl.classList.remove('health-ok', 'health-warn', 'health-breach');
        valEl.classList.add('health-' + h);
        valEl.textContent = value.toFixed(1) + '%';
    }

    /**
     * Render a sparkline polyline from an array of up to 24 data points.
     * Scales Y values into a 0-40px range within a 200x40 SVG.
     */
    function renderSparkline(id, points) {
        var el = document.getElementById(id);
        if (!el || !points || points.length === 0) { return; }

        var maxVal = Math.max.apply(null, points);
        var minVal = Math.min.apply(null, points);
        var range = maxVal - minVal || 1;
        var stepX = 200 / Math.max(points.length - 1, 1);

        var coords = points.map(function(p, i) {
            var y = 38 - ((p - minVal) / range) * 36 + 1;
            return (i * stepX).toFixed(1) + ',' + y.toFixed(1);
        });

        var poly = el.querySelector('polyline');
        if (poly) { poly.setAttribute('points', coords.join(' ')); }
    }

    /**
     * Render a horizontal budget bar with colored fill.
     */
    function renderBudgetBar(id, percent) {
        var fill = document.getElementById(id + '-fill');
        if (!fill) { return; }

        var clamped = Math.max(0, Math.min(100, percent));
        fill.style.width = clamped + '%';
        fill.classList.remove('fill-ok', 'fill-warn', 'fill-breach');

        if (clamped > 30) { fill.classList.add('fill-ok'); }
        else if (clamped > 10) { fill.classList.add('fill-warn'); }
        else { fill.classList.add('fill-breach'); }
    }

    /**
     * Render P50/P95/P99 latency bars proportional to the target.
     */
    function renderLatencyBars(p50, p95, p99, target) {
        var maxRef = Math.max(p99, target) * 1.2;
        var entries = [
            { id: 'lat-p50', val: p50 },
            { id: 'lat-p95', val: p95 },
            { id: 'lat-p99', val: p99 }
        ];
        entries.forEach(function(e) {
            var fill = document.getElementById(e.id + '-fill');
            var valEl = document.getElementById(e.id + '-val');
            if (!fill || !valEl) { return; }

            var pct = Math.min((e.val / maxRef) * 100, 100);
            fill.style.width = pct + '%';
            fill.classList.remove('fill-ok', 'fill-warn', 'fill-breach');
            fill.classList.add(e.val <= target ? 'fill-ok' : 'fill-breach');
            valEl.textContent = e.val + 'ms';
        });
    }

    /**
     * Render trust score distribution as stacked bar segments.
     * Buckets: [0-250, 251-500, 501-750, 751-1000].
     */
    function renderDistribution(id, buckets) {
        var bar = document.getElementById(id);
        if (!bar || !buckets) { return; }

        var total = buckets.reduce(function(a, b) { return a + b; }, 0) || 1;
        var segments = bar.querySelectorAll('.segment');
        buckets.forEach(function(count, i) {
            if (segments[i]) {
                segments[i].style.flex = String(count / total);
            }
        });
    }

    /**
     * Master update: dispatch snapshot data to all renderers.
     */
    function updateDashboard(data) {
        var a = data.availability;
        renderGauge('avail-gauge', a.currentPercent, a.targetPercent);
        renderBudgetBar('budget-avail', a.errorBudgetRemainingPercent);

        var c = data.policyCompliance;
        renderGauge('compliance-gauge', c.compliancePercent, 99);
        renderBudgetBar('budget-compliance', 100 - (c.violationsToday / Math.max(c.totalEvaluations, 1)) * 100);

        var l = data.latency;
        renderLatencyBars(l.p50Ms, l.p95Ms, l.p99Ms, l.targetMs);
        renderBudgetBar('budget-latency', l.errorBudgetRemainingPercent);

        var t = data.trustScore;
        renderDistribution('trust-dist', t.distribution);

        setText('card-avail', a.currentPercent.toFixed(2) + '%');
        setHealthColor('card-avail', healthClass(a.currentPercent, a.targetPercent));
        setText('card-latency', l.p99Ms + 'ms');
        setHealthColor('card-latency', l.p99Ms <= l.targetMs ? 'ok' : 'breach');
        setText('card-compliance', c.compliancePercent.toFixed(1) + '%');
        setHealthColor('card-compliance', healthClass(c.compliancePercent, 99));
        setText('card-trust', t.meanScore.toString());
        setHealthColor('card-trust', t.meanScore >= 500 ? 'ok' : (t.meanScore >= 300 ? 'warn' : 'breach'));

        setText('burn-rate-val', a.burnRate.toFixed(2) + 'x');
        setHealthColor('burn-rate-val', a.burnRate <= 1 ? 'ok' : (a.burnRate <= 2 ? 'warn' : 'breach'));

        setText('trend-indicator', c.trend === 'up' ? 'Improving' : (c.trend === 'down' ? 'Declining' : 'Stable'));
    }

    function setText(id, text) {
        var el = document.getElementById(id);
        if (el) { el.textContent = text; }
    }

    function setHealthColor(id, h) {
        var el = document.getElementById(id);
        if (!el) { return; }
        el.classList.remove('health-ok', 'health-warn', 'health-breach');
        el.classList.add('health-' + h);
    }

    window.addEventListener('message', function(e) {
        if (e.data.type === 'sloUpdate') {
            updateDashboard(e.data.snapshot);
        }
    });

    document.getElementById('refresh-btn').onclick = function() {
        vscode.postMessage({ type: 'refresh' });
    };
    </script>`;
}
