// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Hub Audit Formatter
 *
 * Returns a JavaScript string containing audit and policy formatting
 * functions for injection into the Governance Hub webview.
 */

/** Returns JS source for audit list rendering and filtering. */
export function hubAuditFormatterScript(): string {
    return `
    /** Render audit list entries. */
    function renderAuditList(entries) {
        return entries.slice(0, 100).map(function(e) {
            var icon = getAuditIcon(e.type);
            var title = esc(e.type) + ': ' + esc(e.violation || e.reason || 'No details');
            var details = esc((e.file || '') + ' ' + (e.language || ''));
            var time = esc(formatTime(e.timestamp));
            return '<div class="audit-item">' +
                '<span class="audit-icon ' + esc(e.type) + '">' + icon + '</span>' +
                '<div class="audit-content">' +
                    '<div class="audit-title">' + title + '</div>' +
                    '<div class="audit-details">' + details + '</div>' +
                '</div>' +
                '<span class="audit-time">' + time + '</span>' +
            '</div>';
        }).join('');
    }

    /** Get icon for audit entry type. */
    function getAuditIcon(type) {
        var icons = { blocked: '\\u{1F6AB}', warning: '\\u26A0\\uFE0F', allowed: '\\u2713', cmvk_review: '\\u{1F50D}' };
        return icons[type] || '\\u2022';
    }

    /** Format timestamp for display. */
    function formatTime(ts) {
        return new Date(ts).toLocaleString();
    }

    /** Build audit filter controls HTML. */
    function buildAuditControls() {
        return '<div class="audit-controls">' +
            '<input type="text" id="audit-search" placeholder="Search..." onkeyup="filterAudit()">' +
            '<select id="audit-type" onchange="filterAudit()">' +
                '<option value="">All Types</option>' +
                '<option value="blocked">Blocked</option>' +
                '<option value="warning">Warning</option>' +
                '<option value="allowed">Allowed</option>' +
                '<option value="cmvk_review">CMVK Review</option>' +
            '</select>' +
            '<button onclick="exportAudit()">Export CSV</button>' +
        '</div>';
    }

    /** Render audit with search/filter controls. */
    function formatAuditContent(data) {
        if (!data || !data.length) {
            return '<div class="empty-state">No audit entries</div>';
        }
        auditData = data;
        return '<div class="audit-panel">' + buildAuditControls() +
            '<div id="audit-list">' + renderAuditList(data) + '</div>' +
        '</div>';
    }

    /** Filter audit entries by search and type. */
    function filterAudit() {
        var searchEl = document.getElementById('audit-search');
        var typeEl = document.getElementById('audit-type');
        var search = searchEl ? searchEl.value.toLowerCase() : '';
        var type = typeEl ? typeEl.value : '';
        var filtered = auditData.filter(function(e) {
            var matchesSearch = !search ||
                (e.violation && e.violation.toLowerCase().includes(search)) ||
                (e.file && e.file.toLowerCase().includes(search)) ||
                (e.reason && e.reason.toLowerCase().includes(search));
            var matchesType = !type || e.type === type;
            return matchesSearch && matchesType;
        });
        var listEl = document.getElementById('audit-list');
        if (listEl) { listEl.innerHTML = renderAuditList(filtered); }
    }

    /** Request CSV export from extension. */
    function exportAudit() {
        vscode.postMessage({ type: 'exportAudit' });
    }
    `;
}

/** Returns JS source for policy panel formatting. */
export function hubPolicyFormatterScript(): string {
    return `
    /** Render policy stats cards. */
    function renderPolicyStats(data) {
        var alertClass = data.totalViolationsToday > 0 ? 'alert' : '';
        return '<div class="policy-stats">' +
            '<div class="stat-card">' +
                '<span class="stat-value">' + data.rules.length + '</span>' +
                '<span class="stat-label">Active Rules</span>' +
            '</div>' +
            '<div class="stat-card">' +
                '<span class="stat-value">' + data.totalEvaluationsToday + '</span>' +
                '<span class="stat-label">Evaluations Today</span>' +
            '</div>' +
            '<div class="stat-card ' + alertClass + '">' +
                '<span class="stat-value">' + data.totalViolationsToday + '</span>' +
                '<span class="stat-label">Violations Today</span>' +
            '</div>' +
        '</div>';
    }

    /** Render a single policy rule card. */
    function renderPolicyRule(r) {
        var disabledClass = r.enabled ? '' : 'disabled';
        var violationClass = r.violationsToday > 0 ? 'violations' : '';
        return '<div class="policy-rule ' + disabledClass + '">' +
            '<div class="rule-header">' +
                '<span class="rule-action action-' + esc(r.action).toLowerCase() + '">' + esc(r.action) + '</span>' +
                '<span class="rule-name">' + esc(r.name) + '</span>' +
                '<span class="rule-scope">' + esc(r.scope) + '</span>' +
            '</div>' +
            '<div class="rule-description">' + esc(r.description) + '</div>' +
            '<div class="rule-stats">' +
                '<span>' + esc(r.evaluationsToday) + ' evals</span>' +
                '<span class="' + violationClass + '">' + esc(r.violationsToday) + ' violations</span>' +
            '</div>' +
        '</div>';
    }

    /** Render policy rules list. */
    function renderPolicyRules(rules) {
        return rules.map(function(r) { return renderPolicyRule(r); }).join('');
    }

    /** Render recent violations list. */
    function renderViolationsList(violations) {
        if (!violations || violations.length === 0) return '';
        var items = violations.map(function(v) {
            var time = new Date(v.timestamp).toLocaleTimeString();
            var loc = v.file || v.context;
            return '<div class="violation-item">' +
                '<span class="violation-time">' + esc(time) + '</span>' +
                '<span class="violation-rule">' + esc(v.ruleName) + '</span>' +
                '<span class="violation-context">' + esc(loc) + '</span>' +
            '</div>';
        }).join('');
        return '<h3>Recent Violations</h3><div class="violations-list">' + items + '</div>';
    }

    /** Main policy panel composition. */
    function formatPoliciesContent(data) {
        if (!data || !data.rules) {
            return '<div class="empty-state">No policy data</div>';
        }
        return '<div class="policies-panel">' +
            renderPolicyStats(data) +
            '<h3>Policy Rules</h3>' +
            '<div class="rules-list">' + renderPolicyRules(data.rules) + '</div>' +
            renderViolationsList(data.recentViolations) +
        '</div>';
    }
    `;
}
