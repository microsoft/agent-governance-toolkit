// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Browser Policy Editor — Templates & Client Logic
 *
 * Provides policy template data and client-side JavaScript for the
 * browser-based governance dashboard policy editor. Vanilla JS only;
 * no React, no build system. Output strings are embedded in script tags.
 */

/** Policy template definition used to build the JSON payload. */
interface PolicyTemplate {
    id: string;
    name: string;
    description: string;
    category: 'security' | 'compliance' | 'operational';
    content: string;
}

const POLICY_TEMPLATES: PolicyTemplate[] = [
    {
        id: 'strict-security',
        name: 'Strict Security',
        description: 'Maximum protection with all safety checks enabled',
        category: 'security',
        content: `kernel:
  version: "1.0"
  mode: strict

signals:
  - SIGSTOP
  - SIGKILL
  - SIGINT

policies:
  - name: block_destructive_sql
    severity: critical
    deny:
      - action: database_write
        operations: [DROP, TRUNCATE, DELETE]
    action: SIGKILL

  - name: block_file_deletes
    severity: critical
    deny:
      - action: file_delete
        paths: ["/**"]
    action: SIGKILL

  - name: credential_protection
    severity: critical
    deny:
      - patterns:
          - '(?i)(password|api[_-]?key|secret)\\s*[:=]\\s*"[^"]+"'
    action: SIGKILL

observability:
  metrics: true
  traces: true
  flight_recorder: true`,
    },
    {
        id: 'soc2-compliance',
        name: 'SOC 2 Compliance',
        description: 'Policies aligned with SOC 2 Type II requirements',
        category: 'compliance',
        content: `kernel:
  version: "1.0"
  mode: strict
  template: soc2

policies:
  - name: access_logging
    severity: high
    category: soc2-cc6
    rules:
      - action: "*"
        audit: always

  - name: encryption_required
    severity: critical
    category: soc2-cc6
    deny:
      - action: http_request
        protocol: http

  - name: data_retention
    severity: high
    category: soc2-cc6
    rules:
      - data_type: audit_logs
        min_retention_days: 365

audit:
  enabled: true
  format: json
  retention_days: 365`,
    },
    {
        id: 'gdpr-data-protection',
        name: 'GDPR Data Protection',
        description: 'Policies for GDPR compliance and PII protection',
        category: 'compliance',
        content: `kernel:
  version: "1.0"
  mode: strict
  template: gdpr

policies:
  - name: pii_detection
    severity: critical
    category: gdpr-article5
    deny:
      - patterns:
          - '\\b\\d{3}-\\d{2}-\\d{4}\\b'
          - '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b'
    action: SIGKILL

  - name: data_minimization
    severity: high
    category: gdpr-article5
    rules:
      - action: data_collection
        requires_purpose: true

  - name: right_to_erasure
    severity: high
    category: gdpr-article17
    allow:
      - action: user_data_delete
        requires_verification: true`,
    },
    {
        id: 'development',
        name: 'Development Mode',
        description: 'Permissive policies for development and testing',
        category: 'operational',
        content: `kernel:
  version: "1.0"
  mode: permissive

policies:
  - name: log_all_actions
    severity: low
    rules:
      - action: "*"
        effect: allow
        audit: always

  - name: block_system_destruction
    severity: critical
    deny:
      - patterns:
          - 'rm\\s+-rf\\s+/'
          - 'format\\s+c:'
    action: SIGKILL

observability:
  metrics: true
  traces: true`,
    },
    {
        id: 'rate-limiting',
        name: 'Rate Limiting & Cost Control',
        description: 'Control API usage and prevent cost overruns',
        category: 'operational',
        content: `kernel:
  version: "1.0"
  mode: strict

policies:
  - name: api_rate_limits
    severity: medium
    limits:
      - action: llm_call
        max_per_minute: 60
        max_tokens_per_call: 4000
      - action: http_request
        max_per_minute: 100
    action: SIGSTOP

  - name: cost_controls
    severity: high
    limits:
      - action: llm_call
        max_cost_per_day_usd: 100
    action: SIGSTOP
    escalate_to: finance_team`,
    },
];

/**
 * Returns a JSON string of the 5 policy templates for embedding
 * as `window.__policyTemplates` in the browser page.
 */
export function buildPolicyTemplatesJson(): string {
    return JSON.stringify(POLICY_TEMPLATES);
}

/**
 * Returns client-side vanilla JS for the policy editor panel.
 * Expects `window.__policyTemplates` to be set and the global
 * `esc()` function to be available for HTML escaping.
 */
export function buildPolicyEditorScript(): string {
    return `
    (function() {
        var templates = window.__policyTemplates || [];
        var editor = document.getElementById('pe-editor');
        var linesEl = document.getElementById('pe-lines');
        var templateSelect = document.getElementById('pe-template');
        var formatSelect = document.getElementById('pe-format');
        var validateBtn = document.getElementById('pe-validate');
        var testBtn = document.getElementById('pe-test');
        var downloadBtn = document.getElementById('pe-download');
        var importBtn = document.getElementById('pe-import');
        var resultsEl = document.getElementById('pe-results');

        /* ── Hidden file input for import ── */
        var fileInput = document.getElementById('pe-file-input');
        if (!fileInput) {
            fileInput = document.createElement('input');
            fileInput.type = 'file';
            fileInput.id = 'pe-file-input';
            fileInput.accept = '.yaml,.yml,.json';
            fileInput.style.display = 'none';
            document.body.appendChild(fileInput);
        }

        /* ── Populate template dropdown ── */
        if (templateSelect) {
            for (var t = 0; t < templates.length; t++) {
                var opt = document.createElement('option');
                opt.value = templates[t].id;
                opt.textContent = templates[t].name + ' (' + templates[t].category + ')';
                templateSelect.appendChild(opt);
            }
        }

        /* ── Line number rendering ── */
        function updateLineNumbers() {
            if (!editor || !linesEl) return;
            var lines = editor.value.split('\\n');
            var html = '';
            for (var i = 1; i <= lines.length; i++) {
                html += i + '\\n';
            }
            linesEl.textContent = html;
        }

        function syncScroll() {
            if (!editor || !linesEl) return;
            linesEl.scrollTop = editor.scrollTop;
        }

        if (editor) {
            editor.addEventListener('input', updateLineNumbers);
            editor.addEventListener('scroll', syncScroll);
        }

        /* ── Template loading ── */
        if (templateSelect) {
            templateSelect.addEventListener('change', function() {
                var id = templateSelect.value;
                if (!id) return;
                for (var i = 0; i < templates.length; i++) {
                    if (templates[i].id === id) {
                        if (editor) editor.value = templates[i].content;
                        if (formatSelect) formatSelect.value = 'yaml';
                        updateLineNumbers();
                        break;
                    }
                }
            });
        }

        /* ── Validate ── */
        function showResults(html) {
            if (resultsEl) resultsEl.innerHTML = html;
        }

        if (validateBtn) {
            validateBtn.addEventListener('click', function() {
                if (!editor) return;
                var content = editor.value;
                var format = formatSelect ? formatSelect.value : 'yaml';
                var issues = [];

                if (format === 'json') {
                    try {
                        JSON.parse(content);
                        issues.push('<div style="color:var(--vscode-testing-iconPassed, #4ec9b0);">JSON is valid.</div>');
                    } catch (e) {
                        issues.push('<div style="color:var(--vscode-errorForeground, #f44747);">JSON parse error: ' + esc(e.message) + '</div>');
                    }
                } else {
                    /* YAML heuristic checks */
                    if (/\\t/.test(content)) {
                        issues.push('<div style="color:var(--vscode-errorForeground, #f44747);">Error: YAML must not contain tabs. Use spaces for indentation.</div>');
                    }
                    if (!/^kernel:/m.test(content)) {
                        issues.push('<div style="color:var(--vscode-editorWarning-foreground, #cca700);">Warning: Missing top-level "kernel:" key.</div>');
                    }
                    if (!/^policies:/m.test(content)) {
                        issues.push('<div style="color:var(--vscode-editorWarning-foreground, #cca700);">Warning: Missing "policies:" section.</div>');
                    }
                    if (issues.length === 0) {
                        issues.push('<div style="color:var(--vscode-testing-iconPassed, #4ec9b0);">YAML structure looks valid.</div>');
                    }
                }

                showResults(issues.join(''));
            });
        }

        /* ── Test scenarios ── */
        if (testBtn) {
            testBtn.addEventListener('click', function() {
                if (!editor) return;
                var content = editor.value;

                var scenarios = [
                    { name: 'SQL Injection', input: "query = 'SELECT * FROM users WHERE id = ' + user_input" },
                    { name: 'File Deletion', input: 'rm -rf /tmp/important' },
                    { name: 'Hardcoded Secret', input: "api_key = 'EXAMPLE_KEY_PLACEHOLDER'" },
                    { name: 'Safe Operation', input: 'const result = await db.query("SELECT * FROM users WHERE id = ?", [userId])' }
                ];

                var patterns = [
                    /rm\\s+-rf/i,
                    /api[_-]?key\\s*=\\s*['""][^'""]+['"]/i,
                    /password\\s*=\\s*['""][^'""]+['"]/i,
                    /\\+\\s*user_input/i,
                    /DROP\\s+TABLE/i
                ];

                var html = '<div style="margin-bottom:8px;font-weight:600;">Test Results</div>';
                for (var i = 0; i < scenarios.length; i++) {
                    var blocked = false;
                    for (var j = 0; j < patterns.length; j++) {
                        if (patterns[j].test(scenarios[i].input)) {
                            blocked = true;
                            break;
                        }
                    }
                    var color = blocked
                        ? 'var(--vscode-testing-iconPassed, #4ec9b0)'
                        : 'var(--vscode-errorForeground, #f44747)';
                    var icon = blocked ? '&#9632;' : '&#9632;';
                    var label = blocked ? 'BLOCKED' : 'ALLOWED';
                    html += '<div style="margin:4px 0;">'
                        + '<span style="color:' + color + ';">' + icon + ' ' + label + '</span> '
                        + esc(scenarios[i].name) + ': <code>' + esc(scenarios[i].input) + '</code></div>';
                }
                showResults(html);
            });
        }

        /* ── Download ── */
        if (downloadBtn) {
            downloadBtn.addEventListener('click', function() {
                if (!editor) return;
                var format = formatSelect ? formatSelect.value : 'yaml';
                var blob = new Blob([editor.value], { type: 'text/plain' });
                var url = URL.createObjectURL(blob);
                var a = document.createElement('a');
                a.href = url;
                a.download = 'policy.' + format;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            });
        }

        /* ── Import ── */
        if (importBtn) {
            importBtn.addEventListener('click', function() {
                if (fileInput) fileInput.click();
            });
        }

        if (fileInput) {
            fileInput.addEventListener('change', function() {
                var file = fileInput.files && fileInput.files[0];
                if (!file) return;
                var reader = new FileReader();
                reader.onload = function(e) {
                    if (editor && e.target && e.target.result) {
                        editor.value = e.target.result;
                        updateLineNumbers();
                    }
                };
                reader.readAsText(file);
                fileInput.value = '';
            });
        }

        /* Initial line numbers */
        updateLineNumbers();
    })();
`;
}
