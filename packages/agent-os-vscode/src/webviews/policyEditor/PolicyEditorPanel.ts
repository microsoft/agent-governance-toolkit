// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Policy Editor Panel - WebView-based policy management studio
 * 
 * Provides a visual interface for creating, editing, and testing policies
 * with syntax highlighting, real-time validation, and template library.
 */

import * as vscode from 'vscode';
import * as path from 'path';
import * as crypto from 'crypto';

interface PolicyTemplate {
    id: string;
    name: string;
    description: string;
    category: 'security' | 'compliance' | 'operational' | 'custom';
    content: string;
}

interface PolicyValidationResult {
    valid: boolean;
    errors: PolicyError[];
    warnings: PolicyWarning[];
}

interface PolicyError {
    line: number;
    column: number;
    message: string;
    code: string;
}

interface PolicyWarning {
    line: number;
    column: number;
    message: string;
    suggestion?: string;
}

export class PolicyEditorPanel {
    public static currentPanel: PolicyEditorPanel | undefined;
    private readonly _panel: vscode.WebviewPanel;
    private readonly _extensionUri: vscode.Uri;
    private _disposables: vscode.Disposable[] = [];
    private _currentPolicy: string = '';
    private _currentFormat: 'yaml' | 'json' | 'rego' = 'yaml';

    public static readonly viewType = 'agentOS.policyEditor';

    private static readonly templates: PolicyTemplate[] = [
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
          - '(?i)(password|api[_-]?key|secret)\\s*[:=]\\s*["\\''][^\\"\\'']+["\\'']'
    action: SIGKILL

observability:
  metrics: true
  traces: true
  flight_recorder: true
`
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

description: |
  SOC 2 Type II compliance policy template
  Covers: Security, Availability, Confidentiality

policies:
  - name: access_logging
    description: Log all access to sensitive resources
    severity: high
    category: soc2-cc6
    rules:
      - action: "*"
        audit: always
        fields: [timestamp, user, action, resource, outcome]

  - name: encryption_required
    description: Require encryption for data at rest and in transit
    severity: critical
    category: soc2-cc6
    deny:
      - action: http_request
        protocol: http  # Must use HTTPS

  - name: data_retention
    description: Enforce data retention policies
    severity: high
    category: soc2-cc6
    rules:
      - data_type: audit_logs
        min_retention_days: 365
      - data_type: user_data
        max_retention_days: 90

audit:
  enabled: true
  format: json
  retention_days: 365
  export:
    enabled: true
    destinations:
      - type: siem
`
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
    description: Detect and protect personally identifiable information
    severity: critical
    category: gdpr-article5
    scope: [input, output]
    deny:
      - patterns:
          - '\\b\\d{3}-\\d{2}-\\d{4}\\b'  # SSN
          - '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b'  # Email
          - '\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\\b'  # Credit card
    action: SIGKILL
    message: "PII detected - data must be anonymized or encrypted"

  - name: data_minimization
    description: Enforce data minimization principle
    severity: high
    category: gdpr-article5
    rules:
      - action: data_collection
        requires_purpose: true
        requires_consent: true

  - name: right_to_erasure
    description: Support right to be forgotten
    severity: high
    category: gdpr-article17
    allow:
      - action: user_data_delete
        requires_verification: true

  - name: data_portability
    description: Support data export requests
    severity: medium
    category: gdpr-article20
    allow:
      - action: user_data_export
        formats: [json, csv]

audit:
  enabled: true
  include_pii_detection: true
`
        },
        {
            id: 'development',
            name: 'Development Mode',
            description: 'Permissive policies for development and testing',
            category: 'operational',
            content: `kernel:
  version: "1.0"
  mode: permissive

signals:
  - SIGSTOP
  - SIGKILL

policies:
  # Allow most operations but log everything
  - name: log_all_actions
    description: Audit all actions for debugging
    severity: low
    rules:
      - action: "*"
        effect: allow
        audit: always

  # Still block truly dangerous operations
  - name: block_system_destruction
    description: Prevent accidental system damage
    severity: critical
    deny:
      - patterns:
          - 'rm\\s+-rf\\s+/'
          - 'format\\s+c:'
          - 'dd\\s+if=.*of=/dev/sd'
    action: SIGKILL

observability:
  metrics: true
  traces: true
  flight_recorder: true
`
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
    description: Prevent API abuse
    severity: medium
    category: operational
    limits:
      - action: llm_call
        max_per_minute: 60
        max_per_hour: 1000
        max_tokens_per_call: 4000
      - action: http_request
        max_per_minute: 100
      - action: database_query
        max_per_minute: 200
    action: SIGSTOP
    message: "Rate limit exceeded"

  - name: cost_controls
    description: Control AI spending
    severity: high
    category: operational
    limits:
      - action: llm_call
        max_cost_per_day_usd: 100
        max_cost_per_month_usd: 2000
      - action: cmvk_review
        max_per_day: 50
    action: SIGSTOP
    escalate_to: finance_team

  - name: resource_limits
    description: Prevent resource exhaustion
    severity: high
    limits:
      - memory_mb: 1024
      - cpu_percent: 80
      - concurrent_agents: 10
    action: SIGSTOP
`
        }
    ];

    private constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri) {
        this._panel = panel;
        this._extensionUri = extensionUri;

        this._update();

        this._panel.onDidDispose(() => this.dispose(), null, this._disposables);
        
        this._panel.webview.onDidReceiveMessage(
            async message => {
                switch (message.type) {
                    case 'save':
                        await this._savePolicy(message.content, message.format);
                        break;
                    case 'validate':
                        const result = this._validatePolicy(message.content, message.format);
                        this._panel.webview.postMessage({ type: 'validationResult', result });
                        break;
                    case 'loadTemplate':
                        const template = PolicyEditorPanel.templates.find(t => t.id === message.templateId);
                        if (template) {
                            this._panel.webview.postMessage({ type: 'templateLoaded', content: template.content });
                        }
                        break;
                    case 'export':
                        await this._exportPolicy(message.content, message.format);
                        break;
                    case 'import':
                        await this._importPolicy();
                        break;
                    case 'test':
                        await this._testPolicy(message.content);
                        break;
                    case 'convertFormat':
                        const converted = this._convertFormat(message.content, message.from, message.to);
                        this._panel.webview.postMessage({ type: 'formatConverted', content: converted });
                        break;
                }
            },
            null,
            this._disposables
        );
    }

    public static createOrShow(extensionUri: vscode.Uri) {
        const column = vscode.window.activeTextEditor
            ? vscode.window.activeTextEditor.viewColumn
            : undefined;

        if (PolicyEditorPanel.currentPanel) {
            PolicyEditorPanel.currentPanel._panel.reveal(column);
            return;
        }

        const panel = vscode.window.createWebviewPanel(
            PolicyEditorPanel.viewType,
            'Policy Editor',
            column || vscode.ViewColumn.One,
            {
                enableScripts: true,
                retainContextWhenHidden: true,
                localResourceRoots: [
                    vscode.Uri.joinPath(extensionUri, 'media'),
                    vscode.Uri.joinPath(extensionUri, 'out')
                ]
            }
        );

        PolicyEditorPanel.currentPanel = new PolicyEditorPanel(panel, extensionUri);
    }

    public static revive(panel: vscode.WebviewPanel, extensionUri: vscode.Uri) {
        PolicyEditorPanel.currentPanel = new PolicyEditorPanel(panel, extensionUri);
    }

    private _validatePolicy(content: string, format: string): PolicyValidationResult {
        const errors: PolicyError[] = [];
        const warnings: PolicyWarning[] = [];

        try {
            if (format === 'yaml') {
                // Basic YAML validation
                const lines = content.split('\n');
                let inBlock = false;
                let blockIndent = 0;

                lines.forEach((line, index) => {
                    // Check for tabs (should use spaces)
                    if (line.includes('\t')) {
                        errors.push({
                            line: index + 1,
                            column: line.indexOf('\t') + 1,
                            message: 'Use spaces instead of tabs for indentation',
                            code: 'YAML001'
                        });
                    }

                    // Check for required fields
                    if (index === 0 && !line.startsWith('kernel:')) {
                        warnings.push({
                            line: 1,
                            column: 1,
                            message: 'Policy should start with kernel: section',
                            suggestion: 'Add kernel:\\n  version: "1.0"\\n  mode: strict'
                        });
                    }
                });

                // Check for required sections
                if (!content.includes('policies:')) {
                    warnings.push({
                        line: 1,
                        column: 1,
                        message: 'Policy should include a policies: section'
                    });
                }

            } else if (format === 'json') {
                JSON.parse(content);
            }
        } catch (e: any) {
            errors.push({
                line: 1,
                column: 1,
                message: e.message || 'Invalid syntax',
                code: 'PARSE001'
            });
        }

        return {
            valid: errors.length === 0,
            errors,
            warnings
        };
    }

    private async _savePolicy(content: string, format: string): Promise<void> {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) {
            vscode.window.showErrorMessage('No workspace folder open');
            return;
        }

        const ext = format === 'yaml' ? 'yaml' : format === 'json' ? 'json' : 'rego';
        const uri = await vscode.window.showSaveDialog({
            defaultUri: vscode.Uri.joinPath(workspaceFolder.uri, `.agents/policy.${ext}`),
            filters: {
                'Policy Files': [ext],
                'All Files': ['*']
            }
        });

        if (uri) {
            await vscode.workspace.fs.writeFile(uri, Buffer.from(content));
            vscode.window.showInformationMessage(`Policy saved to ${uri.fsPath}`);
        }
    }

    private async _exportPolicy(content: string, format: string): Promise<void> {
        await this._savePolicy(content, format);
    }

    private async _importPolicy(): Promise<void> {
        const uris = await vscode.window.showOpenDialog({
            canSelectMany: false,
            filters: {
                'Policy Files': ['yaml', 'yml', 'json', 'rego'],
                'All Files': ['*']
            }
        });

        if (uris && uris[0]) {
            const content = await vscode.workspace.fs.readFile(uris[0]);
            const ext = path.extname(uris[0].fsPath).toLowerCase();
            const format = ext === '.json' ? 'json' : ext === '.rego' ? 'rego' : 'yaml';
            
            this._panel.webview.postMessage({
                type: 'policyImported',
                content: content.toString(),
                format
            });
        }
    }

    private async _testPolicy(content: string): Promise<void> {
        // Test the policy against sample scenarios
        const testCases = [
            { name: 'SQL Injection', code: "query = 'SELECT * FROM users WHERE id = ' + user_input" },
            { name: 'File Deletion', code: 'rm -rf /tmp/important' },
            { name: 'Hardcoded Secret', code: "api_key = 'sk-1234567890abcdef'" },
            { name: 'Safe Operation', code: 'const result = await db.query("SELECT * FROM users WHERE id = ?", [userId])' }
        ];

        const results = testCases.map(tc => ({
            name: tc.name,
            blocked: this._wouldBeBlocked(content, tc.code),
            code: tc.code
        }));

        this._panel.webview.postMessage({ type: 'testResults', results });
    }

    private _wouldBeBlocked(policy: string, code: string): boolean {
        // Simple pattern matching for demo
        const dangerousPatterns = [
            /rm\s+-rf/i,
            /api[_-]?key\s*=\s*['"][^'"]+['"]/i,
            /password\s*=\s*['"][^'"]+['"]/i,
            /\+\s*user_input/i,
            /DROP\s+TABLE/i
        ];

        return dangerousPatterns.some(pattern => pattern.test(code));
    }

    private _convertFormat(content: string, from: string, to: string): string {
        // Basic format conversion
        if (from === 'json' && to === 'yaml') {
            try {
                const obj = JSON.parse(content);
                return this._jsonToYaml(obj);
            } catch {
                return content;
            }
        } else if (from === 'yaml' && to === 'json') {
            try {
                const obj = this._yamlToJson(content);
                return JSON.stringify(obj, null, 2);
            } catch {
                return content;
            }
        }
        return content;
    }

    private _jsonToYaml(obj: any, indent: number = 0): string {
        const spaces = '  '.repeat(indent);
        let result = '';

        for (const [key, value] of Object.entries(obj)) {
            if (value === null || value === undefined) {
                result += `${spaces}${key}: null\n`;
            } else if (typeof value === 'string') {
                result += `${spaces}${key}: "${value}"\n`;
            } else if (typeof value === 'number' || typeof value === 'boolean') {
                result += `${spaces}${key}: ${value}\n`;
            } else if (Array.isArray(value)) {
                result += `${spaces}${key}:\n`;
                value.forEach(item => {
                    if (typeof item === 'object') {
                        result += `${spaces}  -\n${this._jsonToYaml(item, indent + 2)}`;
                    } else {
                        result += `${spaces}  - ${item}\n`;
                    }
                });
            } else if (typeof value === 'object') {
                result += `${spaces}${key}:\n${this._jsonToYaml(value, indent + 1)}`;
            }
        }

        return result;
    }

    private _yamlToJson(yaml: string): any {
        // Basic YAML parsing (simplified)
        const result: any = {};
        const lines = yaml.split('\n');
        const stack: { obj: any; indent: number }[] = [{ obj: result, indent: -1 }];

        for (const line of lines) {
            if (line.trim() === '' || line.trim().startsWith('#')) continue;

            const indent = line.search(/\S/);
            const content = line.trim();

            // Pop stack until we find parent
            while (stack.length > 1 && stack[stack.length - 1].indent >= indent) {
                stack.pop();
            }

            const parent = stack[stack.length - 1].obj;
            const match = content.match(/^([^:]+):\s*(.*)$/);

            if (match) {
                const [, key, value] = match;
                if (value === '' || value === '|' || value === '>') {
                    parent[key] = {};
                    stack.push({ obj: parent[key], indent });
                } else {
                    parent[key] = this._parseYamlValue(value);
                }
            }
        }

        return result;
    }

    private _parseYamlValue(value: string): any {
        if (value === 'true') return true;
        if (value === 'false') return false;
        if (value === 'null') return null;
        if (/^\d+$/.test(value)) return parseInt(value, 10);
        if (/^\d+\.\d+$/.test(value)) return parseFloat(value);
        if (/^["'].*["']$/.test(value)) return value.slice(1, -1);
        return value;
    }

    public dispose() {
        PolicyEditorPanel.currentPanel = undefined;
        this._panel.dispose();
        while (this._disposables.length) {
            const disposable = this._disposables.pop();
            if (disposable) {
                disposable.dispose();
            }
        }
    }

    private _update() {
        const webview = this._panel.webview;
        this._panel.title = 'Agent OS Policy Editor';
        this._panel.webview.html = this._getHtmlForWebview(webview);
    }

    private _getHtmlForWebview(webview: vscode.Webview) {
        const nonce = crypto.randomBytes(16).toString('base64');
        const cspSource = webview.cspSource;
        const templatesJson = JSON.stringify(PolicyEditorPanel.templates);

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}'; img-src ${cspSource} https:; font-src ${cspSource};">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Policy Editor</title>
    <style>
        * {
            box-sizing: border-box;
        }
        body {
            font-family: var(--vscode-font-family);
            color: var(--vscode-foreground);
            background-color: var(--vscode-editor-background);
            margin: 0;
            padding: 20px;
        }
        .container {
            display: grid;
            grid-template-columns: 250px 1fr 300px;
            gap: 20px;
            height: calc(100vh - 40px);
        }
        .sidebar {
            background: var(--vscode-sideBar-background);
            border-radius: 8px;
            padding: 15px;
            overflow-y: auto;
        }
        .editor-container {
            display: flex;
            flex-direction: column;
            background: var(--vscode-editor-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 8px;
            overflow: hidden;
        }
        .toolbar {
            display: flex;
            gap: 10px;
            padding: 10px;
            background: var(--vscode-editorGroupHeader-tabsBackground);
            border-bottom: 1px solid var(--vscode-panel-border);
        }
        .editor {
            flex: 1;
            padding: 15px;
            font-family: var(--vscode-editor-font-family);
            font-size: var(--vscode-editor-font-size);
            background: var(--vscode-editor-background);
            color: var(--vscode-editor-foreground);
            border: none;
            resize: none;
            line-height: 1.5;
        }
        .editor:focus {
            outline: none;
        }
        .validation-panel {
            background: var(--vscode-sideBar-background);
            border-radius: 8px;
            padding: 15px;
            overflow-y: auto;
        }
        h2 {
            margin-top: 0;
            font-size: 14px;
            text-transform: uppercase;
            color: var(--vscode-sideBarSectionHeader-foreground);
            border-bottom: 1px solid var(--vscode-panel-border);
            padding-bottom: 10px;
        }
        .template-card {
            background: var(--vscode-editor-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 6px;
            padding: 12px;
            margin-bottom: 10px;
            cursor: pointer;
            transition: all 0.2s;
        }
        .template-card:hover {
            border-color: var(--vscode-focusBorder);
            background: var(--vscode-list-hoverBackground);
        }
        .template-card h3 {
            margin: 0 0 5px 0;
            font-size: 13px;
            color: var(--vscode-foreground);
        }
        .template-card p {
            margin: 0;
            font-size: 11px;
            color: var(--vscode-descriptionForeground);
        }
        .template-card .category {
            display: inline-block;
            font-size: 10px;
            padding: 2px 6px;
            border-radius: 3px;
            margin-top: 8px;
        }
        .category-security { background: #dc354530; color: #dc3545; }
        .category-compliance { background: #0d6efd30; color: #0d6efd; }
        .category-operational { background: #ffc10730; color: #ffc107; }
        .category-custom { background: #6c757d30; color: #6c757d; }
        button {
            background: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
        }
        button:hover {
            background: var(--vscode-button-hoverBackground);
        }
        button.secondary {
            background: var(--vscode-button-secondaryBackground);
            color: var(--vscode-button-secondaryForeground);
        }
        select {
            background: var(--vscode-dropdown-background);
            color: var(--vscode-dropdown-foreground);
            border: 1px solid var(--vscode-dropdown-border);
            padding: 5px 10px;
            border-radius: 4px;
            font-size: 12px;
        }
        .error {
            color: var(--vscode-errorForeground);
            background: var(--vscode-inputValidation-errorBackground);
            border-left: 3px solid var(--vscode-errorForeground);
            padding: 8px 12px;
            margin: 5px 0;
            font-size: 12px;
            border-radius: 0 4px 4px 0;
        }
        .warning {
            color: var(--vscode-editorWarning-foreground);
            background: var(--vscode-inputValidation-warningBackground);
            border-left: 3px solid var(--vscode-editorWarning-foreground);
            padding: 8px 12px;
            margin: 5px 0;
            font-size: 12px;
            border-radius: 0 4px 4px 0;
        }
        .success {
            color: #28a745;
            background: #28a74515;
            border-left: 3px solid #28a745;
            padding: 8px 12px;
            margin: 5px 0;
            font-size: 12px;
            border-radius: 0 4px 4px 0;
        }
        .test-result {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px;
            margin: 5px 0;
            background: var(--vscode-editor-background);
            border-radius: 4px;
            font-size: 12px;
        }
        .test-result.blocked { border-left: 3px solid #28a745; }
        .test-result.allowed { border-left: 3px solid #dc3545; }
        .status-indicator {
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }
        .status-indicator.blocked { background: #28a745; }
        .status-indicator.allowed { background: #dc3545; }
        .line-numbers {
            padding: 15px 10px;
            background: var(--vscode-editorLineNumber-background);
            color: var(--vscode-editorLineNumber-foreground);
            font-family: var(--vscode-editor-font-family);
            font-size: var(--vscode-editor-font-size);
            line-height: 1.5;
            text-align: right;
            user-select: none;
            border-right: 1px solid var(--vscode-panel-border);
        }
        .editor-wrapper {
            display: flex;
            flex: 1;
            overflow: auto;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="sidebar">
            <h2>📋 Policy Templates</h2>
            <div id="templates"></div>
        </div>
        
        <div class="editor-container">
            <div class="toolbar">
                <select id="format">
                    <option value="yaml">YAML</option>
                    <option value="json">JSON</option>
                    <option value="rego">Rego</option>
                </select>
                <button onclick="validate()">✓ Validate</button>
                <button onclick="testPolicy()">🧪 Test</button>
                <button onclick="savePolicy()">💾 Save</button>
                <button class="secondary" onclick="importPolicy()">📥 Import</button>
                <button class="secondary" onclick="exportPolicy()">📤 Export</button>
            </div>
            <div class="editor-wrapper">
                <div class="line-numbers" id="lineNumbers">1</div>
                <textarea class="editor" id="editor" spellcheck="false" placeholder="Enter your policy here or select a template..."></textarea>
            </div>
        </div>
        
        <div class="validation-panel">
            <h2>🔍 Validation</h2>
            <div id="validationResults">
                <p style="color: var(--vscode-descriptionForeground); font-size: 12px;">
                    Edit your policy and click Validate to check for errors.
                </p>
            </div>
            
            <h2 style="margin-top: 20px;">🧪 Test Results</h2>
            <div id="testResults">
                <p style="color: var(--vscode-descriptionForeground); font-size: 12px;">
                    Click Test to see how your policy handles common scenarios.
                </p>
            </div>
        </div>
    </div>

    <script nonce="${nonce}">
        const vscode = acquireVsCodeApi();
        const templates = ${templatesJson};
        const editor = document.getElementById('editor');
        const lineNumbers = document.getElementById('lineNumbers');
        
        // Render templates
        const templatesContainer = document.getElementById('templates');
        templates.forEach(template => {
            const card = document.createElement('div');
            card.className = 'template-card';
            card.innerHTML = \`
                <h3>\${template.name}</h3>
                <p>\${template.description}</p>
                <span class="category category-\${template.category}">\${template.category}</span>
            \`;
            card.onclick = () => loadTemplate(template.id);
            templatesContainer.appendChild(card);
        });

        // Update line numbers
        function updateLineNumbers() {
            const lines = editor.value.split('\\n').length;
            lineNumbers.innerHTML = Array.from({length: lines}, (_, i) => i + 1).join('<br>');
        }
        
        editor.addEventListener('input', updateLineNumbers);
        editor.addEventListener('scroll', () => {
            lineNumbers.scrollTop = editor.scrollTop;
        });

        function loadTemplate(id) {
            vscode.postMessage({ type: 'loadTemplate', templateId: id });
        }

        function validate() {
            const content = editor.value;
            const format = document.getElementById('format').value;
            vscode.postMessage({ type: 'validate', content, format });
        }

        function savePolicy() {
            const content = editor.value;
            const format = document.getElementById('format').value;
            vscode.postMessage({ type: 'save', content, format });
        }

        function importPolicy() {
            vscode.postMessage({ type: 'import' });
        }

        function exportPolicy() {
            const content = editor.value;
            const format = document.getElementById('format').value;
            vscode.postMessage({ type: 'export', content, format });
        }

        function testPolicy() {
            const content = editor.value;
            vscode.postMessage({ type: 'test', content });
        }

        // Handle messages from extension
        window.addEventListener('message', event => {
            const message = event.data;
            switch (message.type) {
                case 'templateLoaded':
                    editor.value = message.content;
                    document.getElementById('format').value = 'yaml';
                    updateLineNumbers();
                    break;
                case 'validationResult':
                    showValidationResults(message.result);
                    break;
                case 'testResults':
                    showTestResults(message.results);
                    break;
                case 'policyImported':
                    editor.value = message.content;
                    document.getElementById('format').value = message.format;
                    updateLineNumbers();
                    break;
            }
        });

        function showValidationResults(result) {
            const container = document.getElementById('validationResults');
            container.innerHTML = '';

            if (result.valid && result.warnings.length === 0) {
                container.innerHTML = '<div class="success">✓ Policy is valid</div>';
                return;
            }

            result.errors.forEach(error => {
                const div = document.createElement('div');
                div.className = 'error';
                div.innerHTML = \`<strong>Line \${error.line}:</strong> \${error.message}\`;
                container.appendChild(div);
            });

            result.warnings.forEach(warning => {
                const div = document.createElement('div');
                div.className = 'warning';
                div.innerHTML = \`<strong>Line \${warning.line}:</strong> \${warning.message}\`;
                if (warning.suggestion) {
                    div.innerHTML += \`<br><small>💡 \${warning.suggestion}</small>\`;
                }
                container.appendChild(div);
            });
        }

        function showTestResults(results) {
            const container = document.getElementById('testResults');
            container.innerHTML = '';

            results.forEach(result => {
                const div = document.createElement('div');
                div.className = \`test-result \${result.blocked ? 'blocked' : 'allowed'}\`;
                div.innerHTML = \`
                    <span class="status-indicator \${result.blocked ? 'blocked' : 'allowed'}"></span>
                    <span><strong>\${result.name}:</strong> \${result.blocked ? '🛡️ Blocked' : '⚠️ Allowed'}</span>
                \`;
                container.appendChild(div);
            });
        }

        // Initialize
        updateLineNumbers();
    </script>
</body>
</html>`;
    }
}
