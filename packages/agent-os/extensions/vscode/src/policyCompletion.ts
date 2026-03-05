// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Agent OS - Policy YAML Completion Provider
 * 
 * Provides auto-completion for .agents/*.yaml policy files.
 * Helps users configure policies with intelligent suggestions.
 */

import * as vscode from 'vscode';

export class PolicyCompletionProvider implements vscode.CompletionItemProvider {
    
    provideCompletionItems(
        document: vscode.TextDocument,
        position: vscode.Position,
        token: vscode.CancellationToken,
        context: vscode.CompletionContext
    ): vscode.ProviderResult<vscode.CompletionItem[] | vscode.CompletionList> {
        
        // Only provide completions for agent-os config files
        if (!this.isAgentOSConfigFile(document)) {
            return [];
        }

        const linePrefix = document.lineAt(position).text.substring(0, position.character);
        const indent = this.getIndentLevel(linePrefix);

        // Determine context and provide relevant completions
        if (indent === 0) {
            return this.getRootCompletions();
        }

        const context_path = this.getYAMLPath(document, position);
        return this.getContextualCompletions(context_path, linePrefix);
    }

    private isAgentOSConfigFile(document: vscode.TextDocument): boolean {
        const path = document.uri.fsPath.toLowerCase();
        return path.includes('.agents') || 
               path.includes('agent-os') ||
               path.endsWith('security.yaml') ||
               path.endsWith('policies.yaml');
    }

    private getIndentLevel(line: string): number {
        const match = line.match(/^(\s*)/);
        return match ? Math.floor(match[1].length / 2) : 0;
    }

    private getYAMLPath(document: vscode.TextDocument, position: vscode.Position): string[] {
        const path: string[] = [];
        const currentIndent = this.getIndentLevel(document.lineAt(position).text);
        
        // Walk backwards to find parent keys
        for (let i = position.line - 1; i >= 0; i--) {
            const line = document.lineAt(i).text;
            const indent = this.getIndentLevel(line);
            
            if (indent < currentIndent) {
                const match = line.match(/^\s*(\w+):/);
                if (match) {
                    path.unshift(match[1]);
                }
            }
        }
        
        return path;
    }

    private getRootCompletions(): vscode.CompletionItem[] {
        return [
            this.createCompletion('kernel', 'Kernel configuration', `kernel:
  version: "1.0"
  mode: strict`, vscode.CompletionItemKind.Module),
            
            this.createCompletion('policies', 'Policy definitions', `policies:
  - name: default
    blocked_actions: []`, vscode.CompletionItemKind.Module),
            
            this.createCompletion('signals', 'Signal configuration', `signals:
  on_violation: SIGKILL
  on_warning: SIGSTOP`, vscode.CompletionItemKind.Module),
            
            this.createCompletion('audit', 'Audit settings', `audit:
  enabled: true
  log_level: INFO`, vscode.CompletionItemKind.Module),
            
            this.createCompletion('cmvk', 'Verification', `cmvk:
  enabled: false
  models: ["gpt-4", "claude-sonnet-4"]
  threshold: 0.8`, vscode.CompletionItemKind.Module),
            
            this.createCompletion('iatp', 'Inter-agent trust protocol', `iatp:
  enabled: false
  trust_level: HIGH`, vscode.CompletionItemKind.Module),
        ];
    }

    private getContextualCompletions(path: string[], linePrefix: string): vscode.CompletionItem[] {
        const context = path.join('.');

        // Kernel completions
        if (context === 'kernel') {
            return [
                this.createCompletion('version', 'Kernel version', 'version: "1.0"', vscode.CompletionItemKind.Property),
                this.createCompletion('mode', 'Enforcement mode', 'mode: strict', vscode.CompletionItemKind.Property),
            ];
        }

        if (context === 'kernel' && linePrefix.includes('mode')) {
            return [
                this.createValueCompletion('strict', 'Block all violations'),
                this.createValueCompletion('permissive', 'Log only, no blocking'),
                this.createValueCompletion('audit', 'Full logging, selective blocking'),
            ];
        }

        // Policy completions
        if (context === 'policies') {
            return [
                this.createCompletion('- name', 'New policy', `- name: custom_policy
    description: "Custom policy"
    blocked_actions: []`, vscode.CompletionItemKind.Property),
            ];
        }

        if (context.startsWith('policies')) {
            return [
                this.createCompletion('name', 'Policy name', 'name: ', vscode.CompletionItemKind.Property),
                this.createCompletion('description', 'Policy description', 'description: ""', vscode.CompletionItemKind.Property),
                this.createCompletion('blocked_actions', 'Actions to block', `blocked_actions:
  - file_write
  - file_delete`, vscode.CompletionItemKind.Property),
                this.createCompletion('blocked_patterns', 'Patterns to block', `blocked_patterns:
  - pattern: "\\\\bpassword\\\\b"
    reason: "PII detected"`, vscode.CompletionItemKind.Property),
                this.createCompletion('allowed_actions', 'Explicitly allowed actions', `allowed_actions:
  - read_file
  - query_database`, vscode.CompletionItemKind.Property),
            ];
        }

        // Blocked actions completions
        if (context.includes('blocked_actions') || linePrefix.includes('- ')) {
            return this.getActionCompletions();
        }

        // Signal completions
        if (context === 'signals') {
            return [
                this.createCompletion('on_violation', 'Signal on policy violation', 'on_violation: SIGKILL', vscode.CompletionItemKind.Property),
                this.createCompletion('on_warning', 'Signal on warning', 'on_warning: SIGSTOP', vscode.CompletionItemKind.Property),
                this.createCompletion('on_rate_limit', 'Signal on rate limit', 'on_rate_limit: SIGSTOP', vscode.CompletionItemKind.Property),
            ];
        }

        if (linePrefix.includes('SIG') || context.includes('signals')) {
            return this.getSignalCompletions();
        }

        // CMVK completions
        if (context === 'cmvk') {
            return [
                this.createCompletion('enabled', 'Enable CMVK', 'enabled: true', vscode.CompletionItemKind.Property),
                this.createCompletion('models', 'Models for verification', 'models: ["gpt-4", "claude-sonnet-4", "gemini-pro"]', vscode.CompletionItemKind.Property),
                this.createCompletion('threshold', 'Consensus threshold', 'threshold: 0.8', vscode.CompletionItemKind.Property),
                this.createCompletion('timeout', 'Verification timeout (ms)', 'timeout: 30000', vscode.CompletionItemKind.Property),
            ];
        }

        // Audit completions
        if (context === 'audit') {
            return [
                this.createCompletion('enabled', 'Enable auditing', 'enabled: true', vscode.CompletionItemKind.Property),
                this.createCompletion('log_level', 'Logging level', 'log_level: INFO', vscode.CompletionItemKind.Property),
                this.createCompletion('destination', 'Log destination', 'destination: ./audit.log', vscode.CompletionItemKind.Property),
                this.createCompletion('retention_days', 'Log retention period', 'retention_days: 30', vscode.CompletionItemKind.Property),
            ];
        }

        return [];
    }

    private getActionCompletions(): vscode.CompletionItem[] {
        const actions = [
            { name: 'file_write', desc: 'Block file write operations' },
            { name: 'file_delete', desc: 'Block file deletion' },
            { name: 'file_read', desc: 'Block file reading' },
            { name: 'database_write', desc: 'Block database writes (INSERT, UPDATE)' },
            { name: 'database_delete', desc: 'Block database deletes (DELETE, DROP)' },
            { name: 'database_read', desc: 'Block database reads' },
            { name: 'network_request', desc: 'Block network requests' },
            { name: 'execute_shell', desc: 'Block shell command execution' },
            { name: 'send_email', desc: 'Block email sending' },
            { name: 'api_call', desc: 'Block external API calls' },
            { name: 'privilege_escalation', desc: 'Block sudo, chmod 777, etc.' },
            { name: 'secret_access', desc: 'Block access to secrets/credentials' },
        ];

        return actions.map(action => 
            this.createValueCompletion(action.name, action.desc)
        );
    }

    private getSignalCompletions(): vscode.CompletionItem[] {
        return [
            this.createValueCompletion('SIGKILL', 'Terminate immediately (non-catchable)'),
            this.createValueCompletion('SIGSTOP', 'Pause for human review'),
            this.createValueCompletion('SIGCONT', 'Resume execution'),
            this.createValueCompletion('SIGTERM', 'Graceful termination'),
            this.createValueCompletion('SIGWARN', 'Warning (continue execution)'),
        ];
    }

    private createCompletion(
        label: string, 
        detail: string, 
        insertText: string,
        kind: vscode.CompletionItemKind
    ): vscode.CompletionItem {
        const item = new vscode.CompletionItem(label, kind);
        item.detail = detail;
        item.insertText = new vscode.SnippetString(insertText);
        item.documentation = new vscode.MarkdownString(`**${label}**\n\n${detail}`);
        return item;
    }

    private createValueCompletion(value: string, description: string): vscode.CompletionItem {
        const item = new vscode.CompletionItem(value, vscode.CompletionItemKind.Value);
        item.detail = description;
        item.insertText = value;
        return item;
    }
}

/**
 * Policy Hover Provider
 * 
 * Shows policy documentation on hover over policy keywords.
 */
export class PolicyHoverProvider implements vscode.HoverProvider {
    
    private policyDocs: Map<string, string> = new Map([
        ['SIGKILL', '**SIGKILL** - Terminate the agent immediately.\n\nThis signal cannot be caught or ignored. Use for critical policy violations that must stop execution.'],
        ['SIGSTOP', '**SIGSTOP** - Pause the agent for review.\n\nThe agent is suspended until a SIGCONT is received. Use for suspicious activity that needs human review.'],
        ['SIGCONT', '**SIGCONT** - Resume a paused agent.\n\nSent after human review to continue execution.'],
        ['strict', '**Strict Mode**\n\nAll policy violations result in immediate blocking. No exceptions.'],
        ['permissive', '**Permissive Mode**\n\nPolicy violations are logged but not blocked. Useful for testing.'],
        ['audit', '**Audit Mode**\n\nFull logging of all actions. Selective blocking based on rules.'],
        ['file_write', '**file_write**\n\nBlocks all file write operations including:\n- `open(..., "w")`\n- File.write()\n- fs.writeFile()'],
        ['file_delete', '**file_delete**\n\nBlocks file deletion operations including:\n- `os.remove()`\n- `rm -rf`\n- `unlink()`'],
        ['database_delete', '**database_delete**\n\nBlocks destructive SQL operations:\n- `DROP TABLE`\n- `DELETE FROM`\n- `TRUNCATE`'],
        ['cmvk', '**CMVK — Verification Kernel**\n\nVerifies agent outputs by comparing across multiple LLMs. If models disagree significantly, the action is flagged.'],
        ['iatp', '**IATP - Inter-Agent Trust Protocol**\n\nCryptographic signing and verification of messages between agents. Ensures message authenticity and prevents tampering.'],
    ]);

    provideHover(
        document: vscode.TextDocument,
        position: vscode.Position,
        token: vscode.CancellationToken
    ): vscode.ProviderResult<vscode.Hover> {
        
        const wordRange = document.getWordRangeAtPosition(position);
        if (!wordRange) return null;
        
        const word = document.getText(wordRange);
        const doc = this.policyDocs.get(word);
        
        if (doc) {
            return new vscode.Hover(new vscode.MarkdownString(doc));
        }
        
        return null;
    }
}

/**
 * Policy Diagnostics Provider
 * 
 * Validates policy YAML files and shows errors/warnings.
 */
export class PolicyDiagnosticsProvider {
    private diagnosticCollection: vscode.DiagnosticCollection;

    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('agent-os-policy');
    }

    validateDocument(document: vscode.TextDocument): void {
        if (!this.isPolicyFile(document)) return;

        const diagnostics: vscode.Diagnostic[] = [];
        const text = document.getText();
        const lines = text.split('\n');

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            
            // Check for common issues
            
            // Unknown signal
            const signalMatch = line.match(/:\s*(SIG\w+)/);
            if (signalMatch) {
                const signal = signalMatch[1];
                if (!['SIGKILL', 'SIGSTOP', 'SIGCONT', 'SIGTERM', 'SIGWARN'].includes(signal)) {
                    const range = new vscode.Range(i, line.indexOf(signal), i, line.indexOf(signal) + signal.length);
                    diagnostics.push(new vscode.Diagnostic(
                        range,
                        `Unknown signal: ${signal}. Valid signals: SIGKILL, SIGSTOP, SIGCONT, SIGTERM, SIGWARN`,
                        vscode.DiagnosticSeverity.Error
                    ));
                }
            }

            // Invalid threshold value
            if (line.includes('threshold')) {
                const thresholdMatch = line.match(/threshold:\s*([\d.]+)/);
                if (thresholdMatch) {
                    const value = parseFloat(thresholdMatch[1]);
                    if (value < 0 || value > 1) {
                        const start = line.indexOf(thresholdMatch[1]);
                        const range = new vscode.Range(i, start, i, start + thresholdMatch[1].length);
                        diagnostics.push(new vscode.Diagnostic(
                            range,
                            'Threshold must be between 0.0 and 1.0',
                            vscode.DiagnosticSeverity.Error
                        ));
                    }
                }
            }

            // Missing required fields (simple check)
            if (line.includes('policies:') && i + 1 < lines.length) {
                // Check if next non-empty line has a name
                let j = i + 1;
                while (j < lines.length && lines[j].trim() === '') j++;
                if (j < lines.length && lines[j].includes('-') && !lines[j].includes('name')) {
                    const range = new vscode.Range(j, 0, j, lines[j].length);
                    diagnostics.push(new vscode.Diagnostic(
                        range,
                        'Policy should have a "name" field',
                        vscode.DiagnosticSeverity.Warning
                    ));
                }
            }
        }

        this.diagnosticCollection.set(document.uri, diagnostics);
    }

    private isPolicyFile(document: vscode.TextDocument): boolean {
        const path = document.uri.fsPath.toLowerCase();
        return (path.includes('.agents') || path.includes('agent-os')) && 
               (path.endsWith('.yaml') || path.endsWith('.yml'));
    }

    dispose(): void {
        this.diagnosticCollection.dispose();
    }
}
