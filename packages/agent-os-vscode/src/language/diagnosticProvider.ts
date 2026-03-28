// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Diagnostic Provider for Agent OS
 * 
 * Provides real-time diagnostics for policy violations, security issues,
 * and best practice recommendations.
 */

import * as vscode from 'vscode';

interface DiagnosticRule {
    pattern: RegExp;
    message: string;
    severity: vscode.DiagnosticSeverity;
    code: string;
    source: string;
    tags?: vscode.DiagnosticTag[];
    quickFix?: {
        title: string;
        replacement: string;
    };
}

export class AgentOSDiagnosticProvider {
    private diagnosticCollection: vscode.DiagnosticCollection;
    private disposables: vscode.Disposable[] = [];

    private readonly securityRules: DiagnosticRule[] = [
        {
            pattern: /DROP\s+(TABLE|DATABASE|SCHEMA)\s+\w+/gi,
            message: 'Destructive SQL operation: DROP statement detected. This could cause data loss.',
            severity: vscode.DiagnosticSeverity.Error,
            code: 'AOS001',
            source: 'Agent OS',
            quickFix: {
                title: 'Comment out DROP statement',
                replacement: '-- $0 -- DISABLED BY AGENT OS'
            }
        },
        {
            pattern: /DELETE\s+FROM\s+\w+\s*(;|$|WHERE\s+1\s*=\s*1)/gi,
            message: 'Destructive SQL: DELETE without proper WHERE clause. All records would be deleted.',
            severity: vscode.DiagnosticSeverity.Error,
            code: 'AOS002',
            source: 'Agent OS'
        },
        {
            pattern: /TRUNCATE\s+TABLE\s+\w+/gi,
            message: 'Destructive SQL: TRUNCATE operation will delete all data.',
            severity: vscode.DiagnosticSeverity.Error,
            code: 'AOS003',
            source: 'Agent OS'
        },
        {
            pattern: /rm\s+(-rf|-fr|--recursive\s+--force)\s+[\/~]/gi,
            message: 'Dangerous shell command: rm -rf with root or home directory.',
            severity: vscode.DiagnosticSeverity.Error,
            code: 'AOS004',
            source: 'Agent OS'
        },
        {
            pattern: /(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["'][a-zA-Z0-9_-]{20,}["']/gi,
            message: 'Hardcoded API key detected. Use environment variables instead.',
            severity: vscode.DiagnosticSeverity.Error,
            code: 'AOS005',
            source: 'Agent OS',
            quickFix: {
                title: 'Use environment variable',
                replacement: 'process.env.API_KEY'
            }
        },
        {
            pattern: /(password|passwd|pwd)\s*[=:]\s*["'][^"']+["']/gi,
            message: 'Hardcoded password detected. Use a secrets manager.',
            severity: vscode.DiagnosticSeverity.Error,
            code: 'AOS006',
            source: 'Agent OS'
        },
        {
            pattern: /AKIA[0-9A-Z]{16}/g,
            message: 'AWS Access Key ID detected. Never commit AWS credentials.',
            severity: vscode.DiagnosticSeverity.Error,
            code: 'AOS007',
            source: 'Agent OS'
        },
        {
            pattern: /-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----/g,
            message: 'Private key detected in code. Use a secrets manager.',
            severity: vscode.DiagnosticSeverity.Error,
            code: 'AOS008',
            source: 'Agent OS'
        },
        {
            pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/g,
            message: 'GitHub token detected. Use environment variables.',
            severity: vscode.DiagnosticSeverity.Error,
            code: 'AOS009',
            source: 'Agent OS'
        },
        {
            pattern: /sudo\s+/gi,
            message: 'Privilege escalation: sudo command detected. Avoid in automated scripts.',
            severity: vscode.DiagnosticSeverity.Warning,
            code: 'AOS010',
            source: 'Agent OS'
        },
        {
            pattern: /chmod\s+777\s+/gi,
            message: 'Insecure permissions: chmod 777 grants full access to everyone.',
            severity: vscode.DiagnosticSeverity.Warning,
            code: 'AOS011',
            source: 'Agent OS',
            quickFix: {
                title: 'Use restrictive permissions (755)',
                replacement: 'chmod 755 '
            }
        },
        {
            pattern: /eval\s*\(\s*(.*fetch|.*request|.*input)/gi,
            message: 'Security risk: eval() with external input enables code injection.',
            severity: vscode.DiagnosticSeverity.Error,
            code: 'AOS012',
            source: 'Agent OS'
        },
        {
            pattern: /\.innerHTML\s*=\s*[^'"`]+\+/gi,
            message: 'XSS risk: innerHTML with string concatenation. Use textContent or sanitize input.',
            severity: vscode.DiagnosticSeverity.Warning,
            code: 'AOS013',
            source: 'Agent OS'
        }
    ];

    private readonly bestPracticeRules: DiagnosticRule[] = [
        {
            pattern: /["']http:\/\/(?!localhost|127\.0\.0\.1)/gi,
            message: 'Insecure HTTP connection. Use HTTPS for production.',
            severity: vscode.DiagnosticSeverity.Warning,
            code: 'AOS101',
            source: 'Agent OS'
        },
        {
            pattern: /console\.(log|debug|info)\s*\(/gi,
            message: 'Console logging detected. Consider removing before production.',
            severity: vscode.DiagnosticSeverity.Information,
            code: 'AOS102',
            source: 'Agent OS',
            tags: [vscode.DiagnosticTag.Unnecessary]
        },
        {
            pattern: /TODO|FIXME|HACK|XXX/gi,
            message: 'Code comment indicates pending work.',
            severity: vscode.DiagnosticSeverity.Information,
            code: 'AOS103',
            source: 'Agent OS'
        }
    ];

    private readonly policyRules: DiagnosticRule[] = [
        {
            pattern: /mode:\s*permissive/gi,
            message: 'Permissive mode allows violations. Use strict for production.',
            severity: vscode.DiagnosticSeverity.Warning,
            code: 'AOS201',
            source: 'Agent OS Policy'
        },
        {
            pattern: /observability:\s*\n\s*metrics:\s*false/gi,
            message: 'Metrics disabled. Enable for production monitoring.',
            severity: vscode.DiagnosticSeverity.Information,
            code: 'AOS202',
            source: 'Agent OS Policy'
        }
    ];

    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('agentOS');
    }

    activate(context: vscode.ExtensionContext): void {
        // Analyze on document open
        this.disposables.push(
            vscode.workspace.onDidOpenTextDocument(doc => this.analyzeDocument(doc))
        );

        // Analyze on document change
        this.disposables.push(
            vscode.workspace.onDidChangeTextDocument(event => this.analyzeDocument(event.document))
        );

        // Analyze on save
        this.disposables.push(
            vscode.workspace.onDidSaveTextDocument(doc => this.analyzeDocument(doc))
        );

        // Analyze currently open documents
        vscode.workspace.textDocuments.forEach(doc => this.analyzeDocument(doc));

        // Register code action provider for quick fixes
        this.disposables.push(
            vscode.languages.registerCodeActionsProvider(
                [
                    { scheme: 'file', language: 'javascript' },
                    { scheme: 'file', language: 'typescript' },
                    { scheme: 'file', language: 'python' },
                    { scheme: 'file', language: 'sql' },
                    { scheme: 'file', language: 'yaml' },
                    { scheme: 'file', language: 'shellscript' }
                ],
                new AgentOSCodeActionProvider(),
                { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
            )
        );

        context.subscriptions.push(this.diagnosticCollection, ...this.disposables);
    }

    private analyzeDocument(document: vscode.TextDocument): void {
        // Skip if Agent OS is disabled
        const config = vscode.workspace.getConfiguration('agentOS');
        if (!config.get<boolean>('enabled', true)) {
            this.diagnosticCollection.delete(document.uri);
            return;
        }

        // Skip unsupported languages
        const supportedLanguages = [
            'javascript', 'typescript', 'python', 'sql', 'yaml', 'json',
            'shellscript', 'bash', 'sh', 'php', 'ruby', 'java', 'csharp'
        ];
        if (!supportedLanguages.includes(document.languageId)) {
            return;
        }

        const text = document.getText();
        const diagnostics: vscode.Diagnostic[] = [];

        // Apply security rules
        for (const rule of this.securityRules) {
            this.applyRule(document, text, rule, diagnostics);
        }

        // Apply best practice rules
        for (const rule of this.bestPracticeRules) {
            this.applyRule(document, text, rule, diagnostics);
        }

        // Apply policy rules for YAML/JSON policy files
        if (document.languageId === 'yaml' || document.languageId === 'json') {
            if (document.fileName.includes('agent-os') || 
                document.fileName.includes('policy') ||
                document.fileName.includes('.agents')) {
                for (const rule of this.policyRules) {
                    this.applyRule(document, text, rule, diagnostics);
                }
            }
        }

        this.diagnosticCollection.set(document.uri, diagnostics);
    }

    private applyRule(
        document: vscode.TextDocument,
        text: string,
        rule: DiagnosticRule,
        diagnostics: vscode.Diagnostic[]
    ): void {
        let match: RegExpExecArray | null;
        
        // Reset regex state
        rule.pattern.lastIndex = 0;
        
        while ((match = rule.pattern.exec(text)) !== null) {
            const startPos = document.positionAt(match.index);
            const endPos = document.positionAt(match.index + match[0].length);
            const range = new vscode.Range(startPos, endPos);

            const diagnostic = new vscode.Diagnostic(
                range,
                rule.message,
                rule.severity
            );
            diagnostic.code = rule.code;
            diagnostic.source = rule.source;
            
            if (rule.tags) {
                diagnostic.tags = rule.tags;
            }

            // Store quick fix info in the diagnostic
            if (rule.quickFix) {
                (diagnostic as any).quickFix = rule.quickFix;
            }

            diagnostics.push(diagnostic);
        }
    }

    dispose(): void {
        this.diagnosticCollection.dispose();
        this.disposables.forEach(d => d.dispose());
    }
}

class AgentOSCodeActionProvider implements vscode.CodeActionProvider {
    provideCodeActions(
        document: vscode.TextDocument,
        range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        token: vscode.CancellationToken
    ): vscode.ProviderResult<(vscode.CodeAction | vscode.Command)[]> {
        const actions: vscode.CodeAction[] = [];

        for (const diagnostic of context.diagnostics) {
            if (diagnostic.source?.startsWith('Agent OS')) {
                // Check for quick fix
                const quickFix = (diagnostic as any).quickFix;
                if (quickFix) {
                    const action = new vscode.CodeAction(
                        quickFix.title,
                        vscode.CodeActionKind.QuickFix
                    );
                    action.edit = new vscode.WorkspaceEdit();
                    
                    const text = document.getText(diagnostic.range);
                    const replacement = quickFix.replacement.replace('$0', text);
                    action.edit.replace(document.uri, diagnostic.range, replacement);
                    
                    action.diagnostics = [diagnostic];
                    action.isPreferred = true;
                    actions.push(action);
                }

                // Add "Suppress for this line" action
                const suppressAction = new vscode.CodeAction(
                    `Suppress: ${diagnostic.code}`,
                    vscode.CodeActionKind.QuickFix
                );
                suppressAction.edit = new vscode.WorkspaceEdit();
                
                const line = document.lineAt(diagnostic.range.start.line);
                const suppressComment = this.getSuppressComment(document.languageId, diagnostic.code as string);
                suppressAction.edit.insert(
                    document.uri,
                    new vscode.Position(line.lineNumber, line.text.length),
                    suppressComment
                );
                
                suppressAction.diagnostics = [diagnostic];
                actions.push(suppressAction);

                // Add "Allow once" action for blocked operations
                if (diagnostic.severity === vscode.DiagnosticSeverity.Error) {
                    const allowOnceAction = new vscode.CodeAction(
                        'Agent OS: Allow This Once',
                        vscode.CodeActionKind.QuickFix
                    );
                    allowOnceAction.command = {
                        command: 'agent-os.allowOnce',
                        title: 'Allow once',
                        arguments: [diagnostic.code]
                    };
                    allowOnceAction.diagnostics = [diagnostic];
                    actions.push(allowOnceAction);
                }

                // Add "Learn more" action
                const learnMoreAction = new vscode.CodeAction(
                    `Learn more about ${diagnostic.code}`,
                    vscode.CodeActionKind.Empty
                );
                learnMoreAction.command = {
                    command: 'vscode.open',
                    title: 'Learn more',
                    arguments: [vscode.Uri.parse(`https://agent-os.dev/docs/rules/${diagnostic.code}`)]
                };
                actions.push(learnMoreAction);
            }
        }

        return actions;
    }

    private getSuppressComment(languageId: string, code: string): string {
        switch (languageId) {
            case 'python':
                return `  # noqa: ${code}`;
            case 'javascript':
            case 'typescript':
                return `  // @agent-os-ignore ${code}`;
            case 'sql':
                return `  -- @agent-os-ignore ${code}`;
            case 'yaml':
                return `  # @agent-os-ignore ${code}`;
            default:
                return `  // @agent-os-ignore ${code}`;
        }
    }
}
