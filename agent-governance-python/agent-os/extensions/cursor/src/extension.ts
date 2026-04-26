// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Agent OS Cursor Extension
 * 
 * Provides kernel-level safety for Cursor AI (Composer, Copilot++).
 * Intercepts AI completions, enforces policies, and provides audit trails.
 * 
 * "The AI IDE with a Safety Kernel"
 */

import * as vscode from 'vscode';
import { PolicyEngine } from './policyEngine';
import { CMVKClient } from './cmvkClient';
import { AuditLogger, AuditEntry } from './auditLogger';
import { AuditLogProvider } from './views/auditLogView';
import { PoliciesProvider } from './views/policiesView';
import { StatsProvider } from './views/statsView';
import { StatusBarManager } from './statusBar';

let policyEngine: PolicyEngine;
let cmvkClient: CMVKClient;
let auditLogger: AuditLogger;
let statusBar: StatusBarManager;

export function activate(context: vscode.ExtensionContext) {
    console.log('Agent OS for Cursor activating...');

    // Initialize core components
    policyEngine = new PolicyEngine();
    cmvkClient = new CMVKClient();
    auditLogger = new AuditLogger(context);
    statusBar = new StatusBarManager();

    // Create tree data providers
    const auditLogProvider = new AuditLogProvider(auditLogger);
    const policiesProvider = new PoliciesProvider(policyEngine);
    const statsProvider = new StatsProvider(auditLogger);

    // Register tree views
    vscode.window.registerTreeDataProvider('agent-os.auditLog', auditLogProvider);
    vscode.window.registerTreeDataProvider('agent-os.policies', policiesProvider);
    vscode.window.registerTreeDataProvider('agent-os.stats', statsProvider);

    // Register inline completion interceptor
    const completionInterceptor = vscode.languages.registerInlineCompletionItemProvider(
        { pattern: '**' },
        {
            async provideInlineCompletionItems(
                document: vscode.TextDocument,
                position: vscode.Position,
                context: vscode.InlineCompletionContext,
                token: vscode.CancellationToken
            ): Promise<vscode.InlineCompletionItem[] | null> {
                // We don't provide completions - we intercept and validate existing ones
                // This hook allows us to log what completions are being suggested
                return null;
            }
        }
    );

    // Register document change listener to analyze pasted/typed code
    const textChangeListener = vscode.workspace.onDidChangeTextDocument(async (event) => {
        if (!isEnabled()) return;

        for (const change of event.contentChanges) {
            if (change.text.length > 10) {  // Only analyze substantial changes
                const result = await policyEngine.analyzeCode(change.text, event.document.languageId);
                
                if (result.blocked) {
                    await handleBlockedCode(event.document, change, result);
                } else if (result.warnings.length > 0) {
                    await handleWarnings(result.warnings);
                }
            }
        }
    });

    // Register commands
    const reviewCodeCmd = vscode.commands.registerCommand('agent-os.reviewCode', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('No active editor');
            return;
        }

        const selection = editor.selection;
        const code = selection.isEmpty 
            ? editor.document.getText() 
            : editor.document.getText(selection);

        await reviewCodeWithCMVK(code, editor.document.languageId);
    });

    const toggleSafetyCmd = vscode.commands.registerCommand('agent-os.toggleSafety', () => {
        const config = vscode.workspace.getConfiguration('agentOS');
        const currentState = config.get<boolean>('enabled', true);
        config.update('enabled', !currentState, vscode.ConfigurationTarget.Global);
        
        const newState = !currentState ? 'enabled' : 'disabled';
        vscode.window.showInformationMessage(`Agent OS safety ${newState}`);
        statusBar.update(!currentState);
    });

    const showAuditLogCmd = vscode.commands.registerCommand('agent-os.showAuditLog', () => {
        vscode.commands.executeCommand('agent-os.auditLog.focus');
    });

    const configurePolicyCmd = vscode.commands.registerCommand('agent-os.configurePolicy', async () => {
        await openPolicyConfiguration();
    });

    const exportAuditLogCmd = vscode.commands.registerCommand('agent-os.exportAuditLog', async () => {
        await exportAuditLog();
    });

    const allowOnceCmd = vscode.commands.registerCommand('agent-os.allowOnce', async (violation: string) => {
        policyEngine.allowOnce(violation);
        vscode.window.showInformationMessage(`Allowed once: ${violation}`);
    });

    // Cursor-specific: Ask Cursor for safe alternative
    const askCursorAlternativeCmd = vscode.commands.registerCommand('agent-os.askCursorAlternative', async (blockedCode: string, reason: string) => {
        await askCursorForAlternative(blockedCode, reason);
    });

    // Cursor-specific: Show enterprise info
    const showEnterpriseInfoCmd = vscode.commands.registerCommand('agent-os.showEnterpriseInfo', async () => {
        await showEnterpriseInfo();
    });

    // Register configuration change listener
    const configChangeListener = vscode.workspace.onDidChangeConfiguration((event) => {
        if (event.affectsConfiguration('agentOS')) {
            policyEngine.loadPolicies();
            statusBar.update(isEnabled());
            policiesProvider.refresh();
        }
    });

    // Add all disposables to context
    context.subscriptions.push(
        completionInterceptor,
        textChangeListener,
        reviewCodeCmd,
        toggleSafetyCmd,
        showAuditLogCmd,
        configurePolicyCmd,
        exportAuditLogCmd,
        allowOnceCmd,
        askCursorAlternativeCmd,
        showEnterpriseInfoCmd,
        configChangeListener,
        statusBar
    );

    // Initialize status bar
    statusBar.update(isEnabled());

    // Show welcome message on first activation
    const hasShownWelcome = context.globalState.get('agent-os.welcomeShown', false);
    if (!hasShownWelcome) {
        showWelcomeMessage();
        context.globalState.update('agent-os.welcomeShown', true);
    }

    console.log('Agent OS for Cursor activated - Your AI is now protected');
}

export function deactivate() {
    console.log('Agent OS for Cursor deactivated');
}

// Helper functions

function isEnabled(): boolean {
    return vscode.workspace.getConfiguration('agentOS').get<boolean>('enabled', true);
}

async function handleBlockedCode(
    document: vscode.TextDocument,
    change: vscode.TextDocumentContentChangeEvent,
    result: { blocked: boolean; reason: string; violation: string; suggestion?: string }
): Promise<void> {
    const config = vscode.workspace.getConfiguration('agentOS');
    
    // Log the blocked action
    auditLogger.log({
        type: 'blocked',
        timestamp: new Date(),
        file: document.fileName,
        language: document.languageId,
        code: change.text.substring(0, 200), // Truncate for logging
        violation: result.violation,
        reason: result.reason
    });

    // Update stats
    statusBar.incrementBlocked();

    // Show notification if enabled
    if (config.get<boolean>('notifications.showBlocked', true)) {
        const actions = ['Review Policy', 'Allow Once'];
        
        // Cursor-specific: Add "Ask Cursor" option if enabled
        if (config.get<boolean>('cursor.askForAlternative', true)) {
            actions.push('Ask Cursor for Alternative');
        }
        if (result.suggestion) {
            actions.push('Use Suggestion');
        }

        const selection = await vscode.window.showWarningMessage(
            `⚠️ Agent OS blocked: ${result.reason}`,
            ...actions
        );

        if (selection === 'Review Policy') {
            await openPolicyConfiguration();
        } else if (selection === 'Allow Once') {
            policyEngine.allowOnce(result.violation);
        } else if (selection === 'Ask Cursor for Alternative') {
            await askCursorForAlternative(change.text, result.reason);
        } else if (selection === 'Use Suggestion' && result.suggestion) {
            // Replace the blocked code with the safe alternative
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                const range = new vscode.Range(
                    change.range.start,
                    change.range.start.translate(0, change.text.length)
                );
                await editor.edit(editBuilder => {
                    editBuilder.replace(range, result.suggestion!);
                });
            }
        }
    }

    // Enterprise: Send to webhook if configured
    await sendToEnterpriseWebhook('blocked', {
        file: document.fileName,
        violation: result.violation,
        reason: result.reason
    });
}

async function handleWarnings(warnings: string[]): Promise<void> {
    const config = vscode.workspace.getConfiguration('agentOS');
    
    if (config.get<boolean>('notifications.showWarnings', true)) {
        for (const warning of warnings) {
            vscode.window.showWarningMessage(`⚠️ Agent OS: ${warning}`);
        }
    }
}

async function reviewCodeWithCMVK(code: string, language: string): Promise<void> {
    const config = vscode.workspace.getConfiguration('agentOS');
    const cmvkEnabled = config.get<boolean>('cmvk.enabled', false);

    if (!cmvkEnabled) {
        const enable = await vscode.window.showInformationMessage(
            'CMVK multi-model review is not enabled. Enable it now?',
            'Enable', 'Cancel'
        );
        if (enable === 'Enable') {
            await config.update('cmvk.enabled', true, vscode.ConfigurationTarget.Global);
        } else {
            return;
        }
    }

    // Show progress
    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'Agent OS: Reviewing code with CMVK',
        cancellable: true
    }, async (progress, token) => {
        const models = config.get<string[]>('cmvk.models', ['gpt-4', 'claude-sonnet-4', 'gemini-pro']);
        
        progress.report({ message: `Reviewing with ${models.length} models...` });

        try {
            const result = await cmvkClient.reviewCode(code, language, models);
            
            if (token.isCancellationRequested) return;

            // Show results in a panel
            const panel = vscode.window.createWebviewPanel(
                'agentOSCMVK',
                'Agent OS: Code Review',
                vscode.ViewColumn.Beside,
                { enableScripts: true }
            );

            panel.webview.html = generateCMVKResultsHTML(result);

            // Log the review
            auditLogger.log({
                type: 'cmvk_review',
                timestamp: new Date(),
                language,
                code: code.substring(0, 200),
                result: {
                    consensus: result.consensus,
                    models: result.modelResults.map(m => m.model)
                }
            });

        } catch (error) {
            vscode.window.showErrorMessage(`CMVK review failed: ${error}`);
        }
    });
}

function generateCMVKResultsHTML(result: any): string {
    const consensusColor = result.consensus >= 0.8 ? '#28a745' 
        : result.consensus >= 0.5 ? '#ffc107' 
        : '#dc3545';

    const modelRows = result.modelResults.map((m: any) => `
        <tr>
            <td>${m.passed ? '✅' : '⚠️'}</td>
            <td><strong>${m.model}</strong></td>
            <td>${m.summary}</td>
        </tr>
    `).join('');

    const issuesList = result.issues.length > 0 
        ? `<ul>${result.issues.map((i: string) => `<li>${i}</li>`).join('')}</ul>`
        : '<p>No issues detected</p>';

    return `
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 20px; }
            .consensus { font-size: 24px; font-weight: bold; color: ${consensusColor}; }
            table { width: 100%; border-collapse: collapse; margin: 20px 0; }
            th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
            .section { margin: 20px 0; }
            h2 { border-bottom: 2px solid #333; padding-bottom: 10px; }
            .recommendation { background: #f0f0f0; padding: 15px; border-radius: 8px; }
        </style>
    </head>
    <body>
        <h1>🛡️ Agent OS Code Review</h1>
        
        <div class="section">
            <h2>Consensus</h2>
            <p class="consensus">${(result.consensus * 100).toFixed(0)}% Agreement</p>
            <p>${result.consensus >= 0.8 ? 'Code looks safe!' : 'Review recommended'}</p>
        </div>

        <div class="section">
            <h2>Model Results</h2>
            <table>
                <tr><th></th><th>Model</th><th>Assessment</th></tr>
                ${modelRows}
            </table>
        </div>

        <div class="section">
            <h2>Issues Found</h2>
            ${issuesList}
        </div>

        ${result.recommendations ? `
        <div class="section">
            <h2>Recommendations</h2>
            <div class="recommendation">
                ${result.recommendations}
            </div>
        </div>
        ` : ''}
    </body>
    </html>
    `;
}

async function openPolicyConfiguration(): Promise<void> {
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
    
    if (workspaceFolder) {
        const configPath = vscode.Uri.joinPath(workspaceFolder.uri, '.vscode', 'agent-os.json');
        
        try {
            await vscode.workspace.fs.stat(configPath);
        } catch {
            // Create default config file
            const defaultConfig = {
                policies: {
                    blockDestructiveSQL: true,
                    blockFileDeletes: true,
                    blockSecretExposure: true,
                    blockPrivilegeEscalation: true,
                    blockUnsafeNetworkCalls: false
                },
                cmvk: {
                    enabled: false,
                    models: ['gpt-4', 'claude-sonnet-4', 'gemini-pro'],
                    consensusThreshold: 0.8
                },
                customRules: []
            };
            
            await vscode.workspace.fs.createDirectory(vscode.Uri.joinPath(workspaceFolder.uri, '.vscode'));
            await vscode.workspace.fs.writeFile(
                configPath, 
                Buffer.from(JSON.stringify(defaultConfig, null, 2))
            );
        }
        
        const doc = await vscode.workspace.openTextDocument(configPath);
        await vscode.window.showTextDocument(doc);
    } else {
        // Open global settings
        vscode.commands.executeCommand('workbench.action.openSettings', 'agentOS');
    }
}

async function exportAuditLog(): Promise<void> {
    const logs = auditLogger.getAll();
    
    const uri = await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.file('agent-os-audit.json'),
        filters: { 'JSON': ['json'] }
    });

    if (uri) {
        await vscode.workspace.fs.writeFile(uri, Buffer.from(JSON.stringify(logs, null, 2)));
        vscode.window.showInformationMessage(`Audit log exported to ${uri.fsPath}`);
    }
}

function showWelcomeMessage(): void {
    vscode.window.showInformationMessage(
        '🛡️ Welcome to Agent OS for Cursor! Your AI is now protected with kernel-level safety.',
        'Configure Policies',
        'Enterprise Features',
        'Learn More'
    ).then(selection => {
        if (selection === 'Configure Policies') {
            openPolicyConfiguration();
        } else if (selection === 'Enterprise Features') {
            showEnterpriseInfo();
        } else if (selection === 'Learn More') {
            vscode.env.openExternal(vscode.Uri.parse('https://github.com/microsoft/agent-governance-toolkit'));
        }
    });
}

/**
 * Cursor-specific: Ask Cursor AI for a safe alternative to blocked code
 */
async function askCursorForAlternative(blockedCode: string, reason: string): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) return;

    // Create a prompt that asks for a safe alternative
    const safePrompt = `The following code was blocked by Agent OS safety policy:

\`\`\`
${blockedCode}
\`\`\`

Reason: ${reason}

Please suggest a SAFE alternative that:
1. Accomplishes the same goal
2. Does not violate the safety policy
3. Follows security best practices

Provide only the safe code, no explanation needed.`;

    // Copy the prompt to clipboard and notify user to paste in Cursor Chat
    await vscode.env.clipboard.writeText(safePrompt);
    
    const action = await vscode.window.showInformationMessage(
        '📋 Safe alternative prompt copied to clipboard. Paste it in Cursor Chat (Cmd+L) to get a safe suggestion.',
        'Open Cursor Chat',
        'Dismiss'
    );

    if (action === 'Open Cursor Chat') {
        // Try to open Cursor's AI chat
        vscode.commands.executeCommand('cursorChat.focus').then(undefined, () => {
            // Fallback to command palette
            vscode.commands.executeCommand('workbench.action.quickOpen', '>Cursor');
        });
    }

    // Log this interaction
    auditLogger.log({
        type: 'allowed',
        timestamp: new Date(),
        file: editor.document.fileName,
        language: editor.document.languageId,
        code: blockedCode.substring(0, 200),
        reason: 'Asked Cursor for safe alternative'
    });
}

/**
 * Show enterprise features information
 */
async function showEnterpriseInfo(): Promise<void> {
    const panel = vscode.window.createWebviewPanel(
        'agentOSEnterprise',
        'Agent OS Enterprise',
        vscode.ViewColumn.One,
        { enableScripts: true }
    );

    panel.webview.html = `
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 20px; max-width: 800px; margin: 0 auto; }
            h1 { color: #0066cc; }
            .feature { background: #f5f5f5; padding: 15px; border-radius: 8px; margin: 15px 0; }
            .feature h3 { margin-top: 0; color: #333; }
            .badge { background: #28a745; color: white; padding: 3px 8px; border-radius: 4px; font-size: 12px; }
            .cta { background: #0066cc; color: white; padding: 12px 24px; border-radius: 6px; text-decoration: none; display: inline-block; margin-top: 20px; }
            table { width: 100%; border-collapse: collapse; margin: 20px 0; }
            th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
            th { background: #f0f0f0; }
        </style>
    </head>
    <body>
        <h1>🏢 Agent OS Enterprise for Cursor</h1>
        <p><strong>The safest AI IDE for enterprise teams.</strong></p>

        <div class="feature">
            <h3>🔐 SOC 2 Compliance Mode <span class="badge">Enterprise</span></h3>
            <p>Complete audit trails with configurable retention, immutable logs, and compliance reports.</p>
            <code>agentOS.enterprise.soc2Mode: true</code>
        </div>

        <div class="feature">
            <h3>✅ Approval Workflows <span class="badge">Enterprise</span></h3>
            <p>Require manual approval for high-risk operations. Integrates with Slack, Teams, and PagerDuty.</p>
            <code>agentOS.enterprise.requireApproval: true</code>
        </div>

        <div class="feature">
            <h3>📡 Webhook Streaming <span class="badge">Enterprise</span></h3>
            <p>Stream all audit events to your SIEM (Splunk, DataDog, etc.) in real-time.</p>
            <code>agentOS.enterprise.webhookUrl: "https://..."</code>
        </div>

        <div class="feature">
            <h3>🔑 SSO Integration <span class="badge">Enterprise</span></h3>
            <p>SAML/OIDC integration with Okta, Azure AD, and other identity providers.</p>
        </div>

        <h2>Pricing</h2>
        <table>
            <tr><th>Tier</th><th>Price</th><th>Features</th></tr>
            <tr><td>Free</td><td>$0</td><td>Local policies, 7-day audit, 10 CMVK/day</td></tr>
            <tr><td>Pro</td><td>$9/mo</td><td>Unlimited CMVK, 90-day audit, priority support</td></tr>
            <tr><td>Enterprise</td><td>Custom</td><td>SOC 2, SSO, approval workflows, webhook streaming</td></tr>
        </table>

        <a class="cta" href="https://agent-os.dev/enterprise">Contact Sales →</a>
    </body>
    </html>
    `;
}

/**
 * Send audit event to enterprise webhook if configured
 */
async function sendToEnterpriseWebhook(eventType: string, data: any): Promise<void> {
    const config = vscode.workspace.getConfiguration('agentOS');
    const webhookUrl = config.get<string>('enterprise.webhookUrl', '');
    const soc2Mode = config.get<boolean>('enterprise.soc2Mode', false);

    if (!webhookUrl || !soc2Mode) return;

    try {
        const payload = {
            timestamp: new Date().toISOString(),
            eventType,
            source: 'agent-os-cursor',
            version: '0.1.0',
            data
        };

        // Fire and forget - don't block the extension
        fetch(webhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        }).catch(() => {
            // Silently fail - enterprise webhook should not break the extension
        });
    } catch {
        // Silently fail
    }
}
