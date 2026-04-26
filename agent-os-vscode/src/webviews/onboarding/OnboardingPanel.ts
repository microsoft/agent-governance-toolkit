// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Onboarding Panel - Interactive welcome and tutorial experience
 * 
 * Guides new users through AgentOS setup with an interactive walkthrough,
 * first-agent tutorial, and template gallery.
 */

import * as vscode from 'vscode';
import * as crypto from 'crypto';
import { escapeHtml } from '../../utils/escapeHtml';

interface OnboardingStep {
    id: string;
    title: string;
    description: string;
    action?: {
        label: string;
        command: string;
        args?: any[];
    };
    completed: boolean;
}

export class OnboardingPanel {
    public static currentPanel: OnboardingPanel | undefined;
    private readonly _panel: vscode.WebviewPanel;
    private readonly _extensionUri: vscode.Uri;
    private readonly _context: vscode.ExtensionContext;
    private _disposables: vscode.Disposable[] = [];

    public static readonly viewType = 'agentOS.onboarding';

    private _steps: OnboardingStep[] = [
        {
            id: 'welcome',
            title: 'Welcome to Agent OS',
            description: 'Agent OS provides kernel-level safety for AI agents. Let\'s get you started!',
            completed: false
        },
        {
            id: 'understand',
            title: 'Understand the Safety Model',
            description: 'Agent OS intercepts AI actions before they execute, checking them against your policies. Unlike prompt-based safety, violations are blocked at the kernel level.',
            completed: false
        },
        {
            id: 'configure',
            title: 'Configure Your Policies',
            description: 'Set up your safety policies. Start with our recommended defaults or customize for your needs.',
            action: {
                label: 'Open Policy Editor',
                command: 'agent-os.openPolicyEditor'
            },
            completed: false
        },
        {
            id: 'first-agent',
            title: 'Create Your First Governed Agent',
            description: 'Let\'s create a simple agent that runs with AgentOS safety guarantees.',
            action: {
                label: 'Create Agent',
                command: 'agent-os.createFirstAgent'
            },
            completed: false
        },
        {
            id: 'test-safety',
            title: 'Test the Safety System',
            description: 'Try triggering a policy violation to see AgentOS in action. Don\'t worry, dangerous operations will be blocked!',
            action: {
                label: 'Run Safety Test',
                command: 'agent-os.runSafetyTest'
            },
            completed: false
        },
        {
            id: 'explore',
            title: 'Explore Advanced Features',
            description: 'Discover CMVK multi-model review, time-travel debugging, and enterprise features.',
            action: {
                label: 'View Documentation',
                command: 'agent-os.openDocs'
            },
            completed: false
        }
    ];

    private constructor(
        panel: vscode.WebviewPanel,
        extensionUri: vscode.Uri,
        context: vscode.ExtensionContext
    ) {
        this._panel = panel;
        this._extensionUri = extensionUri;
        this._context = context;

        // Load saved progress
        const savedProgress = context.globalState.get<string[]>('agent-os.onboardingProgress', []);
        this._steps.forEach(step => {
            step.completed = savedProgress.includes(step.id);
        });

        this._update();

        this._panel.onDidDispose(() => this.dispose(), null, this._disposables);
        
        this._panel.webview.onDidReceiveMessage(
            async message => {
                switch (message.type) {
                    case 'completeStep':
                        await this._completeStep(message.stepId);
                        break;
                    case 'executeAction':
                        await this._executeAction(message.command, message.args);
                        break;
                    case 'skipOnboarding':
                        await this._skipOnboarding();
                        break;
                    case 'resetProgress':
                        await this._resetProgress();
                        break;
                }
            },
            null,
            this._disposables
        );
    }

    public static createOrShow(extensionUri: vscode.Uri, context: vscode.ExtensionContext) {
        const column = vscode.window.activeTextEditor
            ? vscode.window.activeTextEditor.viewColumn
            : undefined;

        if (OnboardingPanel.currentPanel) {
            OnboardingPanel.currentPanel._panel.reveal(column);
            return;
        }

        const panel = vscode.window.createWebviewPanel(
            OnboardingPanel.viewType,
            'Welcome to Agent OS',
            column || vscode.ViewColumn.One,
            {
                enableScripts: true,
                retainContextWhenHidden: true
            }
        );

        OnboardingPanel.currentPanel = new OnboardingPanel(panel, extensionUri, context);
    }

    private async _completeStep(stepId: string): Promise<void> {
        const step = this._steps.find(s => s.id === stepId);
        if (step) {
            step.completed = true;
            
            // Save progress
            const completed = this._steps.filter(s => s.completed).map(s => s.id);
            await this._context.globalState.update('agent-os.onboardingProgress', completed);
            
            // Update UI
            this._panel.webview.postMessage({ type: 'stepCompleted', stepId });
            
            // Check if all steps completed
            if (this._steps.every(s => s.completed)) {
                vscode.window.showInformationMessage(
                    '🎉 Congratulations! You\'ve completed the Agent OS onboarding!',
                    'View Dashboard'
                ).then(selection => {
                    if (selection === 'View Dashboard') {
                        vscode.commands.executeCommand('agent-os.showMetrics');
                    }
                });
            }
        }
    }

    private async _executeAction(command: string, args?: any[]): Promise<void> {
        try {
            await vscode.commands.executeCommand(command, ...(args || []));
        } catch (error) {
            vscode.window.showErrorMessage(`Failed to execute: ${error}`);
        }
    }

    private async _skipOnboarding(): Promise<void> {
        await this._context.globalState.update('agent-os.onboardingSkipped', true);
        this._panel.dispose();
        vscode.window.showInformationMessage(
            'Onboarding skipped. You can restart it anytime from the command palette.',
            'OK'
        );
    }

    private async _resetProgress(): Promise<void> {
        this._steps.forEach(step => step.completed = false);
        await this._context.globalState.update('agent-os.onboardingProgress', []);
        this._update();
    }

    public dispose() {
        OnboardingPanel.currentPanel = undefined;
        this._panel.dispose();
        while (this._disposables.length) {
            const disposable = this._disposables.pop();
            if (disposable) {
                disposable.dispose();
            }
        }
    }

    private _update() {
        this._panel.title = 'Welcome to Agent OS';
        this._panel.webview.html = this._getHtmlForWebview();
    }

    private _getHtmlForWebview() {
        const nonce = crypto.randomBytes(16).toString('base64');
        const webview = this._panel.webview;
        const cspSource = webview.cspSource;

        const stepsJson = JSON.stringify(this._steps);
        const completedCount = this._steps.filter(s => s.completed).length;
        const totalSteps = this._steps.length;
        const progress = Math.round((completedCount / totalSteps) * 100);

        return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <!-- SECURITY: 'unsafe-inline' for styles required by VS Code theme CSS variable injection. Scripts nonce-gated. -->
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}'; img-src ${cspSource} https:; font-src ${cspSource};">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to Agent OS</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: var(--vscode-font-family);
            color: var(--vscode-foreground);
            background-color: var(--vscode-editor-background);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
        }
        .container {
            max-width: 800px;
            padding: 40px 20px;
            width: 100%;
        }
        .hero {
            text-align: center;
            margin-bottom: 40px;
        }
        .logo {
            font-size: 64px;
            margin-bottom: 10px;
        }
        .hero h1 {
            margin: 0 0 10px 0;
            font-size: 28px;
        }
        .hero p {
            color: var(--vscode-descriptionForeground);
            font-size: 14px;
            margin: 0;
        }
        .progress-container {
            background: var(--vscode-sideBar-background);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
        }
        .progress-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .progress-label {
            font-size: 14px;
            font-weight: bold;
        }
        .progress-count {
            font-size: 12px;
            color: var(--vscode-descriptionForeground);
        }
        .progress-bar {
            height: 8px;
            background: var(--vscode-input-background);
            border-radius: 4px;
            overflow: hidden;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #28a745, #20c997);
            border-radius: 4px;
            transition: width 0.3s ease;
        }
        .steps {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }
        .step {
            background: var(--vscode-sideBar-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 8px;
            padding: 20px;
            transition: all 0.2s;
        }
        .step:hover {
            border-color: var(--vscode-focusBorder);
        }
        .step.completed {
            opacity: 0.7;
        }
        .step-header {
            display: flex;
            align-items: flex-start;
            gap: 15px;
        }
        .step-number {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            background: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 14px;
            font-weight: bold;
            flex-shrink: 0;
        }
        .step.completed .step-number {
            background: #28a745;
        }
        .step-content {
            flex: 1;
        }
        .step-title {
            font-size: 16px;
            font-weight: bold;
            margin: 0 0 8px 0;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .step.completed .step-title::after {
            content: '✓';
            color: #28a745;
            font-size: 18px;
        }
        .step-description {
            color: var(--vscode-descriptionForeground);
            font-size: 13px;
            line-height: 1.5;
            margin: 0 0 15px 0;
        }
        .step-actions {
            display: flex;
            gap: 10px;
        }
        button {
            background: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }
        button:hover {
            background: var(--vscode-button-hoverBackground);
        }
        button.secondary {
            background: var(--vscode-button-secondaryBackground);
            color: var(--vscode-button-secondaryForeground);
        }
        button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        .footer {
            margin-top: 30px;
            text-align: center;
            padding-top: 20px;
            border-top: 1px solid var(--vscode-panel-border);
        }
        .footer-links {
            display: flex;
            justify-content: center;
            gap: 20px;
            margin-bottom: 15px;
        }
        .footer-links a {
            color: var(--vscode-textLink-foreground);
            text-decoration: none;
            font-size: 13px;
        }
        .footer-links a:hover {
            text-decoration: underline;
        }
        .footer-actions {
            display: flex;
            justify-content: center;
            gap: 10px;
        }
        .tip {
            background: var(--vscode-inputValidation-infoBackground);
            border-left: 3px solid var(--vscode-inputValidation-infoBorder);
            padding: 12px 15px;
            border-radius: 0 4px 4px 0;
            font-size: 12px;
            margin-top: 15px;
        }
        .tip strong {
            color: var(--vscode-foreground);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="hero">
            <div class="logo">🛡️</div>
            <h1>Welcome to Agent OS</h1>
            <p>Kernel-level safety for autonomous AI agents</p>
        </div>

        <div class="progress-container">
            <div class="progress-header">
                <span class="progress-label">Getting Started</span>
                <span class="progress-count">${escapeHtml(completedCount)} of ${escapeHtml(totalSteps)} completed</span>
            </div>
            <div class="progress-bar">
                <div class="progress-fill" style="width: ${escapeHtml(progress)}%"></div>
            </div>
        </div>

        <div class="steps" id="steps"></div>

        <div class="footer">
            <div class="footer-links">
                <a href="https://github.com/microsoft/agent-governance-toolkit" target="_blank">📚 Documentation</a>
                <a href="https://github.com/microsoft/agent-governance-toolkit/issues" target="_blank">💬 Get Help</a>
                <a href="https://github.com/microsoft/agent-governance-toolkit" target="_blank">⭐ Star on GitHub</a>
            </div>
            <div class="footer-actions">
                <button class="secondary" onclick="resetProgress()">Reset Progress</button>
                <button class="secondary" onclick="skipOnboarding()">Skip Onboarding</button>
            </div>
        </div>
    </div>

    <script nonce="${nonce}">
        const vscode = acquireVsCodeApi();
        const steps = ${stepsJson};

        function escapeHtml(value) {
            return String(value ?? '')
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        function renderSteps() {
            const container = document.getElementById('steps');
            container.innerHTML = steps.map((step, index) => \`
                <div class="step \${step.completed ? 'completed' : ''}" id="step-\${escapeHtml(step.id)}">
                    <div class="step-header">
                        <div class="step-number">\${step.completed ? '✓' : index + 1}</div>
                        <div class="step-content">
                            <h3 class="step-title">\${escapeHtml(step.title)}</h3>
                            <p class="step-description">\${escapeHtml(step.description)}</p>
                            <div class="step-actions">
                                \${step.action ? \`
                                    <button onclick="executeAction('\${escapeHtml(step.action.command)}')" \${step.completed ? 'disabled' : ''}>
                                        \${escapeHtml(step.action.label)}
                                    </button>
                                \` : ''}
                                \${!step.completed ? \`
                                    <button class="secondary" onclick="completeStep('\${escapeHtml(step.id)}')">
                                        Mark Complete
                                    </button>
                                \` : ''}
                            </div>
                            \${index === 0 ? \`
                                <div class="tip">
                                    <strong>💡 Tip:</strong> Agent OS works with existing AI tools like GitHub Copilot, 
                                    Cursor, and LangChain. It adds a safety layer without changing your workflow.
                                </div>
                            \` : ''}
                        </div>
                    </div>
                </div>
            \`).join('');
        }

        function completeStep(stepId) {
            vscode.postMessage({ type: 'completeStep', stepId });
            const step = steps.find(s => s.id === stepId);
            if (step) {
                step.completed = true;
                renderSteps();
                updateProgress();
            }
        }

        function executeAction(command, args) {
            vscode.postMessage({ type: 'executeAction', command, args });
        }

        function skipOnboarding() {
            vscode.postMessage({ type: 'skipOnboarding' });
        }

        function resetProgress() {
            vscode.postMessage({ type: 'resetProgress' });
            steps.forEach(s => s.completed = false);
            renderSteps();
            updateProgress();
        }

        function updateProgress() {
            const completed = steps.filter(s => s.completed).length;
            const total = steps.length;
            const progress = Math.round((completed / total) * 100);
            document.querySelector('.progress-fill').style.width = progress + '%';
            document.querySelector('.progress-count').textContent = completed + ' of ' + total + ' completed';
        }

        window.addEventListener('message', event => {
            if (event.data.type === 'stepCompleted') {
                const step = steps.find(s => s.id === event.data.stepId);
                if (step) {
                    step.completed = true;
                    renderSteps();
                    updateProgress();
                }
            }
        });

        renderSteps();
    </script>
</body>
</html>`;
    }
}
