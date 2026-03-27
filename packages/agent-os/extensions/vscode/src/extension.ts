// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Agent OS VS Code Extension
 * 
 * Provides kernel-level safety for AI coding assistants.
 * Intercepts AI completions, enforces policies, and provides audit trails.
 * 
 * GA Release - v1.0.0
 */

import * as vscode from 'vscode';
import { PolicyEngine } from './policyEngine';
import { CMVKClient } from './cmvkClient';
import { AuditLogger } from './auditLogger';
import { AuditLogProvider } from './views/auditLogView';
import { PoliciesProvider } from './views/policiesView';
import { StatsProvider } from './views/statsView';
import { StatusBarManager } from './statusBar';
import { KernelDebuggerProvider, MemoryBrowserProvider } from './views/kernelDebuggerView';

// New GA Features
import { PolicyEditorPanel } from './webviews/policyEditor/PolicyEditorPanel';
import { WorkflowDesignerPanel } from './webviews/workflowDesigner/WorkflowDesignerPanel';
import { MetricsDashboardPanel } from './webviews/metricsDashboard/MetricsDashboardPanel';
import { OnboardingPanel } from './webviews/onboarding/OnboardingPanel';
import { AgentOSCompletionProvider, AgentOSHoverProvider } from './language/completionProvider';
import { AgentOSDiagnosticProvider } from './language/diagnosticProvider';
import { GovernanceDiagnosticProvider } from './language/governanceDiagnosticProvider';

// Governance Visualization (Issue #39)
import { SLODashboardProvider } from './views/sloDashboardView';
import { AgentTopologyProvider, createMockTopologyProvider } from './views/agentTopologyView';
import { GovernanceStatusBar } from './governanceStatusBar';

// Governance Webview Panels (Issue #39 - Rich Visualization)
import { SLODashboardPanel } from './webviews/sloDashboard/SLODashboardPanel';
import { TopologyGraphPanel } from './webviews/agentTopology/TopologyGraphPanel';

// Governance Hub (Issue #39 - Unified Dashboard)
import { GovernanceHubPanel } from './webviews/governanceHub/GovernanceHubPanel';

// 3-Slot Sidebar (Sidebar Redesign)
import { SidebarProvider } from './webviews/sidebar/SidebarProvider';
import { GovernanceEventBus } from './webviews/sidebar/governanceEventBus';
import { GovernanceStore } from './webviews/sidebar/GovernanceStore';

// Governance Server (Issue #39 - Browser Experience)
import { GovernanceServer } from './server/GovernanceServer';

// Export & Observability (Issue #39 - Shareable Reports)
import { ReportGenerator, LocalStorageProvider, CredentialError } from './export';
import { MetricsExporter } from './observability';

// Backend Services
import { createMockSLOBackend } from './mockBackend/MockSLOBackend';
import { createMockTopologyBackend } from './mockBackend/MockTopologyBackend';
import { createMockPolicyBackend } from './mockBackend/MockPolicyBackend';
import { PolicyDataProvider } from './views/policyTypes';

// Provider Factory
import { createProviders, ProviderConfig, Providers } from './services/providerFactory';

// Enterprise Features
import { EnterpriseAuthProvider } from './enterprise/auth/ssoProvider';
import { RBACManager } from './enterprise/auth/rbacManager';
import { CICDIntegration } from './enterprise/integration/cicdIntegration';
import { ComplianceManager } from './enterprise/compliance/frameworkLoader';

let policyEngine: PolicyEngine;
let cmvkClient: CMVKClient;
let auditLogger: AuditLogger;
let statusBar: StatusBarManager;
let authProvider: EnterpriseAuthProvider;
let rbacManager: RBACManager;
let cicdIntegration: CICDIntegration;
let complianceManager: ComplianceManager;
let diagnosticProvider: AgentOSDiagnosticProvider;
let governanceDiagnosticProvider: GovernanceDiagnosticProvider;
let governanceStatusBar: GovernanceStatusBar;
let governanceServer: GovernanceServer | undefined;
let sidebarProvider: SidebarProvider | undefined;
let activeProviders: Providers | undefined;

export async function activate(context: vscode.ExtensionContext) {
    console.log('Agent OS extension activating...');

    try {
        // Initialize core components
        console.log('Initializing core components...');
        policyEngine = new PolicyEngine();
        cmvkClient = new CMVKClient();
        auditLogger = new AuditLogger(context);
        statusBar = new StatusBarManager();

        // Initialize enterprise components
        console.log('Initializing enterprise components...');
        authProvider = new EnterpriseAuthProvider(context);
        rbacManager = new RBACManager(authProvider);
        cicdIntegration = new CICDIntegration();
        complianceManager = new ComplianceManager();
        diagnosticProvider = new AgentOSDiagnosticProvider();
        governanceDiagnosticProvider = new GovernanceDiagnosticProvider();
        governanceStatusBar = new GovernanceStatusBar();

        // Log RBAC initialization
        console.log(`RBAC initialized with ${rbacManager.getAllRoles().length} roles`);

        // Create tree data providers
        console.log('Creating tree data providers...');
        const auditLogProvider = new AuditLogProvider(auditLogger);
        const policiesProvider = new PoliciesProvider(policyEngine);
        const statsProvider = new StatsProvider(auditLogger);
        const kernelDebuggerProvider = new KernelDebuggerProvider();
        const memoryBrowserProvider = new MemoryBrowserProvider();

        // Tree data providers are kept as data sources but no longer registered as views.
        // The new SidebarProvider aggregates their data into a single webview.

        // Register governance visualization (Issue #39)
        const govConfig = vscode.workspace.getConfiguration('agentOS.governance');
        const providerConfig: ProviderConfig = {
            pythonPath: govConfig.get<string>('pythonPath', 'python'),
            endpoint: govConfig.get<string>('endpoint', ''),
            refreshIntervalMs: govConfig.get<number>('refreshIntervalMs', 10000),
        };
        activeProviders = await createProviders(providerConfig);
        const sloDataProvider = activeProviders.slo;
        const sloDashboardProvider = new SLODashboardProvider(sloDataProvider);
        const agentTopologyDataProvider = activeProviders.topology;
        const agentTopologyProvider = new AgentTopologyProvider(agentTopologyDataProvider);
        const policyDataProvider = activeProviders.policy;

    // Register 3-slot sidebar webview (Sidebar Redesign)
    const governanceEventBus = new GovernanceEventBus();
    const governanceStore = new GovernanceStore(
        {
            slo: sloDataProvider, topology: agentTopologyDataProvider,
            audit: auditLogger, policy: policyDataProvider,
            kernel: kernelDebuggerProvider, memory: memoryBrowserProvider,
        },
        governanceEventBus,
        context.workspaceState,
        providerConfig.refreshIntervalMs ?? 10000,
    );
    sidebarProvider = new SidebarProvider(
        context.extensionUri,
        context,
        governanceStore,
    );
    context.subscriptions.push(governanceStore);
    context.subscriptions.push(governanceEventBus);
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider(
            SidebarProvider.viewType,
            sidebarProvider,
        )
    );

    // Register completion and hover providers for IntelliSense
    const completionProvider = new AgentOSCompletionProvider();
    const hoverProvider = new AgentOSHoverProvider();
    
    context.subscriptions.push(
        vscode.languages.registerCompletionItemProvider(
            [
                { scheme: 'file', language: 'python' },
                { scheme: 'file', language: 'javascript' },
                { scheme: 'file', language: 'typescript' },
                { scheme: 'file', language: 'yaml' },
                { scheme: 'file', language: 'json' }
            ],
            completionProvider,
            '.', ':', '"', "'"
        ),
        vscode.languages.registerHoverProvider(
            [
                { scheme: 'file', language: 'python' },
                { scheme: 'file', language: 'javascript' },
                { scheme: 'file', language: 'typescript' },
                { scheme: 'file', language: 'yaml' }
            ],
            hoverProvider
        )
    );

    // Activate diagnostic providers
    diagnosticProvider.activate(context);
    governanceDiagnosticProvider.activate(context);

    // Initialize governance status bar with defaults
    const mode = vscode.workspace.getConfiguration('agentOS').get<string>('mode', 'basic');
    const GOVERNANCE_LEVEL_MAP: Record<string, 'strict' | 'permissive' | 'audit-only'> = {
        enterprise: 'strict',
        enhanced: 'permissive',
    };
    const governanceLevel = GOVERNANCE_LEVEL_MAP[mode] ?? 'audit-only';
    governanceStatusBar.updateGovernanceMode(governanceLevel, 0);

    // Register inline completion interceptor
    const completionInterceptor = vscode.languages.registerInlineCompletionItemProvider(
        { pattern: '**' },
        {
            async provideInlineCompletionItems(
                _document: vscode.TextDocument,
                _position: vscode.Position,
                _context: vscode.InlineCompletionContext,
                _token: vscode.CancellationToken
            ): Promise<vscode.InlineCompletionItem[] | null> {
                // We don't provide completions - we intercept and validate existing ones
                // This hook allows us to log what completions are being suggested
                return null;
            }
        }
    );

    // Register document change listener to analyze pasted/typed code
    const textChangeListener = vscode.workspace.onDidChangeTextDocument(async (event) => {
        if (!isEnabled()) { return; }

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

    // ========================================
    // Register Core Commands
    // ========================================
    
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

    // ========================================
    // Register GA Feature Commands
    // ========================================

    // Policy Editor
    const openPolicyEditorCmd = vscode.commands.registerCommand('agent-os.openPolicyEditor', () => {
        PolicyEditorPanel.createOrShow(context.extensionUri);
    });

    // Workflow Designer
    const openWorkflowDesignerCmd = vscode.commands.registerCommand('agent-os.openWorkflowDesigner', () => {
        WorkflowDesignerPanel.createOrShow(context.extensionUri);
    });

    // Metrics Dashboard
    const showMetricsCmd = vscode.commands.registerCommand('agent-os.showMetrics', () => {
        MetricsDashboardPanel.createOrShow(context.extensionUri, auditLogger);
    });

    // Onboarding
    const showOnboardingCmd = vscode.commands.registerCommand('agent-os.showOnboarding', () => {
        OnboardingPanel.createOrShow(context.extensionUri, context);
    });

    // Template Gallery - create first agent
    const createFirstAgentCmd = vscode.commands.registerCommand('agent-os.createFirstAgent', async () => {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) {
            vscode.window.showErrorMessage('Please open a workspace folder first');
            return;
        }

        const agentCode = `"""
My First Governed Agent

This agent is protected by Agent OS with kernel-level safety guarantees.
"""

from agent_os import KernelSpace

# Create kernel with strict policy
kernel = KernelSpace(policy="strict")

@kernel.register
async def my_first_agent(task: str):
    """A simple agent that processes tasks safely."""
    # Your agent code here
    # All operations are checked against policies
    result = f"Processed: {task}"
    return result

if __name__ == "__main__":
    import asyncio
    result = asyncio.run(kernel.execute(my_first_agent, "Hello Agent OS!"))
    print(result)
`;

        const uri = vscode.Uri.joinPath(workspaceFolder.uri, 'my_first_agent.py');
        await vscode.workspace.fs.writeFile(uri, Buffer.from(agentCode));
        const doc = await vscode.workspace.openTextDocument(uri);
        await vscode.window.showTextDocument(doc);
        vscode.window.showInformationMessage('Created your first governed agent! 🎉');
    });

    // Safety Test
    const runSafetyTestCmd = vscode.commands.registerCommand('agent-os.runSafetyTest', async () => {
        const testCode = `# Agent OS Safety Test
# This demonstrates how Agent OS blocks dangerous operations

# Test 1: SQL Injection - WILL BE BLOCKED
query = "SELECT * FROM users WHERE id = " + user_input

# Test 2: Hardcoded Secret - WILL BE BLOCKED  
api_key = "sk-EXAMPLE-NOT-A-REAL-KEY-replace-with-your-own"

# Test 3: Destructive Command - WILL BE BLOCKED
import os
os.system("rm -rf /important")

# Test 4: Safe Code - WILL BE ALLOWED
safe_query = "SELECT * FROM users WHERE id = ?"
`;
        const doc = await vscode.workspace.openTextDocument({
            language: 'python',
            content: testCode
        });
        await vscode.window.showTextDocument(doc);
        vscode.window.showInformationMessage(
            'Safety test file created! Notice the diagnostics highlighting dangerous code.',
            'View Diagnostics'
        );
    });

    // Open Documentation
    const openDocsCmd = vscode.commands.registerCommand('agent-os.openDocs', () => {
        vscode.env.openExternal(vscode.Uri.parse('https://github.com/microsoft/agent-governance-toolkit'));
    });

    // ========================================
    // Register Governance Visualization Commands (Issue #39)
    // ========================================

    const showSLODashboardCmd = vscode.commands.registerCommand('agent-os.showSLODashboard', () => {
        vscode.commands.executeCommand('agent-os.sloDashboard.focus');
    });

    const showAgentTopologyCmd = vscode.commands.registerCommand('agent-os.showAgentTopology', () => {
        vscode.commands.executeCommand('agent-os.agentTopology.focus');
    });

    const refreshSLOCmd = vscode.commands.registerCommand('agent-os.refreshSLO', () => {
        sloDashboardProvider.refresh();
    });

    const refreshTopologyCmd = vscode.commands.registerCommand('agent-os.refreshTopology', () => {
        agentTopologyProvider.refresh();
    });

    // Governance Webview Panels (Issue #39 - Rich Visualization)
    const showSLOWebviewCmd = vscode.commands.registerCommand('agent-os.showSLOWebview', () => {
        SLODashboardPanel.createOrShow(context.extensionUri, sloDataProvider);
    });

    const showTopologyGraphCmd = vscode.commands.registerCommand('agent-os.showTopologyGraph', () => {
        TopologyGraphPanel.createOrShow(context.extensionUri, agentTopologyDataProvider);
    });

    // Governance Hub Panel (Issue #39 - Unified Dashboard)
    const showGovernanceHubCmd = vscode.commands.registerCommand('agent-os.showGovernanceHub', () => {
        GovernanceHubPanel.createOrShow(
            context.extensionUri,
            sloDataProvider,
            agentTopologyDataProvider,
            auditLogger,
            policyDataProvider
        );
    });

    // Agent Drill-Down Command (Dashboard Feature Completeness - Phase 2)
    const showAgentDetailsCmd = vscode.commands.registerCommand(
        'agent-os.showAgentDetails',
        async (did: string) => {
            const agents = agentTopologyDataProvider.getAgents();
            const agent = agents.find(a => a.did === did);
            if (!agent) {
                vscode.window.showWarningMessage(`Agent not found: ${did}`);
                return;
            }

            const ringLabels: Record<number, string> = {
                0: 'Ring 0 (Root)',
                1: 'Ring 1 (Trusted)',
                2: 'Ring 2 (Standard)',
                3: 'Ring 3 (Sandbox)',
            };

            const items: vscode.QuickPickItem[] = [
                { label: '$(key) DID', description: agent.did },
                { label: '$(shield) Trust Score', description: `${agent.trustScore} / 1000` },
                { label: '$(layers) Execution Ring', description: ringLabels[agent.ring] || `Ring ${agent.ring}` },
                { label: '$(clock) Registered', description: agent.registeredAt || 'Unknown' },
                { label: '$(pulse) Last Activity', description: agent.lastActivity || 'Unknown' },
                { label: '$(tools) Capabilities', description: agent.capabilities?.join(', ') || 'None' },
            ];

            await vscode.window.showQuickPick(items, {
                title: `Agent: ${did.slice(0, 24)}...`,
                placeHolder: 'Agent details',
            });
        }
    );

    // Audit CSV Export Command (Dashboard Feature Completeness - Phase 3)
    const exportAuditCSVCmd = vscode.commands.registerCommand(
        'agent-os.exportAuditCSV',
        async () => {
            const entries = auditLogger.getAll();
            if (entries.length === 0) {
                vscode.window.showInformationMessage('No audit entries to export');
                return;
            }

            const csv = [
                'Timestamp,Type,File,Language,Violation,Reason',
                ...entries.map(e => {
                    const entry = e as { timestamp: Date; type: string; file?: string; language?: string; violation?: string; reason?: string };
                    return [
                        entry.timestamp.toISOString(),
                        entry.type,
                        entry.file || '',
                        entry.language || '',
                        (entry.violation || '').replace(/,/g, ';'),
                        (entry.reason || '').replace(/,/g, ';'),
                    ].join(',');
                })
            ].join('\n');

            const uri = await vscode.window.showSaveDialog({
                defaultUri: vscode.Uri.file(`audit-log-${Date.now()}.csv`),
                filters: { 'CSV': ['csv'] },
            });

            if (uri) {
                await vscode.workspace.fs.writeFile(uri, Buffer.from(csv, 'utf-8'));
                vscode.window.showInformationMessage(`Exported ${entries.length} entries to ${uri.fsPath}`);
            }
        }
    );

    // Browser Experience Commands (Issue #39 - Local Dev Server)
    const openGovernanceInBrowserCmd = vscode.commands.registerCommand(
        'agent-os.openGovernanceInBrowser',
        async () => {
            governanceServer = GovernanceServer.getInstance(
                sloDataProvider,
                agentTopologyDataProvider,
                auditLogger
            );
            const port = await governanceServer.start();
            const url = `http://localhost:${port}`;
            vscode.env.openExternal(vscode.Uri.parse(url));
        }
    );

    const openSLOInBrowserCmd = vscode.commands.registerCommand(
        'agent-os.openSLOInBrowser',
        async () => {
            governanceServer = GovernanceServer.getInstance(
                sloDataProvider,
                agentTopologyDataProvider,
                auditLogger
            );
            const port = await governanceServer.start();
            const url = `http://localhost:${port}/#slo`;
            vscode.env.openExternal(vscode.Uri.parse(url));
        }
    );

    const openTopologyInBrowserCmd = vscode.commands.registerCommand(
        'agent-os.openTopologyInBrowser',
        async () => {
            governanceServer = GovernanceServer.getInstance(
                sloDataProvider,
                agentTopologyDataProvider,
                auditLogger
            );
            const port = await governanceServer.start();
            const url = `http://localhost:${port}/#topology`;
            vscode.env.openExternal(vscode.Uri.parse(url));
        }
    );

    // Export Report Command (Issue #39 - Shareable Reports)
    const exportReportCmd = vscode.commands.registerCommand(
        'agent-os.exportReport',
        async () => {
            const config = vscode.workspace.getConfiguration('agentOS.export');
            const localPath = config.get<string>('localPath', '');
            const outputDir = localPath || vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '';
            const provider = new LocalStorageProvider(outputDir);

            // Zero-trust: validate on every export
            try {
                await provider.validateCredentials();
            } catch (e) {
                if (e instanceof CredentialError) {
                    const action = await vscode.window.showErrorMessage(
                        `Storage credentials ${e.reason}: ${e.message}`,
                        'Configure'
                    );
                    if (action === 'Configure') {
                        vscode.commands.executeCommand(
                            'workbench.action.openSettings',
                            `agentOS.export.${e.provider}`
                        );
                    }
                    return;
                }
                throw e;
            }

            // Generate report
            const reportGenerator = new ReportGenerator();
            const sloSnapshot = await sloDataProvider.getSnapshot();
            const agents = agentTopologyDataProvider.getAgents();
            const bridges = agentTopologyDataProvider.getBridges();
            const delegations = agentTopologyDataProvider.getDelegations();
            const auditEntries = auditLogger.getAll().map(e => ({
                timestamp: new Date(),
                type: 'audit',
                details: e as unknown as Record<string, unknown>
            }));

            const report = reportGenerator.generate({
                sloSnapshot,
                agents,
                bridges,
                delegations,
                auditEvents: auditEntries,
                timeRange: { start: new Date(Date.now() - 86400000), end: new Date() }
            });

            const result = await provider.upload(
                report,
                `governance-report-${Date.now()}.html`
            );

            const action = await vscode.window.showInformationMessage(
                `Report saved: ${result.url}`,
                'Open'
            );
            if (action === 'Open') {
                vscode.env.openExternal(vscode.Uri.parse(result.url));
            }
        }
    );

    // ========================================
    // Register Enterprise Commands
    // ========================================

    // SSO Sign In
    const signInCmd = vscode.commands.registerCommand('agent-os.signIn', () => {
        authProvider.signIn();
    });

    // SSO Sign Out
    const signOutCmd = vscode.commands.registerCommand('agent-os.signOut', () => {
        authProvider.signOut();
    });

    // CI/CD Integration
    const setupCICDCmd = vscode.commands.registerCommand('agent-os.setupCICD', () => {
        cicdIntegration.showConfigWizard();
    });

    // Pre-commit Hook
    const installHooksCmd = vscode.commands.registerCommand('agent-os.installHooks', () => {
        cicdIntegration.installPreCommitHook();
    });

    // Compliance Check
    const checkComplianceCmd = vscode.commands.registerCommand('agent-os.checkCompliance', () => {
        complianceManager.showComplianceWizard();
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
        configChangeListener,
        statusBar,
        // GA Features
        openPolicyEditorCmd,
        openWorkflowDesignerCmd,
        showMetricsCmd,
        showOnboardingCmd,
        createFirstAgentCmd,
        runSafetyTestCmd,
        openDocsCmd,
        // Governance Visualization
        showSLOWebviewCmd,
        showTopologyGraphCmd,
        showSLODashboardCmd,
        showAgentTopologyCmd,
        refreshSLOCmd,
        refreshTopologyCmd,
        sidebarProvider!,
        governanceStatusBar,
        // Governance Hub & Browser Experience
        showGovernanceHubCmd,
        showAgentDetailsCmd,
        exportAuditCSVCmd,
        openGovernanceInBrowserCmd,
        openSLOInBrowserCmd,
        openTopologyInBrowserCmd,
        exportReportCmd,
        // Enterprise Features
        signInCmd,
        signOutCmd,
        setupCICDCmd,
        installHooksCmd,
        checkComplianceCmd
    );

    // Initialize status bar
    statusBar.update(isEnabled());

    // Show onboarding for first-time users
    const hasShownWelcome = context.globalState.get('agent-os.welcomeShown', false);
    const onboardingSkipped = context.globalState.get('agent-os.onboardingSkipped', false);
    
    if (!hasShownWelcome && !onboardingSkipped) {
        // Show onboarding panel for new users
        OnboardingPanel.createOrShow(context.extensionUri, context);
        context.globalState.update('agent-os.welcomeShown', true);
    } else if (!hasShownWelcome) {
        showWelcomeMessage();
        context.globalState.update('agent-os.welcomeShown', true);
    }

    console.log('Agent OS extension activated - GA Release v1.0.0');
    } catch (error) {
        console.error('Agent OS extension activation failed:', error);
        vscode.window.showErrorMessage(`Agent OS failed to activate: ${error}`);
    }
}

export async function deactivate() {
    // Clean up governance server if running
    if (governanceServer) {
        await governanceServer.stop();
        governanceServer = undefined;
    }

    // Clean up sidebar provider
    if (sidebarProvider) {
        sidebarProvider.dispose();
        sidebarProvider = undefined;
    }
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
        if (result.suggestion) {
            actions.push('Use Alternative');
        }

        const selection = await vscode.window.showWarningMessage(
            `⚠️ Agent OS blocked: ${result.reason}`,
            ...actions
        );

        if (selection === 'Review Policy') {
            await openPolicyConfiguration();
        } else if (selection === 'Allow Once') {
            policyEngine.allowOnce(result.violation);
        } else if (selection === 'Use Alternative' && result.suggestion) {
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
        'Welcome to Agent OS! Your AI coding assistant is now protected.',
        'Configure Policies',
        'Learn More'
    ).then(selection => {
        if (selection === 'Configure Policies') {
            openPolicyConfiguration();
        } else if (selection === 'Learn More') {
            vscode.env.openExternal(vscode.Uri.parse('https://github.com/microsoft/agent-governance-toolkit'));
        }
    });
}
