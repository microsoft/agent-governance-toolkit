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
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
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
import { GovernanceStatusBar } from './governanceStatusBar';

// Governance Webview Panels — React detail panels (D1 migration)
import { showSLODetail } from './webviews/sloDetail/SLODetailPanel';
import { showTopologyDetail } from './webviews/topologyDetail/TopologyDetailPanel';
import { showHubDetail } from './webviews/hubDetail/HubDetailPanel';
import { showKernelDetail } from './webviews/kernelDetail/KernelDetailPanel';
import { showMemoryDetail } from './webviews/memoryDetail/MemoryDetailPanel';
import { showStatsDetail } from './webviews/statsDetail/StatsDetailPanel';
import { showAuditDetail } from './webviews/auditDetail/AuditDetailPanel';
import { showPolicyDetail } from './webviews/policyDetail/PolicyDetailPanel';

// 3-Slot Sidebar (Sidebar Redesign)
import { SidebarProvider } from './webviews/sidebar/SidebarProvider';
import { GovernanceEventBus } from './webviews/sidebar/governanceEventBus';
import { GovernanceStore } from './webviews/sidebar/GovernanceStore';
import type { DataProviders } from './webviews/sidebar/dataAggregator';

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
import { SLODataProvider } from './views/sloTypes';
import { AgentTopologyDataProvider } from './views/topologyTypes';

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
        context.subscriptions.push(kernelDebuggerProvider);
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

    // Register 3-slot sidebar SYNCHRONOUSLY with empty providers so the
    // webview view provider is available immediately — before the async
    // createProviders() call which can block or throw.
    const governanceEventBus = new GovernanceEventBus();
    const emptyProviders: DataProviders = {
        slo: { getSnapshot: async () => ({ availability: { currentPercent: 0, targetPercent: 0, errorBudgetRemainingPercent: 0, burnRate: 0 }, latency: { p50Ms: 0, p95Ms: 0, p99Ms: 0, targetMs: 0, errorBudgetRemainingPercent: 0 }, policyCompliance: { totalEvaluations: 0, violationsToday: 0, compliancePercent: 0, trend: 'stable' as const }, trustScore: { meanScore: 0, minScore: 0, agentsBelowThreshold: 0, distribution: [0, 0, 0, 0] } }) },
        topology: { getAgents: () => [], getBridges: () => [], getDelegations: () => [] },
        audit: auditLogger,
        policy: { getSnapshot: async () => ({ rules: [], recentViolations: [], totalEvaluationsToday: 0, totalViolationsToday: 0 }) },
        kernel: kernelDebuggerProvider,
        memory: memoryBrowserProvider,
    };
    const governanceStore = new GovernanceStore(
        emptyProviders,
        governanceEventBus,
        context.workspaceState,
        providerConfig.refreshIntervalMs ?? 10000,
        undefined,  // thresholdMs
        undefined,  // liveClient — wired after createProviders resolves
        auditLogger,
    );
    sidebarProvider = new SidebarProvider(
        context.extensionUri,
        context,
        governanceStore,
    );
    context.subscriptions.push(governanceStore);
    context.subscriptions.push(governanceEventBus);
    context.subscriptions.push(auditLogger);
    context.subscriptions.push(
        vscode.window.registerWebviewViewProvider(
            SidebarProvider.viewType,
            sidebarProvider,
        )
    );

    // Async: connect live providers in background (non-blocking)
    createProviders(providerConfig).then((providers) => {
        activeProviders = providers;
        context.subscriptions.push(providers);
        governanceStore.upgradeProviders(
            {
                slo: providers.slo, topology: providers.topology,
                audit: auditLogger, policy: providers.policy,
                kernel: kernelDebuggerProvider, memory: memoryBrowserProvider,
            },
            providers.liveClient ?? undefined,
            auditLogger,
        );
    }).catch((err) => {
        console.warn('Agent OS: live providers unavailable, using disconnected mode:', err);
    });

    // Provider proxies — commands read from activeProviders when available,
    // falling back to empty defaults. This avoids blocking activation.
    const sloDataProvider: SLODataProvider = {
        getSnapshot: () => (activeProviders?.slo ?? emptyProviders.slo).getSnapshot(),
    };
    const agentTopologyDataProvider: AgentTopologyDataProvider = {
        getAgents: () => (activeProviders?.topology ?? emptyProviders.topology).getAgents(),
        getBridges: () => (activeProviders?.topology ?? emptyProviders.topology).getBridges(),
        getDelegations: () => (activeProviders?.topology ?? emptyProviders.topology).getDelegations(),
    };
    const policyDataProvider: PolicyDataProvider = {
        getSnapshot: () => (activeProviders?.policy ?? emptyProviders.policy).getSnapshot(),
    };

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

    const refreshSLOCmd = vscode.commands.registerCommand('agent-os.refreshSLO', () => {
        governanceStore.refreshNow();
    });

    const refreshTopologyCmd = vscode.commands.registerCommand('agent-os.refreshTopology', () => {
        governanceStore.refreshNow();
    });

    // Governance Webview Panels — React detail panels (D1 migration)
    const showSLOWebviewCmd = vscode.commands.registerCommand('agent-os.showSLOWebview', () => {
        showSLODetail(context.extensionUri, governanceStore);
    });

    const showTopologyGraphCmd = vscode.commands.registerCommand('agent-os.showTopologyGraph', () => {
        showTopologyDetail(context.extensionUri, governanceStore);
    });

    const showGovernanceHubCmd = vscode.commands.registerCommand('agent-os.showGovernanceHub', () => {
        showHubDetail(context.extensionUri, governanceStore);
    });

    const showKernelDebuggerCmd = vscode.commands.registerCommand('agent-os.showKernelDebugger', () => {
        showKernelDetail(context.extensionUri, governanceStore);
    });

    const showMemoryBrowserCmd = vscode.commands.registerCommand('agent-os.showMemoryBrowser', () => {
        showMemoryDetail(context.extensionUri, governanceStore);
    });

    const showSafetyStatsCmd = vscode.commands.registerCommand('agent-os.showSafetyStats', () => {
        showStatsDetail(context.extensionUri, governanceStore);
    });

    const showAuditDetailCmd = vscode.commands.registerCommand('agent-os.showAuditDetail', () => {
        showAuditDetail(context.extensionUri, governanceStore);
    });

    const showPolicyDetailCmd = vscode.commands.registerCommand('agent-os.showPolicyDetail', () => {
        showPolicyDetail(context.extensionUri, governanceStore);
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
                auditLogger,
                policyDataProvider,
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
                auditLogger,
                policyDataProvider,
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
                auditLogger,
                policyDataProvider,
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
    // Help Command
    // ========================================

    const showHelpCmd = vscode.commands.registerCommand('agent-os.showHelp', () => {
        const panel = vscode.window.createWebviewPanel(
            'agent-os.help', 'Agent OS Help', vscode.ViewColumn.Beside,
            { enableScripts: false, localResourceRoots: [] },
        );
        const helpPath = path.join(context.extensionPath, 'HELP.md');
        let content = '';
        try { content = fs.readFileSync(helpPath, 'utf8'); } catch { content = '# Help\n\nHelp file not found.'; }
        panel.webview.html = renderMarkdownHtml(content);
    });

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
        refreshSLOCmd,
        refreshTopologyCmd,
        sidebarProvider!,
        governanceStatusBar,
        // Governance Hub & Browser Experience
        showGovernanceHubCmd,
        showKernelDebuggerCmd,
        showMemoryBrowserCmd,
        showSafetyStatsCmd,
        showAuditDetailCmd,
        showPolicyDetailCmd,
        showAgentDetailsCmd,
        exportAuditCSVCmd,
        openGovernanceInBrowserCmd,
        openSLOInBrowserCmd,
        openTopologyInBrowserCmd,
        exportReportCmd,
        // Help
        showHelpCmd,
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

            panel.webview.html = generateCMVKResultsHTML(result, panel.webview);

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

function generateCMVKResultsHTML(result: any, webview: vscode.Webview): string {
    const nonce = crypto.randomBytes(16).toString('base64');
    const cspSource = webview.cspSource;

    const consensusColor = result.consensus >= 0.8 ? '#28a745'
        : result.consensus >= 0.5 ? '#ffc107' 
        : '#dc3545';

    const modelRows = result.modelResults.map((m: any) => `
        <tr>
            <td>${m.passed ? '✅' : '⚠️'}</td>
            <td><strong>${escHtml(String(m.model))}</strong></td>
            <td>${escHtml(String(m.summary))}</td>
        </tr>
    `).join('');

    const issuesList = result.issues.length > 0
        ? `<ul>${result.issues.map((i: string) => `<li>${escHtml(i)}</li>`).join('')}</ul>`
        : '<p>No issues detected</p>';

    return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}'; img-src ${cspSource} https:; font-src ${cspSource};">
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
                ${escHtml(String(result.recommendations))}
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

/** Escape HTML entities for safe rendering. */
function escHtml(s: string): string { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

/** Apply inline Markdown formatting (bold, code). */
function inlineMdFormat(s: string): string {
    let out = escHtml(s);
    out = out.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    return out.replace(/`(.+?)`/g, '<code>$1</code>');
}

/** CSS for the help panel webview. */
const HELP_CSS = [
    'body{font-family:var(--vscode-font-family);color:var(--vscode-foreground);background:var(--vscode-editor-background);padding:20px;line-height:1.6}',
    'h1{font-size:1.4em;border-bottom:1px solid var(--vscode-panel-border);padding-bottom:8px}',
    'h2{font-size:1.2em;margin-top:24px} h3{font-size:1.05em;margin-top:16px}',
    'table{width:100%;border-collapse:collapse;margin:12px 0}',
    'th,td{padding:6px 10px;border:1px solid var(--vscode-panel-border);text-align:left}',
    'th{background:var(--vscode-sideBar-background)}',
    'code{background:var(--vscode-textCodeBlock-background);padding:2px 4px;border-radius:3px;font-family:var(--vscode-editor-font-family)}',
    'ul{padding-left:20px;margin:8px 0} li{margin:4px 0}',
].join('\n');

/** Convert Markdown text to a simple themed HTML document. */
function renderMarkdownHtml(md: string): string {
    const out: string[] = [];
    let inList = false, inTable = false;
    function close(): void {
        if (inList) { out.push('</ul>'); inList = false; }
        if (inTable) { out.push('</table>'); inTable = false; }
    }
    for (const line of md.split('\n')) {
        const t = line.trim();
        if (t.startsWith('### ')) { close(); out.push(`<h3>${escHtml(t.slice(4))}</h3>`); }
        else if (t.startsWith('## ')) { close(); out.push(`<h2>${escHtml(t.slice(3))}</h2>`); }
        else if (t.startsWith('# ')) { close(); out.push(`<h1>${escHtml(t.slice(2))}</h1>`); }
        else if (t.startsWith('| ')) {
            const cells = t.split('|').filter(c => c.trim() !== '');
            if (!cells.every(c => /^[\s-:]+$/.test(c))) {
                const tag = !inTable ? 'th' : 'td';
                if (!inTable) { out.push('<table>'); inTable = true; }
                out.push('<tr>' + cells.map(c => `<${tag}>${inlineMdFormat(c.trim())}</${tag}>`).join('') + '</tr>');
            }
        } else if (t.startsWith('- ')) {
            if (!inList) { out.push('<ul>'); inList = true; }
            out.push(`<li>${inlineMdFormat(t.slice(2))}</li>`);
        } else if (t === '') { close(); }
        else { close(); out.push(`<p>${inlineMdFormat(t)}</p>`); }
    }
    close();
    return `<!DOCTYPE html><html lang="en"><head><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';"><style>${HELP_CSS}</style></head><body>${out.join('\n')}</body></html>`;
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
