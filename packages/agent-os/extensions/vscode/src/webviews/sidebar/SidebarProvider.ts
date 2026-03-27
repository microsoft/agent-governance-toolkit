// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Sidebar Provider
 *
 * WebviewViewProvider for the 3-slot governance sidebar.
 * Delegates data fetching to dataAggregator and pushes unified
 * SidebarState to the React webview.
 */

import * as vscode from 'vscode';
import * as crypto from 'crypto';
import { SLODataProvider } from '../../views/sloTypes';
import { AgentTopologyDataProvider } from '../../views/topologyTypes';
import { PolicyDataProvider } from '../../views/policyTypes';
import {
    PanelId,
    SlotConfig,
    SidebarState,
    WebviewMessage,
    DEFAULT_SLOTS,
} from './types';
import { DataProviders, fetchAllData } from './dataAggregator';

/** Audit logger interface for dependency injection. */
export interface AuditLoggerLike {
    getAll(): unknown[];
    getStats(): {
        blockedToday: number;
        blockedThisWeek: number;
        warningsToday: number;
        cmvkReviewsToday: number;
        totalLogs: number;
    };
}

/** Kernel state interface for dependency injection. */
export interface KernelStateLike {
    getKernelSummary(): {
        activeAgents: number;
        policyViolations: number;
        totalCheckpoints: number;
        uptime: number;
    };
}

/** VFS state interface for dependency injection. */
export interface MemoryBrowserLike {
    getVfsSummary(): {
        directoryCount: number;
        fileCount: number;
        rootPaths: string[];
    };
}

/** Map of PanelId to the VS Code command that opens its full webview. */
const PROMOTE_COMMANDS: Record<PanelId, string> = {
    'slo-dashboard': 'agent-os.showSLOWebview',
    'agent-topology': 'agent-os.showTopologyGraph',
    'governance-hub': 'agent-os.showGovernanceHub',
    'audit-log': 'agent-os.showGovernanceHub',
    'active-policies': 'agent-os.openPolicyEditor',
    'safety-stats': 'agent-os.showGovernanceHub',
    'kernel-debugger': 'agent-os.showGovernanceHub',
    'memory-browser': 'agent-os.showGovernanceHub',
};

const SLOT_CONFIG_KEY = 'agentOS.slotConfig';

/**
 * Provides the 3-slot governance sidebar as a single webview.
 */
export class SidebarProvider implements vscode.WebviewViewProvider, vscode.Disposable {

    public static readonly viewType = 'agent-os.sidebar';

    private _view: vscode.WebviewView | undefined;
    private _refreshInterval: ReturnType<typeof setInterval> | undefined;
    private _fetching = false;
    private _state: SidebarState;
    private readonly _providers: DataProviders;

    constructor(
        private readonly _extensionUri: vscode.Uri,
        private readonly _context: vscode.ExtensionContext,
        sloProvider: SLODataProvider,
        topologyProvider: AgentTopologyDataProvider,
        auditLogger: AuditLoggerLike,
        policyProvider: PolicyDataProvider,
        kernelState: KernelStateLike,
        memoryBrowser: MemoryBrowserLike,
    ) {
        this._providers = {
            slo: sloProvider,
            topology: topologyProvider,
            audit: auditLogger,
            policy: policyProvider,
            kernel: kernelState,
            memory: memoryBrowser,
        };
        const persisted = _context.workspaceState.get<SlotConfig>(SLOT_CONFIG_KEY);
        this._state = {
            slots: persisted ?? DEFAULT_SLOTS,
            slo: null, audit: null, topology: null,
            policy: null, stats: null, kernel: null, memory: null, hub: null,
        };
    }

    public resolveWebviewView(
        webviewView: vscode.WebviewView,
        _context: vscode.WebviewViewResolveContext,
        _token: vscode.CancellationToken,
    ): void {
        this._view = webviewView;
        webviewView.webview.options = {
            enableScripts: true,
            localResourceRoots: [vscode.Uri.joinPath(this._extensionUri, 'out', 'webviews')],
        };
        this._setWebviewContent();
        this._registerListeners(webviewView);
        this._startAutoRefresh();
    }

    private _setWebviewContent(): void {
        if (!this._view) { return; }
        const webview = this._view.webview;
        const nonce = crypto.randomBytes(16).toString('hex');
        const scriptUri = webview.asWebviewUri(
            vscode.Uri.joinPath(this._extensionUri, 'out', 'webviews', 'sidebar', 'main.js'),
        );
        const styleUri = webview.asWebviewUri(
            vscode.Uri.joinPath(this._extensionUri, 'out', 'webviews', 'index.css'),
        );
        // CSP: unsafe-inline required for Tailwind utility injection
        webview.html = /* html */ `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta http-equiv="Content-Security-Policy"
          content="default-src 'none';
                   style-src ${webview.cspSource} 'unsafe-inline';
                   script-src 'nonce-${nonce}';
                   font-src ${webview.cspSource};" />
    <link rel="stylesheet" href="${styleUri}" />
    <title>Agent OS Sidebar</title>
</head>
<body>
    <div id="root"></div>
    <script nonce="${nonce}" src="${scriptUri}"></script>
</body>
</html>`;
    }

    private _registerListeners(webviewView: vscode.WebviewView): void {
        webviewView.onDidChangeVisibility(() => {
            if (webviewView.visible) { this._pushState(); }
        });
        webviewView.webview.onDidReceiveMessage((msg: WebviewMessage) => {
            this._handleMessage(msg);
        });
    }

    private _handleMessage(message: WebviewMessage): void {
        switch (message.type) {
            case 'ready':
                this._fetchAndPush();
                break;
            case 'setSlots':
                this._state = { ...this._state, slots: message.slots };
                this._context.workspaceState.update(SLOT_CONFIG_KEY, message.slots);
                this._pushState();
                break;
            case 'promotePanelToWebview': {
                const cmd = PROMOTE_COMMANDS[message.panelId];
                if (cmd) { vscode.commands.executeCommand(cmd); }
                break;
            }
            case 'refresh':
                this._fetchAndPush();
                break;
        }
    }

    private async _fetchAndPush(): Promise<void> {
        if (this._fetching) { return; }
        this._fetching = true;
        try {
            this._state = await fetchAllData(this._providers, this._state);
            this._pushState();
        } finally {
            this._fetching = false;
        }
    }

    private _pushState(): void {
        if (!this._view?.visible) { return; }
        this._view.webview.postMessage({ type: 'stateUpdate', state: this._state });
    }

    private _startAutoRefresh(): void {
        this._refreshInterval = setInterval(() => {
            if (this._view?.visible) { this._fetchAndPush(); }
        }, 10_000);
    }

    public dispose(): void {
        if (this._refreshInterval) {
            clearInterval(this._refreshInterval);
            this._refreshInterval = undefined;
        }
    }
}
