// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Sidebar Provider
 *
 * Thin webview lifecycle bridge for the 3-slot governance sidebar.
 * Delegates all state management to GovernanceStore.
 */

import * as vscode from 'vscode';
import * as crypto from 'crypto';
import type { PanelId, WebviewMessage } from './types';
import { GovernanceStore } from './GovernanceStore';
import type { Disposable } from './governanceEventBus';

/** Map of PanelId to the VS Code command that opens its full webview. */
const PROMOTE_COMMANDS: Record<PanelId, string> = {
    'slo-dashboard': 'agent-os.showSLOWebview',
    'agent-topology': 'agent-os.showTopologyGraph',
    'governance-hub': 'agent-os.showGovernanceHub',
    'audit-log': 'agent-os.showAuditDetail',
    'active-policies': 'agent-os.openPolicyEditor',
    'safety-stats': 'agent-os.showSafetyStats',
    'kernel-debugger': 'agent-os.showKernelDebugger',
    'memory-browser': 'agent-os.showMemoryBrowser',
};

/**
 * Provides the 3-slot governance sidebar as a single webview.
 * All state owned by GovernanceStore; this class manages the webview lifecycle.
 */
export class SidebarProvider implements vscode.WebviewViewProvider, vscode.Disposable {

    public static readonly viewType = 'agent-os.sidebar';

    private _view: vscode.WebviewView | undefined;
    private _storeSubscription: Disposable | undefined;

    constructor(
        private readonly _extensionUri: vscode.Uri,
        private readonly _context: vscode.ExtensionContext,
        private readonly _store: GovernanceStore,
    ) {}

    public resolveWebviewView(
        webviewView: vscode.WebviewView,
        _context: vscode.WebviewViewResolveContext,
        _token: vscode.CancellationToken,
    ): void {
        // Dispose previous subscription on re-resolve (W7 fix)
        this._storeSubscription?.dispose();
        this._view = webviewView;
        webviewView.webview.options = {
            enableScripts: true,
            localResourceRoots: [vscode.Uri.joinPath(this._extensionUri, 'out', 'webviews')],
        };
        this._setWebviewContent();
        this._registerListeners(webviewView);
        this._storeSubscription = this._store.subscribe(() => this._pushState());
        this._store.setVisible(true);
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
        webview.html = /* html */ `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <!-- SECURITY: 'unsafe-inline' for styles required by VS Code theme CSS variable injection on <body>. -->
    <!-- Cannot use style nonces/hashes: VS Code injects theme tokens at runtime, outside extension control. -->
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
            const visible = webviewView.visible;
            this._store.setVisible(visible);
            if (visible) { this._pushState(); }
        });
        webviewView.webview.onDidReceiveMessage((msg: WebviewMessage) => {
            this._handleMessage(msg);
        });
    }

    private _handleMessage(message: WebviewMessage): void {
        switch (message.type) {
            case 'ready':
                this._store.refreshNow();
                this._pushState();
                break;
            case 'setSlots':
                this._store.setSlots(message.slots);
                break;
            case 'promotePanelToWebview': {
                const cmd = PROMOTE_COMMANDS[message.panelId];
                if (cmd) { vscode.commands.executeCommand(cmd); }
                break;
            }
            case 'refresh':
                this._store.refreshNow();
                break;
            case 'setAttentionMode':
                this._store.setAttentionMode(message.mode);
                break;
            case 'openInBrowser':
                vscode.commands.executeCommand('agent-os.openGovernanceInBrowser');
                break;
        }
    }

    private _pushState(): void {
        if (!this._view?.visible) { return; }
        this._view.webview.postMessage({ type: 'stateUpdate', state: this._store.getState() });
    }

    public dispose(): void {
        this._storeSubscription?.dispose();
        this._store.setVisible(false);
    }
}
