// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * SLO Dashboard Panel
 *
 * Singleton webview panel that renders real-time SLO visualizations.
 * Consumes data from an SLODataProvider and pushes snapshots to the
 * webview via message passing on a 10-second refresh interval.
 */

import * as vscode from 'vscode';
import * as crypto from 'crypto';
import { SLODataProvider } from '../../views/sloTypes';

/**
 * Manages the SLO Dashboard webview panel lifecycle.
 *
 * Uses a singleton pattern — only one panel instance is active at a time.
 * Calling `createOrShow` when a panel already exists reveals the existing one.
 */
export class SLODashboardPanel {

    /** Webview panel type identifier registered in package.json. */
    public static readonly viewType = 'agentOS.sloDashboardWebview';

    /** Singleton instance reference. */
    private static _currentPanel: SLODashboardPanel | undefined;

    private readonly _panel: vscode.WebviewPanel;
    private readonly _extensionUri: vscode.Uri;
    private readonly _sloDataProvider: SLODataProvider;
    private readonly _disposables: vscode.Disposable[] = [];
    private _refreshInterval: ReturnType<typeof setInterval> | undefined;

    /**
     * Create a new panel or reveal the existing one.
     *
     * @param extensionUri - Root URI of the extension
     * @param sloDataProvider - Provider that supplies SLO snapshots
     */
    public static createOrShow(
        extensionUri: vscode.Uri,
        sloDataProvider: SLODataProvider
    ): void {
        const column = vscode.window.activeTextEditor
            ? vscode.window.activeTextEditor.viewColumn
            : undefined;

        if (SLODashboardPanel._currentPanel) {
            SLODashboardPanel._currentPanel._panel.reveal(column);
            return;
        }

        const panel = vscode.window.createWebviewPanel(
            SLODashboardPanel.viewType,
            'SLO Dashboard',
            column || vscode.ViewColumn.One,
            {
                enableScripts: true,
                retainContextWhenHidden: true,
                localResourceRoots: [vscode.Uri.joinPath(extensionUri, 'out', 'webviews')],
            }
        );

        SLODashboardPanel._currentPanel = new SLODashboardPanel(
            panel,
            extensionUri,
            sloDataProvider
        );
    }

    /** Return the current panel instance, if any. */
    public static currentPanel(): SLODashboardPanel | undefined {
        return SLODashboardPanel._currentPanel;
    }

    private constructor(
        panel: vscode.WebviewPanel,
        extensionUri: vscode.Uri,
        sloDataProvider: SLODataProvider
    ) {
        this._panel = panel;
        this._extensionUri = extensionUri;
        this._sloDataProvider = sloDataProvider;

        this._setWebviewContent();
        this._startAutoRefresh();
        this._registerListeners();

        // Send initial data after webview has loaded.
        setTimeout(() => this._sendUpdate(), 200);
    }

    /**
     * Generate minimal HTML shell that loads the React bundle.
     */
    private _setWebviewContent(): void {
        const nonce = crypto.randomBytes(16).toString('hex');
        const webview = this._panel.webview;

        const scriptUri = webview.asWebviewUri(
            vscode.Uri.joinPath(this._extensionUri, 'out', 'webviews', 'main.js')
        );
        const cssUri = webview.asWebviewUri(
            vscode.Uri.joinPath(this._extensionUri, 'out', 'webviews', 'index.css')
        );

        this._panel.title = 'SLO Dashboard';
        webview.html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy"
          content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}';">
    <link rel="stylesheet" href="${cssUri}">
    <title>SLO Dashboard</title>
</head>
<body>
    <div id="root"></div>
    <script nonce="${nonce}" src="${scriptUri}"></script>
</body>
</html>`;
    }

    /**
     * Start the 10-second auto-refresh interval.
     */
    private _startAutoRefresh(): void {
        this._refreshInterval = setInterval(() => {
            this._sendUpdate();
        }, 10_000);
    }

    /**
     * Register panel lifecycle and message listeners.
     */
    private _registerListeners(): void {
        this._panel.onDidDispose(
            () => this.dispose(),
            null,
            this._disposables
        );

        this._panel.webview.onDidReceiveMessage(
            (message: { type: string }) => {
                if (message.type === 'refresh') {
                    this._sendUpdate();
                }
            },
            null,
            this._disposables
        );
    }

    /**
     * Fetch the latest SLO snapshot and push it to the webview.
     */
    private async _sendUpdate(): Promise<void> {
        try {
            const snapshot = await this._sloDataProvider.getSnapshot();
            await this._panel.webview.postMessage({
                type: 'sloUpdate',
                snapshot
            });
        } catch {
            // Silently skip — next interval will retry.
        }
    }

    /**
     * Dispose all resources held by this panel.
     */
    public dispose(): void {
        SLODashboardPanel._currentPanel = undefined;

        if (this._refreshInterval) {
            clearInterval(this._refreshInterval);
            this._refreshInterval = undefined;
        }

        this._panel.dispose();

        while (this._disposables.length) {
            const d = this._disposables.pop();
            if (d) {
                d.dispose();
            }
        }
    }
}
