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
import { renderSLODashboard } from './SLODashboardTemplate';

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
                retainContextWhenHidden: true
            }
        );

        SLODashboardPanel._currentPanel = new SLODashboardPanel(
            panel,
            sloDataProvider
        );
    }

    /** Return the current panel instance, if any. */
    public static currentPanel(): SLODashboardPanel | undefined {
        return SLODashboardPanel._currentPanel;
    }

    private constructor(
        panel: vscode.WebviewPanel,
        sloDataProvider: SLODataProvider
    ) {
        this._panel = panel;
        this._sloDataProvider = sloDataProvider;

        this._setWebviewContent();
        this._startAutoRefresh();
        this._registerListeners();

        // Send initial data after webview has loaded.
        setTimeout(() => this._sendUpdate(), 200);
    }

    /**
     * Generate the webview HTML with a fresh CSP nonce.
     */
    private _setWebviewContent(): void {
        const nonce = crypto.randomBytes(16).toString('hex');
        const cspSource = this._panel.webview.cspSource;
        this._panel.title = 'SLO Dashboard';
        this._panel.webview.html = renderSLODashboard(nonce, cspSource);
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
