// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Governance Hub View Provider
 *
 * WebviewViewProvider for the sidebar-embedded Governance Hub.
 * Provides a compact view that shares data providers with the main panel.
 */

import * as vscode from 'vscode';
import * as crypto from 'crypto';
import { SLODataProvider } from '../../views/sloTypes';
import { AgentTopologyDataProvider } from '../../views/topologyTypes';
import { renderGovernanceHub } from './GovernanceHubTemplate';
import { HubConfig, HubOutboundMessage, HubTabId } from './governanceHubTypes';
import { AuditLoggerLike } from './GovernanceHubPanel';

/**
 * Provides a sidebar webview for the Governance Hub (compact mode).
 *
 * Implements WebviewViewProvider to integrate with VS Code sidebar.
 */
export class GovernanceHubViewProvider implements vscode.WebviewViewProvider {
    public static readonly viewType = 'agentOS.governanceHubView';

    private _view: vscode.WebviewView | undefined;
    private _sloProvider: SLODataProvider;
    private _topologyProvider: AgentTopologyDataProvider;
    private _auditLogger: AuditLoggerLike;
    private _refreshInterval: ReturnType<typeof setInterval> | undefined;
    private _config: HubConfig;

    constructor(
        private readonly _extensionUri: vscode.Uri,
        sloProvider: SLODataProvider,
        topologyProvider: AgentTopologyDataProvider,
        auditLogger: AuditLoggerLike
    ) {
        this._sloProvider = sloProvider;
        this._topologyProvider = topologyProvider;
        this._auditLogger = auditLogger;
        this._config = this._loadConfig();
    }

    /** Load configuration with defaults. */
    private _loadConfig(): HubConfig {
        return {
            enabledTabs: ['slo', 'topology', 'audit'] as HubTabId[],
            defaultTab: 'slo',
            refreshIntervalMs: 10_000,
        };
    }

    /**
     * Called when the view is first displayed.
     */
    public resolveWebviewView(
        webviewView: vscode.WebviewView,
        _context: vscode.WebviewViewResolveContext,
        _token: vscode.CancellationToken
    ): void {
        this._view = webviewView;

        webviewView.webview.options = {
            enableScripts: true,
            localResourceRoots: [this._extensionUri],
        };

        this._setWebviewContent();
        this._registerListeners(webviewView);
        this._startAutoRefresh();

        setTimeout(() => this._sendAllUpdates(), 200);
    }

    /** Generate the webview HTML. */
    private _setWebviewContent(): void {
        if (!this._view) { return; }
        const nonce = crypto.randomBytes(16).toString('hex');
        const cspSource = this._view.webview.cspSource;
        this._view.webview.html = renderGovernanceHub(nonce, cspSource, this._config);
    }

    /** Register visibility and message listeners. */
    private _registerListeners(webviewView: vscode.WebviewView): void {
        webviewView.onDidChangeVisibility(() => {
            if (webviewView.visible) {
                this._resumeUpdates();
            } else {
                this._pauseUpdates();
            }
        });

        webviewView.webview.onDidReceiveMessage((msg: HubOutboundMessage) => {
            this._handleMessage(msg);
        });
    }

    /** Handle messages from the webview. */
    private _handleMessage(message: HubOutboundMessage): void {
        switch (message.type) {
            case 'refresh':
                this._sendAllUpdates();
                break;
            case 'openInBrowser':
                vscode.commands.executeCommand('agent-os.openGovernanceInBrowser');
                break;
            case 'export':
                vscode.commands.executeCommand('agent-os.exportReport');
                break;
        }
    }

    /** Start the auto-refresh interval. */
    private _startAutoRefresh(): void {
        const interval = this._config.refreshIntervalMs || 10_000;
        this._refreshInterval = setInterval(() => {
            if (this._view?.visible) { this._sendAllUpdates(); }
        }, interval);
    }

    /** Resume updates when view becomes visible. */
    private _resumeUpdates(): void {
        this._sendAllUpdates();
    }

    /** Pause updates when view is hidden. */
    private _pauseUpdates(): void {
        // Interval continues but checks visibility before sending
    }

    /** Push all data sources to the webview. */
    private async _sendAllUpdates(): Promise<void> {
        if (!this._view) { return; }

        await this._sendSLOUpdate();
        this._sendTopologyUpdate();
        this._sendAuditUpdate();
    }

    /** Fetch and send SLO snapshot. */
    private async _sendSLOUpdate(): Promise<void> {
        if (!this._view) { return; }
        try {
            const snapshot = await this._sloProvider.getSnapshot();
            await this._view.webview.postMessage({ type: 'sloUpdate', payload: snapshot });
        } catch { /* Next interval will retry */ }
    }

    /** Fetch and send topology data. */
    private _sendTopologyUpdate(): void {
        if (!this._view) { return; }
        const nodes = this._topologyProvider.getAgents();
        const edges = this._topologyProvider.getDelegations();
        const bridges = this._topologyProvider.getBridges();
        this._view.webview.postMessage({
            type: 'topologyUpdate',
            payload: { nodes, edges, bridges }
        });
    }

    /** Fetch and send audit log entries. */
    private _sendAuditUpdate(): void {
        if (!this._view) { return; }
        const entries = this._auditLogger.getAll();
        this._view.webview.postMessage({ type: 'auditUpdate', payload: entries });
    }

    /** Clean up resources. */
    public dispose(): void {
        if (this._refreshInterval) {
            clearInterval(this._refreshInterval);
            this._refreshInterval = undefined;
        }
    }
}
