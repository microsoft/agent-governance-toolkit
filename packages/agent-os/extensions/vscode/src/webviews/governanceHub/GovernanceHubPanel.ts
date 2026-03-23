// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Governance Hub Panel
 *
 * Singleton webview panel that hosts the unified Governance Hub.
 * Combines SLO, Topology, and Audit views with a tabbed interface.
 */

import * as vscode from 'vscode';
import * as crypto from 'crypto';
import { SLODataProvider } from '../../views/sloTypes';
import { AgentTopologyDataProvider } from '../../views/topologyTypes';
import { renderGovernanceHub } from './GovernanceHubTemplate';
import { HubConfig, HubOutboundMessage, HubTabId } from './governanceHubTypes';

/** Audit logger interface for dependency injection. */
export interface AuditLoggerLike {
    getAll(): unknown[];
}

/**
 * Manages the Governance Hub webview panel lifecycle.
 *
 * Uses a singleton pattern - only one panel instance is active at a time.
 */
export class GovernanceHubPanel {
    public static readonly viewType = 'agentOS.governanceHubWebview';

    private static _currentPanel: GovernanceHubPanel | undefined;

    private readonly _panel: vscode.WebviewPanel;
    private readonly _extensionUri: vscode.Uri;
    private readonly _sloProvider: SLODataProvider;
    private readonly _topologyProvider: AgentTopologyDataProvider;
    private readonly _auditLogger: AuditLoggerLike;
    private readonly _disposables: vscode.Disposable[] = [];
    private _refreshInterval: ReturnType<typeof setInterval> | undefined;
    private _config: HubConfig;

    /**
     * Create a new panel or reveal the existing one.
     */
    public static createOrShow(
        extensionUri: vscode.Uri,
        sloProvider: SLODataProvider,
        topologyProvider: AgentTopologyDataProvider,
        auditLogger: AuditLoggerLike
    ): void {
        const column = vscode.window.activeTextEditor?.viewColumn;

        if (GovernanceHubPanel._currentPanel) {
            GovernanceHubPanel._currentPanel._panel.reveal(column);
            return;
        }

        const panel = vscode.window.createWebviewPanel(
            GovernanceHubPanel.viewType,
            'Governance Hub',
            column || vscode.ViewColumn.One,
            { enableScripts: true, retainContextWhenHidden: true }
        );

        GovernanceHubPanel._currentPanel = new GovernanceHubPanel(
            panel, extensionUri, sloProvider, topologyProvider, auditLogger
        );
    }

    /** Return the current panel instance, if any. */
    public static currentPanel(): GovernanceHubPanel | undefined {
        return GovernanceHubPanel._currentPanel;
    }

    private constructor(
        panel: vscode.WebviewPanel,
        extensionUri: vscode.Uri,
        sloProvider: SLODataProvider,
        topologyProvider: AgentTopologyDataProvider,
        auditLogger: AuditLoggerLike
    ) {
        this._panel = panel;
        this._extensionUri = extensionUri;
        this._sloProvider = sloProvider;
        this._topologyProvider = topologyProvider;
        this._auditLogger = auditLogger;
        this._config = this._loadConfig();

        this._setWebviewContent();
        this._startAutoRefresh();
        this._registerListeners();

        setTimeout(() => this._sendAllUpdates(), 200);
    }

    /** Load configuration with defaults. */
    private _loadConfig(): HubConfig {
        return {
            enabledTabs: ['slo', 'topology', 'audit'] as HubTabId[],
            defaultTab: 'slo',
            refreshIntervalMs: 10_000,
        };
    }

    /** Generate the webview HTML with a fresh CSP nonce. */
    private _setWebviewContent(): void {
        const nonce = crypto.randomBytes(16).toString('hex');
        const cspSource = this._panel.webview.cspSource;
        this._panel.webview.html = renderGovernanceHub(nonce, cspSource, this._config);
    }

    /** Start unified 10-second auto-refresh interval. */
    private _startAutoRefresh(): void {
        const interval = this._config.refreshIntervalMs || 10_000;
        this._refreshInterval = setInterval(() => this._sendAllUpdates(), interval);
    }

    /** Register panel lifecycle and message listeners. */
    private _registerListeners(): void {
        this._panel.onDidDispose(() => this.dispose(), null, this._disposables);
        this._panel.webview.onDidReceiveMessage(
            (msg: HubOutboundMessage) => this._handleMessage(msg),
            null,
            this._disposables
        );
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

    /** Push all data sources to the webview. */
    private async _sendAllUpdates(): Promise<void> {
        await Promise.all([
            this._sendSLOUpdate(),
            this._sendTopologyUpdate(),
            this._sendAuditUpdate(),
        ]);
        this._updateTimestamp();
    }

    /** Fetch and send SLO snapshot. */
    private async _sendSLOUpdate(): Promise<void> {
        try {
            const snapshot = await this._sloProvider.getSnapshot();
            await this._panel.webview.postMessage({ type: 'sloUpdate', payload: snapshot });
        } catch { /* Next interval will retry */ }
    }

    /** Fetch and send topology data. */
    private _sendTopologyUpdate(): void {
        const nodes = this._topologyProvider.getAgents();
        const edges = this._topologyProvider.getDelegations();
        const bridges = this._topologyProvider.getBridges();
        this._panel.webview.postMessage({
            type: 'topologyUpdate',
            payload: { nodes, edges, bridges }
        });
    }

    /** Fetch and send audit log entries. */
    private _sendAuditUpdate(): void {
        const entries = this._auditLogger.getAll();
        this._panel.webview.postMessage({ type: 'auditUpdate', payload: entries });
    }

    /** Update the last-updated timestamp in footer. */
    private _updateTimestamp(): void {
        const now = new Date().toLocaleTimeString();
        this._panel.webview.postMessage({
            type: 'configUpdate',
            payload: { lastUpdated: now }
        });
    }

    /** Dispose all resources held by this panel. */
    public dispose(): void {
        GovernanceHubPanel._currentPanel = undefined;

        if (this._refreshInterval) {
            clearInterval(this._refreshInterval);
            this._refreshInterval = undefined;
        }

        this._panel.dispose();

        while (this._disposables.length) {
            const d = this._disposables.pop();
            if (d) { d.dispose(); }
        }
    }
}
