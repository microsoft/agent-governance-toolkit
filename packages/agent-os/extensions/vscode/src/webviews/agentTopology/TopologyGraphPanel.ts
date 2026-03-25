// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Topology Graph Panel
 *
 * Singleton webview panel that hosts the force-directed agent topology
 * graph. Manages the panel lifecycle, periodically pushes topology
 * updates from the data provider, and handles inbound messages from the
 * webview (agent selection, manual refresh).
 */

import * as vscode from 'vscode';
import * as crypto from 'crypto';
import { AgentTopologyDataProvider } from '../../views/topologyTypes';
import { renderTopologyGraph } from './TopologyGraphTemplate';

/** Generate a random hex nonce for Content-Security-Policy. */
function generateNonce(): string {
    return crypto.randomBytes(16).toString('hex');
}

/**
 * Webview panel that visualises the agent mesh topology as an
 * interactive force-directed SVG graph.
 */
export class TopologyGraphPanel {
    public static readonly viewType = 'agentOS.topologyGraphWebview';

    /** Singleton instance. */
    public static currentPanel: TopologyGraphPanel | undefined;

    private readonly _panel: vscode.WebviewPanel;
    private readonly _extensionUri: vscode.Uri;
    private readonly _dataProvider: AgentTopologyDataProvider;
    private _disposables: vscode.Disposable[] = [];
    private _refreshInterval: ReturnType<typeof setInterval> | undefined;

    // -----------------------------------------------------------------
    // Public static API
    // -----------------------------------------------------------------

    /**
     * Create or reveal the topology graph panel (singleton pattern).
     *
     * @param extensionUri         - Root URI of the extension.
     * @param topologyDataProvider - Supplies agent, bridge, and delegation data.
     */
    public static createOrShow(
        extensionUri: vscode.Uri,
        topologyDataProvider: AgentTopologyDataProvider,
    ): void {
        const column = vscode.window.activeTextEditor
            ? vscode.window.activeTextEditor.viewColumn
            : undefined;

        if (TopologyGraphPanel.currentPanel) {
            TopologyGraphPanel.currentPanel._panel.reveal(column);
            return;
        }

        const panel = vscode.window.createWebviewPanel(
            TopologyGraphPanel.viewType,
            'Agent Topology Graph',
            column || vscode.ViewColumn.One,
            {
                enableScripts: true,
                retainContextWhenHidden: true,
            },
        );

        TopologyGraphPanel.currentPanel = new TopologyGraphPanel(
            panel,
            extensionUri,
            topologyDataProvider,
        );
    }

    // -----------------------------------------------------------------
    // Constructor (private — use createOrShow)
    // -----------------------------------------------------------------

    private constructor(
        panel: vscode.WebviewPanel,
        extensionUri: vscode.Uri,
        dataProvider: AgentTopologyDataProvider,
    ) {
        this._panel = panel;
        this._extensionUri = extensionUri;
        this._dataProvider = dataProvider;

        this._setWebviewContent();
        this._sendUpdate();

        this._refreshInterval = setInterval(() => {
            this._sendUpdate();
        }, 15_000);

        this._panel.onDidDispose(
            () => this.dispose(),
            null,
            this._disposables,
        );

        this._panel.webview.onDidReceiveMessage(
            (message) => this._handleMessage(message),
            null,
            this._disposables,
        );
    }

    // -----------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------

    /** Tear down the panel and release all resources. */
    public dispose(): void {
        TopologyGraphPanel.currentPanel = undefined;

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

    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    /** Set the webview HTML content with a fresh nonce. */
    private _setWebviewContent(): void {
        const nonce = generateNonce();
        const cspSource = this._panel.webview.cspSource;
        this._panel.webview.html = renderTopologyGraph(nonce, cspSource);
    }

    /** Push the latest topology snapshot to the webview. */
    private _sendUpdate(): void {
        const nodes = this._dataProvider.getAgents();
        const edges = this._dataProvider.getDelegations();
        const bridges = this._dataProvider.getBridges();

        this._panel.webview.postMessage({
            type: 'topologyUpdate',
            nodes,
            edges,
            bridges,
        });
    }

    /** Route inbound messages from the webview script. */
    private _handleMessage(message: { type: string; did?: string }): void {
        switch (message.type) {
            case 'refresh':
                this._sendUpdate();
                break;
            case 'selectAgent':
                this._focusAgent(message.did);
                break;
        }
    }

    /** Execute the agent-focus command when a node is clicked. */
    private _focusAgent(did: string | undefined): void {
        if (!did) {
            return;
        }
        vscode.commands.executeCommand(
            'agent-os.agentTopology.focus',
            did,
        );
    }
}
