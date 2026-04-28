// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Shared Detail Panel Host
 *
 * Factory for singleton WebviewPanels with CSP, nonce-gated scripts,
 * GovernanceStore subscription, and automatic lifecycle management.
 * Eliminates duplication across SLO, Topology, and Hub detail panels.
 */
import * as vscode from 'vscode';
import * as crypto from 'crypto';

/** Configuration for a detail panel. */
export interface DetailPanelConfig {
    viewType: string;
    title: string;
    scriptFolder: string;
    retainContextWhenHidden?: boolean;
}

/** Disposable returned by store subscriptions. */
interface Disposable { dispose(): void; }

/** Callbacks wiring the panel to the GovernanceStore and message handlers. */
export interface DetailPanelCallbacks {
    /** Set up the store subscription; must return a Disposable. */
    onStoreData: (panel: vscode.WebviewPanel) => Disposable;
    /** Optional handler for non-refresh messages from the webview. */
    onMessage?: (msg: Record<string, unknown>) => void;
    /** Called when the user clicks refresh in the webview. */
    onRefresh?: () => void;
}

/** Singleton registry keyed by viewType. */
const _panels = new Map<string, vscode.WebviewPanel>();

/** Show an existing detail panel or create a new singleton instance. */
export function createDetailPanel(
    config: DetailPanelConfig,
    extensionUri: vscode.Uri,
    callbacks: DetailPanelCallbacks,
): void {
    const existing = _panels.get(config.viewType);
    if (existing) {
        existing.reveal(vscode.window.activeTextEditor?.viewColumn ?? vscode.ViewColumn.One);
        return;
    }
    const column = vscode.window.activeTextEditor?.viewColumn ?? vscode.ViewColumn.One;
    const panel = vscode.window.createWebviewPanel(
        config.viewType, config.title, column,
        {
            enableScripts: true,
            localResourceRoots: [vscode.Uri.joinPath(extensionUri, 'out', 'webviews')],
            retainContextWhenHidden: config.retainContextWhenHidden,
        },
    );
    _panels.set(config.viewType, panel);
    setHtml(panel.webview, extensionUri, config.scriptFolder, config.title);

    const storeSub = callbacks.onStoreData(panel);
    const msgSub = panel.webview.onDidReceiveMessage((msg: Record<string, unknown>) => {
        if (msg.type === 'refresh') { callbacks.onRefresh?.(); }
        if (msg.type === 'showHelp') { vscode.commands.executeCommand('agent-os.showHelp'); }
        callbacks.onMessage?.(msg);
    });
    panel.onDidDispose(() => {
        storeSub.dispose();
        msgSub.dispose();
        _panels.delete(config.viewType);
    });
}

function setHtml(
    webview: vscode.Webview, extensionUri: vscode.Uri, scriptFolder: string, title: string,
): void {
    const nonce = crypto.randomBytes(16).toString('hex');
    const scriptUri = webview.asWebviewUri(
        vscode.Uri.joinPath(extensionUri, 'out', 'webviews', scriptFolder, 'main.js'),
    );
    const styleUri = webview.asWebviewUri(
        vscode.Uri.joinPath(extensionUri, 'out', 'webviews', 'index.css'),
    );
    webview.html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <!-- SECURITY: 'unsafe-inline' for styles required by VS Code theme token CSS variable injection. -->
    <!-- Scripts remain nonce-gated — no 'unsafe-inline' for script-src. -->
    <meta http-equiv="Content-Security-Policy"
          content="default-src 'none';
                   style-src ${webview.cspSource} 'unsafe-inline';
                   script-src 'nonce-${nonce}';
                   font-src ${webview.cspSource};" />
    <link rel="stylesheet" href="${styleUri}" />
    <title>${title.replace(/[&<>"']/g, '')}</title>
</head>
<body>
    <div id="root"></div>
    <script nonce="${nonce}" src="${scriptUri}"></script>
</body>
</html>`;
}
