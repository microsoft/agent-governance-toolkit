// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Topology Detail Panel -- thin config wrapper over shared panelHost.
 */

import * as vscode from 'vscode';
import type { GovernanceStore } from '../sidebar/GovernanceStore';
import { createDetailPanel } from '../shared/panelHost';

export function showTopologyDetail(extensionUri: vscode.Uri, store: GovernanceStore): void {
    createDetailPanel(
        {
            viewType: 'agent-os.topologyDetail',
            title: 'Agent Topology',
            scriptFolder: 'topologyDetail',
            // SECURITY: retainContextWhenHidden preserves force simulation state (120 frames).
            // Increases memory ~2MB when backgrounded. Acceptable for UX.
            retainContextWhenHidden: true,
        },
        extensionUri,
        {
            onStoreData: (panel) => store.onDetailSubscribe('topology', (data) => {
                panel.webview.postMessage({ type: 'topologyDetailUpdate', data });
            }),
            onRefresh: () => store.refreshNow(),
            onMessage: (msg) => {
                if (msg.type === 'selectAgent' && typeof msg.did === 'string') {
                    vscode.commands.executeCommand('agent-os.showAgentDetails', msg.did);
                }
            },
        },
    );
}
