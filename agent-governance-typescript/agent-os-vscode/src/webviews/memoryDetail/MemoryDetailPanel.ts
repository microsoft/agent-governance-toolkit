// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Memory Browser Detail Panel -- thin config wrapper over shared panelHost.
 */

import type { GovernanceStore } from '../sidebar/GovernanceStore';
import { createDetailPanel } from '../shared/panelHost';

export function showMemoryDetail(extensionUri: import('vscode').Uri, store: GovernanceStore): void {
    createDetailPanel(
        { viewType: 'agent-os.memoryDetail', title: 'Memory Browser', scriptFolder: 'memoryDetail' },
        extensionUri,
        {
            onStoreData: (panel) => store.onDetailSubscribe('memory', (data) => {
                panel.webview.postMessage({ type: 'memoryDetailUpdate', data });
            }),
            onRefresh: () => store.refreshNow(),
        },
    );
}
