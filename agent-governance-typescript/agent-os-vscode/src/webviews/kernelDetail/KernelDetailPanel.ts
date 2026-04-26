// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Kernel Debugger Detail Panel -- thin config wrapper over shared panelHost.
 */

import type { GovernanceStore } from '../sidebar/GovernanceStore';
import { createDetailPanel } from '../shared/panelHost';

export function showKernelDetail(extensionUri: import('vscode').Uri, store: GovernanceStore): void {
    createDetailPanel(
        { viewType: 'agent-os.kernelDetail', title: 'Kernel Debugger', scriptFolder: 'kernelDetail' },
        extensionUri,
        {
            onStoreData: (panel) => store.onDetailSubscribe('kernel', (data) => {
                panel.webview.postMessage({ type: 'kernelDetailUpdate', data });
            }),
            onRefresh: () => store.refreshNow(),
        },
    );
}
