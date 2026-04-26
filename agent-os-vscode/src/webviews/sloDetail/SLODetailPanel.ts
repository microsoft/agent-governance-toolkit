// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * SLO Detail Panel -- thin config wrapper over shared panelHost.
 */

import type { GovernanceStore } from '../sidebar/GovernanceStore';
import { createDetailPanel } from '../shared/panelHost';

export function showSLODetail(extensionUri: import('vscode').Uri, store: GovernanceStore): void {
    createDetailPanel(
        { viewType: 'agent-os.sloDetail', title: 'SLO Detail', scriptFolder: 'sloDetail' },
        extensionUri,
        {
            onStoreData: (panel) => store.onDetailSubscribe('slo', (data) => {
                panel.webview.postMessage({ type: 'sloDetailUpdate', data });
            }),
            onRefresh: () => store.refreshNow(),
        },
    );
}
