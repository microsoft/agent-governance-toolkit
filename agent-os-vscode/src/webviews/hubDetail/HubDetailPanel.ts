// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Hub Detail Panel -- thin config wrapper over shared panelHost.
 */

import type { GovernanceStore } from '../sidebar/GovernanceStore';
import { createDetailPanel } from '../shared/panelHost';

export function showHubDetail(extensionUri: import('vscode').Uri, store: GovernanceStore): void {
    createDetailPanel(
        { viewType: 'agent-os.hubDetail', title: 'Governance Hub', scriptFolder: 'hubDetail' },
        extensionUri,
        {
            onStoreData: (panel) => store.onDetailSubscribe('hub', (data) => {
                panel.webview.postMessage({ type: 'hubDetailUpdate', data });
            }),
            onRefresh: () => store.refreshNow(),
        },
    );
}
