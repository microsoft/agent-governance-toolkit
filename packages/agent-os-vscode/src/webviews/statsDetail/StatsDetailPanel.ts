// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Safety Stats Detail Panel -- thin config wrapper over shared panelHost.
 */

import type { GovernanceStore } from '../sidebar/GovernanceStore';
import { createDetailPanel } from '../shared/panelHost';

export function showStatsDetail(extensionUri: import('vscode').Uri, store: GovernanceStore): void {
    createDetailPanel(
        { viewType: 'agent-os.statsDetail', title: 'Safety Stats', scriptFolder: 'statsDetail' },
        extensionUri,
        {
            onStoreData: (panel) => store.onDetailSubscribe('stats', (data) => {
                panel.webview.postMessage({ type: 'statsDetailUpdate', data });
            }),
            onRefresh: () => store.refreshNow(),
        },
    );
}
