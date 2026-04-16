// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Policy Detail Panel -- thin config wrapper over shared panelHost.
 */

import type { GovernanceStore } from '../sidebar/GovernanceStore';
import { createDetailPanel } from '../shared/panelHost';

export function showPolicyDetail(extensionUri: import('vscode').Uri, store: GovernanceStore): void {
    createDetailPanel(
        { viewType: 'agent-os.policyDetail', title: 'Active Policies', scriptFolder: 'policyDetail' },
        extensionUri,
        {
            onStoreData: (panel) => store.onDetailSubscribe('policy', (data) => {
                panel.webview.postMessage({ type: 'policyDetailUpdate', data });
            }),
            onRefresh: () => store.refreshNow(),
        },
    );
}
