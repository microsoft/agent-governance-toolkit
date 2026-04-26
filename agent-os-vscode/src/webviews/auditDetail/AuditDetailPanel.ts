// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Audit Log Detail Panel -- thin config wrapper over shared panelHost.
 */

import type { GovernanceStore } from '../sidebar/GovernanceStore';
import { createDetailPanel } from '../shared/panelHost';

export function showAuditDetail(extensionUri: import('vscode').Uri, store: GovernanceStore): void {
    createDetailPanel(
        { viewType: 'agent-os.auditDetail', title: 'Audit Log', scriptFolder: 'auditDetail' },
        extensionUri,
        {
            onStoreData: (panel) => store.onDetailSubscribe('audit', (data) => {
                panel.webview.postMessage({ type: 'auditDetailUpdate', data });
            }),
            onRefresh: () => store.refreshNow(),
        },
    );
}
