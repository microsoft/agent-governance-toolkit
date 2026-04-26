// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Store Event Wiring
 *
 * Subscribes GovernanceStore fetch groups to external change events.
 * Extracted to keep GovernanceStore within the 250-line Section 4 limit.
 */

import type * as vscode from 'vscode';

/** Event source with a vscode.Event<void> change signal. */
export interface ChangeSource {
    onDidChange: vscode.Event<void>;
}

/**
 * Wire change event sources to store fetch callbacks.
 * Returns disposables for cleanup.
 */
export function wireStoreEvents(
    liveClient: ChangeSource | undefined,
    auditLogger: ChangeSource | undefined,
    onLiveChange: () => void,
    onLocalChange: () => void,
): vscode.Disposable[] {
    const subs: vscode.Disposable[] = [];
    if (liveClient) {
        subs.push(liveClient.onDidChange(onLiveChange));
    }
    if (auditLogger) {
        subs.push(auditLogger.onDidChange(onLocalChange));
    }
    return subs;
}
