// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Governance Hub Types
 *
 * Type definitions for the unified Governance Hub webview.
 */

/** Available tab identifiers in the Governance Hub. */
export type HubTabId = 'slo' | 'topology' | 'audit' | 'policies';

/** Configuration for the Governance Hub. */
export interface HubConfig {
    /** Array of enabled tabs to display. */
    enabledTabs: HubTabId[];
    /** Default active tab on load. */
    defaultTab?: HubTabId;
    /** Refresh interval in milliseconds. */
    refreshIntervalMs?: number;
}

/** Message types sent from webview to extension. */
export interface HubOutboundMessage {
    type: 'refresh' | 'openInBrowser' | 'export' | 'tabChange';
    activeTab?: HubTabId;
}

/** Message types sent from extension to webview. */
export interface HubInboundMessage {
    type: 'sloUpdate' | 'topologyUpdate' | 'auditUpdate' | 'configUpdate';
    payload?: unknown;
}
