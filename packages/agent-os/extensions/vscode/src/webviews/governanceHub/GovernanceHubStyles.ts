// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Governance Hub Styles
 *
 * Composes CSS from layout, SLO, topology, and audit sub-modules
 * into a single style block for the Governance Hub webview.
 */

import { layoutStyles } from './GovernanceHubLayoutStyles';
import { sloStyles } from './GovernanceHubSLOStyles';
import { topologyStyles } from './GovernanceHubTopologyStyles';
import { auditStyles } from './GovernanceHubAuditStyles';

/**
 * Returns the complete style block for the Governance Hub.
 *
 * @param nonce - CSP nonce for inline style security
 */
export function governanceHubStyles(nonce: string): string {
    return `<style nonce="${nonce}">
        ${layoutStyles()}
        ${sloStyles()}
        ${topologyStyles()}
        ${auditStyles()}
    </style>`;
}
