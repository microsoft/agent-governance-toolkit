// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Sidebar Hub Styles
 *
 * Composes CSS from layout and content sub-modules into a single
 * style block for the sidebar-embedded Governance Hub view.
 */

import { sidebarLayoutStyles } from './SidebarHubLayoutStyles';
import { sidebarContentStyles } from './SidebarHubContentStyles';

/**
 * Returns the complete style block for the sidebar hub.
 *
 * @param nonce - CSP nonce for inline style security
 */
export function sidebarHubStyles(nonce: string): string {
    return `<style nonce="${nonce}">
${sidebarLayoutStyles()}
${sidebarContentStyles()}
</style>`;
}
