// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * HTML Escape Utility
 *
 * Single source of truth for HTML entity escaping across the extension.
 * Used by export, server, and legacy webview panel code.
 */

/** Escape a value for safe insertion into HTML. Handles & < > " ' */
export function escapeHtml(value: unknown): string {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}
