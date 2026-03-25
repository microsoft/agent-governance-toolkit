// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Hub Audit Helpers
 *
 * Shared audit entry mapping used by both GovernanceHubPanel
 * and GovernanceHubViewProvider to transform raw audit log
 * entries into a serializable format for the webview.
 */

import { AuditLoggerLike } from './GovernanceHubPanel';

/** Serializable audit event sent to the webview. */
export interface AuditEvent {
    type: unknown;
    timestamp: string | unknown;
    file: unknown;
    language: unknown;
    violation: unknown;
    reason: unknown;
}

/**
 * Map raw audit logger entries to serializable AuditEvent objects.
 *
 * Converts Date timestamps to ISO strings. All other fields are
 * passed through as-is from the raw record.
 */
export function mapAuditEntries(auditLogger: AuditLoggerLike): AuditEvent[] {
    const raw = auditLogger.getAll() as Record<string, unknown>[];
    return raw.map((e) => ({
        type: e.type,
        timestamp: e.timestamp instanceof Date
            ? e.timestamp.toISOString()
            : e.timestamp,
        file: e.file,
        language: e.language,
        violation: e.violation,
        reason: e.reason,
    }));
}
