// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Hub Audit Tab
 *
 * Audit log detail view with severity filtering, text search,
 * and a sortable table. Displays within the Governance Hub panel.
 */

import React, { useState, useMemo } from 'react';
import type { AuditDetailData, AuditEntry } from '../shared/types';
import { timeAgo } from '../sidebar/timeUtils';
import { Tooltip } from '../shared/Tooltip';
import { HELP } from '../shared/helpContent';

type Severity = 'all' | 'info' | 'warning' | 'critical';

interface HubAuditTabProps {
    data: AuditDetailData | null;
}

const MAX_DISPLAY = 100;

/** Severity filter options for the dropdown. */
const SEVERITY_OPTIONS: { value: Severity; label: string }[] = [
    { value: 'all', label: 'All' },
    { value: 'info', label: 'Info' },
    { value: 'warning', label: 'Warning' },
    { value: 'critical', label: 'Critical' },
];

/** Map severity to Tailwind badge classes using VS Code theme vars. */
function severityBadgeClass(severity: AuditEntry['severity']): string {
    if (severity === 'critical') { return 'bg-ml-error/20 text-ml-error'; }
    if (severity === 'warning') { return 'bg-ml-warning/20 text-ml-warning'; }
    return 'bg-ml-info/20 text-ml-info';
}

/** Truncate a DID string for table display. */
function truncateDid(did: string | null): string {
    if (!did) { return '\u2014'; }
    if (did.length <= 20) { return did; }
    return `${did.slice(0, 10)}\u2026${did.slice(-8)}`;
}

/** Count entries matching a severity level. */
function countBySeverity(entries: AuditEntry[], sev: AuditEntry['severity']): number {
    return entries.filter((e) => e.severity === sev).length;
}

/** Filter entries by severity and search text. */
function filterEntries(
    entries: AuditEntry[],
    severity: Severity,
    search: string,
): AuditEntry[] {
    let filtered = entries;
    if (severity !== 'all') {
        filtered = filtered.filter((e) => e.severity === severity);
    }
    if (search.trim()) {
        const q = search.toLowerCase();
        filtered = filtered.filter((e) =>
            e.action.toLowerCase().includes(q)
            || (e.agentDid?.toLowerCase().includes(q) ?? false)
            || e.result.toLowerCase().includes(q)
            || (e.file?.toLowerCase().includes(q) ?? false),
        );
    }
    return filtered;
}

/** Sort entries by timestamp descending and cap at MAX_DISPLAY. */
function sortAndLimit(entries: AuditEntry[]): AuditEntry[] {
    const sorted = [...entries].sort(
        (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
    );
    return sorted.slice(0, MAX_DISPLAY);
}

/** Header with title and violation count badge. */
function AuditHeader({ entries }: { entries: AuditEntry[] }): React.JSX.Element {
    const violations = countBySeverity(entries, 'critical')
        + countBySeverity(entries, 'warning');

    return (
        <div className="flex items-center gap-2 mb-ml-sm">
            <h2 className="text-sm font-semibold text-ml-text-bright">Audit Log</h2>
            {violations > 0 && (
                <span className="px-2 py-0.5 text-xs rounded-full bg-ml-error/20 text-ml-error">
                    {violations} violation{violations !== 1 ? 's' : ''}
                </span>
            )}
        </div>
    );
}

/** Severity dropdown and text search bar. */
function AuditFilterBar(
    { severity, onSeverity, search, onSearch }: {
        severity: Severity;
        onSeverity: (s: Severity) => void;
        search: string;
        onSearch: (s: string) => void;
    },
): React.JSX.Element {
    return (
        <div className="flex items-center gap-2 mb-ml-sm">
            <span className="flex items-center gap-1">
                <select
                    value={severity}
                    onChange={(e) => onSeverity(e.target.value as Severity)}
                    className="px-2 py-1 text-xs rounded-ml bg-ml-surface text-ml-text border border-ml-border"
                    aria-label="Filter by severity"
                >
                {SEVERITY_OPTIONS.map((opt) => (
                    <option key={opt.value} value={opt.value}>{opt.label}</option>
                ))}
                </select>
                <Tooltip text={HELP.audit.severity} />
            </span>
            <input
                type="text"
                value={search}
                onChange={(e) => onSearch(e.target.value)}
                placeholder="Search actions, DIDs, files..."
                className="flex-1 px-2 py-1 text-xs rounded-ml bg-ml-surface text-ml-text border border-ml-border"
                aria-label="Search audit entries"
            />
        </div>
    );
}

/** Single audit table row. */
function AuditRow({ entry }: { entry: AuditEntry }): React.JSX.Element {
    return (
        <tr className="border-b border-ml-border/50 hover:bg-ml-surface-hover">
            <td className="px-2 py-1 text-xs text-ml-text-muted">{timeAgo(entry.timestamp)}</td>
            <td className="px-2 py-1 text-xs">{entry.action}</td>
            <td className="px-2 py-1 text-xs font-mono" title={entry.agentDid ?? undefined}>
                {truncateDid(entry.agentDid)}
            </td>
            <td className="px-2 py-1">
                <span className={`px-1.5 py-0.5 text-xs rounded ${severityBadgeClass(entry.severity)}`}>
                    {entry.severity}
                </span>
            </td>
            <td className="px-2 py-1 text-xs">{entry.result}</td>
            <td className="px-2 py-1 text-xs text-ml-text-muted">{entry.file ?? '\u2014'}</td>
        </tr>
    );
}

/** Table header row for the audit log. */
function AuditTableHeader(): React.JSX.Element {
    return (
        <thead>
            <tr className="border-b border-ml-border text-left">
                <th className="px-2 py-1 text-xs font-medium text-ml-text-muted">Time</th>
                <th className="px-2 py-1 text-xs font-medium text-ml-text-muted">Action</th>
                <th className="px-2 py-1 text-xs font-medium text-ml-text-muted">Agent DID</th>
                <th className="px-2 py-1 text-xs font-medium text-ml-text-muted">Severity</th>
                <th className="px-2 py-1 text-xs font-medium text-ml-text-muted">Result</th>
                <th className="px-2 py-1 text-xs font-medium text-ml-text-muted">File</th>
            </tr>
        </thead>
    );
}

/**
 * Audit log tab for the Governance Hub.
 *
 * Renders a filterable, searchable table of audit entries
 * sorted by timestamp descending.
 */
export function HubAuditTab({ data }: HubAuditTabProps): React.JSX.Element {
    const [severity, setSeverity] = useState<Severity>('all');
    const [search, setSearch] = useState('');

    const visible = useMemo(() => {
        if (!data) { return []; }
        return sortAndLimit(filterEntries(data.entries, severity, search));
    }, [data, severity, search]);

    if (!data) {
        return <p className="text-sm text-ml-text-muted py-ml-md">Loading audit data...</p>;
    }

    return (
        <div className="flex flex-col gap-ml-sm">
            <AuditHeader entries={data.entries} />
            <AuditFilterBar
                severity={severity}
                onSeverity={setSeverity}
                search={search}
                onSearch={setSearch}
            />
            <div className="overflow-x-auto">
                <table className="w-full text-left">
                    <AuditTableHeader />
                    <tbody>
                        {visible.map((entry) => (
                            <AuditRow key={entry.id} entry={entry} />
                        ))}
                    </tbody>
                </table>
            </div>
            {visible.length === 0 && (
                <p className="text-xs text-ml-text-muted py-ml-sm">No entries match filters.</p>
            )}
        </div>
    );
}
