// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Detail Shell
 *
 * Shared layout wrapper for all full-panel detail webviews.
 * Provides a consistent header with title, timestamp, and refresh button,
 * plus a scrollable main content area.
 */

import React from 'react';
import { timeAgo } from '../sidebar/timeUtils';
import { getVSCodeAPI } from './vscode';

interface DetailShellProps {
    /** Panel title displayed in the header. */
    title: string;
    /** ISO timestamp of last data fetch, or null if no data yet. */
    timestamp: string | null;
    /** Callback invoked when the user clicks the refresh button. */
    onRefresh: () => void;
    children: React.ReactNode;
}

/** Format timestamp for display, returning empty string when null. */
function formatTimestamp(ts: string | null): string {
    if (!ts) { return ''; }
    return timeAgo(ts);
}

/**
 * Shared layout shell for detail panels.
 *
 * Renders a fixed header row and scrollable content area using
 * VS Code theme tokens for consistent appearance.
 */
export function DetailShell({ title, timestamp, onRefresh, children }: DetailShellProps): React.JSX.Element {
    return (
        <div className="flex flex-col h-screen bg-ml-bg text-ml-text font-sans">
            <header className="flex items-center justify-between px-ml-md py-ml-sm border-b border-ml-border shrink-0">
                <h1 className="text-base font-semibold text-ml-text-bright">
                    {title}
                </h1>
                <span className="text-xs text-ml-text-muted">
                    {formatTimestamp(timestamp)}
                </span>
                <div className="flex items-center gap-1">
                    <button
                        type="button"
                        className="flex items-center justify-center w-6 h-6 rounded-ml hover:bg-ml-surface-hover"
                        onClick={() => getVSCodeAPI().postMessage({ type: 'showHelp' })}
                        aria-label="Help"
                        title="Help"
                    >
                        <i className="codicon codicon-question text-sm" />
                    </button>
                    <button
                        type="button"
                        className="flex items-center justify-center w-6 h-6 rounded-ml hover:bg-ml-surface-hover"
                        onClick={onRefresh}
                        aria-label="Refresh"
                        title="Refresh"
                    >
                        <i className="codicon codicon-refresh text-sm" />
                    </button>
                </div>
            </header>
            <main className="flex-1 overflow-y-auto px-ml-md py-ml-sm">
                {children}
            </main>
        </div>
    );
}
