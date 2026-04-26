// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Topology Legend
 *
 * Static overlay displaying trust tier color meanings.
 * Positioned absolute bottom-left over the force graph.
 */

import React from 'react';

// ---------------------------------------------------------------------------
// Legend data
// ---------------------------------------------------------------------------

interface LegendRow {
    label: string;
    color: string;
}

const ROWS: readonly LegendRow[] = [
    { label: 'High Trust (\u2265750)', color: 'var(--vscode-testing-iconPassed)' },
    { label: 'Medium (\u2265400)', color: 'var(--vscode-list-warningForeground)' },
    { label: 'Low (<400)', color: 'var(--vscode-errorForeground)' },
];

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/** Single legend row with colored dot and label. */
function LegendItem({ row }: { row: LegendRow }): React.JSX.Element {
    return (
        <div className="flex items-center gap-ml-xs">
            <span
                className="inline-block w-2.5 h-2.5 rounded-full shrink-0"
                style={{ backgroundColor: row.color }}
            />
            <span className="text-[10px] text-ml-text-muted whitespace-nowrap">
                {row.label}
            </span>
        </div>
    );
}

/**
 * Trust tier legend overlay.
 *
 * Renders a compact, semi-transparent panel with three trust level
 * indicators. Designed to sit at the bottom-left of the graph area.
 */
export function TopologyLegend(): React.JSX.Element {
    return (
        <div
            className="absolute bottom-2 left-2 flex flex-col gap-0.5 px-2 py-1.5 rounded-ml"
            style={{ backgroundColor: 'var(--ml-surface)', opacity: 0.9 }}
        >
            {ROWS.map((row) => (
                <LegendItem key={row.label} row={row} />
            ))}
        </div>
    );
}
