// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * SLO Budget Bar
 *
 * Horizontal bar visualizing error budget consumption.
 * Color shifts from green to yellow to red as budget is consumed.
 */

import React from 'react';

interface SLOBudgetBarProps {
    /** Amount of budget consumed (same unit as total). */
    consumed: number;
    /** Total error budget available. */
    total: number;
    /** Label displayed to the left of the bar. */
    label: string;
}

/** Map remaining-percentage to a CSS color variable. */
function barColor(remainingPercent: number): string {
    if (remainingPercent > 50) { return 'var(--vscode-testing-iconPassed)'; }
    if (remainingPercent > 20) { return 'var(--vscode-list-warningForeground)'; }
    return 'var(--vscode-errorForeground)';
}

/**
 * Error budget consumption bar.
 *
 * Displays a horizontal bar showing how much error budget has been used.
 * The fill color indicates urgency based on remaining budget.
 */
export function SLOBudgetBar({ consumed, total, label }: SLOBudgetBarProps): React.JSX.Element {
    const safeTotal = total > 0 ? total : 1;
    const fillPercent = Math.min((consumed / safeTotal) * 100, 100);
    const remainingPercent = 100 - fillPercent;
    const color = barColor(remainingPercent);

    return (
        <div className="flex flex-col gap-1">
            <div className="flex justify-between text-xs">
                <span className="text-ml-text-muted">{label}</span>
                <span className="text-ml-text font-mono">
                    {remainingPercent.toFixed(1)}% remaining
                </span>
            </div>
            <div className="h-2 rounded-full bg-ml-surface overflow-hidden">
                <div
                    className="h-full rounded-full"
                    style={{
                        width: `${fillPercent}%`,
                        backgroundColor: color,
                        transition: 'width 0.4s ease-out',
                    }}
                />
            </div>
        </div>
    );
}
