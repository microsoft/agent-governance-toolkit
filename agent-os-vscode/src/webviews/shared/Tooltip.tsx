// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Tooltip
 *
 * Lightweight hover tooltip using Tailwind group-hover pattern.
 * Shows styled popover above the trigger element.
 */

import React from 'react';

interface TooltipProps {
    /** Tooltip text shown on hover. */
    text: string;
    /** Trigger element. Defaults to an info icon if omitted. */
    children?: React.ReactNode;
}

/** Default trigger: a small info icon visible on hover context. */
const InfoIcon = <i className="codicon codicon-info text-[10px] text-ml-text-muted" />;

export function Tooltip({ text, children }: TooltipProps): React.JSX.Element {
    return (
        <span className="relative inline-flex group">
            {children ?? InfoIcon}
            <span
                className="absolute bottom-full left-1/2 -translate-x-1/2 mb-1.5
                           px-ml-sm py-ml-xs rounded-ml text-xs text-ml-text
                           bg-ml-surface border border-ml-border shadow-lg
                           max-w-[240px] whitespace-normal leading-tight
                           opacity-0 group-hover:opacity-100 pointer-events-none
                           transition-opacity duration-150 z-50"
                role="tooltip"
            >
                {text}
            </span>
        </span>
    );
}
