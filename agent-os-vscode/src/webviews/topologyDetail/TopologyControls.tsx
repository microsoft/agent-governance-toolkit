// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Topology Controls
 *
 * Zoom control overlay with +, -, and Reset buttons.
 * Positioned absolute top-right over the force graph.
 */

import React from 'react';

interface TopologyControlsProps {
    zoom: number;
    onZoomIn: () => void;
    onZoomOut: () => void;
    onReset: () => void;
}

// ---------------------------------------------------------------------------
// Shared button style
// ---------------------------------------------------------------------------

interface ControlButtonProps {
    onClick: () => void;
    label: string;
    icon: string;
}

/** Single square control button with codicon icon. */
function ControlButton({ onClick, label, icon }: ControlButtonProps): React.JSX.Element {
    return (
        <button
            type="button"
            className="flex items-center justify-center w-7 h-7 rounded-ml hover:bg-ml-surface-hover"
            onClick={onClick}
            aria-label={label}
            title={label}
        >
            <i className={`codicon codicon-${icon} text-sm`} />
        </button>
    );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/**
 * Zoom control panel overlay.
 *
 * Displays current zoom percentage and three action buttons.
 * Does not enforce min/max; that is the parent's responsibility.
 */
export function TopologyControls(props: TopologyControlsProps): React.JSX.Element {
    const { zoom, onZoomIn, onZoomOut, onReset } = props;
    const pct = Math.round(zoom * 100);

    return (
        <div
            className="absolute top-2 right-2 flex items-center gap-1 px-2 py-1 rounded-ml"
            style={{ backgroundColor: 'var(--ml-surface)', opacity: 0.9 }}
        >
            <span className="text-[10px] text-ml-text-muted mr-1">{pct}%</span>
            <ControlButton onClick={onZoomIn} label="Zoom in" icon="add" />
            <ControlButton onClick={onZoomOut} label="Zoom out" icon="dash" />
            <ControlButton onClick={onReset} label="Reset zoom" icon="screen-normal" />
        </div>
    );
}
