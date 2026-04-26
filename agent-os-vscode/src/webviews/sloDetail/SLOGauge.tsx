// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * SLO Gauge
 *
 * Pure SVG radial gauge for displaying a percentage value against a target.
 * Uses a 270-degree arc with color derived from health status.
 */

import React from 'react';
import { percentColor } from '../sidebar/healthColors';

interface SLOGaugeProps {
    /** Current value (0-100). */
    value: number;
    /** Target threshold (0-100). */
    target: number;
    /** Label shown below the gauge. */
    label: string;
}

/** Arc geometry constants. */
const RADIUS = 48;
const CENTER = 60;
const STROKE_WIDTH = 8;
const ARC_DEGREES = 270;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;
const ARC_LENGTH = (ARC_DEGREES / 360) * CIRCUMFERENCE;

/** Map Tailwind health class to a CSS variable for SVG stroke. */
const COLOR_MAP: Record<string, string> = {
    'text-ml-success': 'var(--vscode-testing-iconPassed)',
    'text-ml-warning': 'var(--vscode-list-warningForeground)',
    'text-ml-error': 'var(--vscode-errorForeground)',
};

/** Compute the stroke color CSS variable from a health class. */
function strokeColor(healthClass: string): string {
    return COLOR_MAP[healthClass] ?? 'var(--vscode-foreground)';
}

/** Compute stroke-dashoffset for the filled portion of the arc. */
function arcOffset(value: number): number {
    const clamped = Math.max(0, Math.min(100, value));
    const filled = (clamped / 100) * ARC_LENGTH;
    return ARC_LENGTH - filled;
}

/**
 * Radial gauge with 270-degree arc.
 *
 * Displays a percentage metric with color coding based on
 * proximity to target. Animates via CSS transition.
 */
export function SLOGauge({ value, target, label }: SLOGaugeProps): React.JSX.Element {
    const healthClass = percentColor(value, target);
    const color = strokeColor(healthClass);
    const offset = arcOffset(value);

    return (
        <div className="flex flex-col items-center">
            <svg viewBox="0 0 120 120" className="w-28 h-28">
                <circle
                    cx={CENTER}
                    cy={CENTER}
                    r={RADIUS}
                    fill="none"
                    stroke="var(--ml-surface)"
                    strokeWidth={STROKE_WIDTH}
                    strokeDasharray={`${ARC_LENGTH} ${CIRCUMFERENCE}`}
                    strokeLinecap="round"
                    transform={`rotate(-225 ${CENTER} ${CENTER})`}
                />
                <circle
                    cx={CENTER}
                    cy={CENTER}
                    r={RADIUS}
                    fill="none"
                    stroke={color}
                    strokeWidth={STROKE_WIDTH}
                    strokeDasharray={`${ARC_LENGTH} ${CIRCUMFERENCE}`}
                    strokeDashoffset={offset}
                    strokeLinecap="round"
                    transform={`rotate(-225 ${CENTER} ${CENTER})`}
                    style={{ transition: 'stroke-dashoffset 0.6s ease-out' }}
                />
                <text
                    x={CENTER}
                    y={CENTER - 4}
                    textAnchor="middle"
                    dominantBaseline="central"
                    fill="var(--ml-text-bright)"
                    fontSize="20"
                    fontWeight="600"
                    fontFamily="var(--ml-font)"
                >
                    {value.toFixed(1)}%
                </text>
                <text
                    x={CENTER}
                    y={CENTER + 16}
                    textAnchor="middle"
                    dominantBaseline="central"
                    fill="var(--ml-text-muted)"
                    fontSize="10"
                    fontFamily="var(--ml-font)"
                >
                    target {target}%
                </text>
            </svg>
            <span className="text-xs text-ml-text-muted mt-1">{label}</span>
        </div>
    );
}
