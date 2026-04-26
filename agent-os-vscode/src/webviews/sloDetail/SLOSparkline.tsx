// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * SLO Sparkline
 *
 * Pure SVG sparkline for displaying a time series as a small line chart
 * with a gradient fill below. Handles empty data gracefully.
 */

import React, { useId } from 'react';

interface SLOSparklineProps {
    /** Array of numeric data points. */
    points: number[];
    /** SVG height in pixels. */
    height?: number;
    /** SVG width as a CSS value. */
    width?: string;
    /** Stroke color as a CSS variable or color string. */
    color?: string;
}

/** Convert data points to an SVG polyline points string. */
function toPolylinePoints(data: number[], w: number, h: number, padding: number): string {
    if (data.length < 2) { return ''; }
    const min = Math.min(...data);
    const max = Math.max(...data);
    const range = max - min || 1;
    const usableH = h - padding * 2;
    const step = w / (data.length - 1);

    return data
        .map((v, i) => {
            const x = i * step;
            const y = padding + usableH - ((v - min) / range) * usableH;
            return `${x},${y}`;
        })
        .join(' ');
}

/** Build the fill polygon points (line + bottom edge). */
function toFillPoints(data: number[], w: number, h: number, padding: number): string {
    const linePoints = toPolylinePoints(data, w, h, padding);
    if (!linePoints) { return ''; }
    const step = w / (data.length - 1);
    const lastX = step * (data.length - 1);
    return `0,${h} ${linePoints} ${lastX},${h}`;
}

/**
 * Compact sparkline chart.
 *
 * Renders a polyline with gradient fill. Returns an empty placeholder
 * when fewer than 2 data points are provided.
 */
export function SLOSparkline({
    points,
    height = 60,
    width = '100%',
    color = 'var(--ml-accent)',
}: SLOSparklineProps): React.JSX.Element {
    const gradientId = useId();
    const svgWidth = 200;
    const padding = 4;

    if (points.length < 2) {
        return (
            <div className="flex items-center justify-center text-xs text-ml-text-muted" style={{ height }}>
                No data
            </div>
        );
    }

    const lineStr = toPolylinePoints(points, svgWidth, height, padding);
    const fillStr = toFillPoints(points, svgWidth, height, padding);

    return (
        <svg
            viewBox={`0 0 ${svgWidth} ${height}`}
            preserveAspectRatio="none"
            style={{ width, height }}
            className="block"
        >
            <defs>
                <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={color} stopOpacity="0.3" />
                    <stop offset="100%" stopColor={color} stopOpacity="0.02" />
                </linearGradient>
            </defs>
            <polygon
                points={fillStr}
                fill={`url(#${gradientId})`}
            />
            <polyline
                points={lineStr}
                fill="none"
                stroke={color}
                strokeWidth="1.5"
                vectorEffect="non-scaling-stroke"
            />
        </svg>
    );
}
