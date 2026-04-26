// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Topology Detail
 *
 * Root component for the full-panel agent topology visualization.
 * Composes ForceGraph, legend, zoom controls, and a stats bar.
 * Accepts data via prop or extension message subscription.
 */

import React, { useState, useRef, useEffect, useCallback } from 'react';
import type { TopologyDetailData } from '../shared/types';
import { useExtensionMessage } from '../shared/useExtensionMessage';
import { getVSCodeAPI } from '../shared/vscode';
import { DetailShell } from '../shared/DetailShell';
import { Tooltip } from '../shared/Tooltip';
import { HELP } from '../shared/helpContent';
import { ForceGraph } from './ForceGraph';
import { TopologyLegend } from './TopologyLegend';
import { TopologyControls } from './TopologyControls';

// ---------------------------------------------------------------------------
// Zoom constants
// ---------------------------------------------------------------------------

const ZOOM_MIN = 0.3;
const ZOOM_MAX = 3.0;
const ZOOM_STEP = 0.2;
const DEFAULT_WIDTH = 800;
const DEFAULT_HEIGHT = 600;

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface TopologyDetailProps {
    /** If provided, skip extension message subscription. */
    data?: TopologyDetailData;
    /** When true, render content only (no DetailShell wrapper). Used by Hub embedding. */
    embedded?: boolean;
}

// ---------------------------------------------------------------------------
// Zoom helpers
// ---------------------------------------------------------------------------

/** Clamp a zoom level to the allowed range. */
function clampZoom(z: number): number {
    return Math.max(ZOOM_MIN, Math.min(ZOOM_MAX, z));
}

// ---------------------------------------------------------------------------
// Stats bar sub-components
// ---------------------------------------------------------------------------

/** Compute average trust across all nodes. */
function meanTrust(nodes: TopologyDetailData['nodes']): number {
    if (nodes.length === 0) { return 0; }
    const sum = nodes.reduce((acc, n) => acc + n.trust, 0);
    return Math.round(sum / nodes.length);
}

/** Bridge status dot: green when connected, gray when not. */
function BridgeDot({ connected }: { connected: boolean }): React.JSX.Element {
    const color = connected
        ? 'var(--vscode-testing-iconPassed)'
        : 'var(--ml-text-muted)';
    return (
        <span
            className="inline-block w-2 h-2 rounded-full"
            style={{ backgroundColor: color }}
        />
    );
}

/** Stats bar showing agent count, bridge count, and average trust. */
function StatsBar({ data }: { data: TopologyDetailData }): React.JSX.Element {
    const avg = meanTrust(data.nodes);
    return (
        <div className="flex items-center gap-ml-md px-ml-md py-ml-xs text-xs text-ml-text-muted border-t border-ml-border shrink-0">
            <span className="flex items-center gap-0.5">
                {data.nodes.length} agents <Tooltip text={HELP.topology.agents} />
            </span>
            <span className="text-ml-border">&middot;</span>
            <span className="flex items-center gap-0.5">
                {data.bridges.length} bridges <Tooltip text={HELP.topology.bridges} />
            </span>
            <span className="text-ml-border">&middot;</span>
            <span className="flex items-center gap-0.5">
                Trust: {avg} <Tooltip text={HELP.topology.trust} />
            </span>
            <span className="text-ml-border">&middot;</span>
            <div className="flex items-center gap-1">
                {data.bridges.map((b) => (
                    <div key={b.protocol} className="flex items-center gap-0.5" title={b.protocol}>
                        <BridgeDot connected={b.connected} />
                        <span className="text-[10px]">{b.protocol}</span>
                    </div>
                ))}
            </div>
        </div>
    );
}

// ---------------------------------------------------------------------------
// Loading state
// ---------------------------------------------------------------------------

/** Placeholder shown while waiting for initial data. */
function LoadingState(): React.JSX.Element {
    return (
        <div className="flex items-center justify-center h-full text-ml-text-muted text-sm">
            <i className="codicon codicon-loading codicon-modifier-spin mr-2" />
            Waiting for topology data...
        </div>
    );
}

// ---------------------------------------------------------------------------
// Container size hook
// ---------------------------------------------------------------------------

/** Track the size of a container element via ResizeObserver. */
function useContainerSize(): {
    ref: React.RefObject<HTMLDivElement | null>;
    width: number;
    height: number;
} {
    const ref = useRef<HTMLDivElement | null>(null);
    const [size, setSize] = useState({ width: DEFAULT_WIDTH, height: DEFAULT_HEIGHT });

    useEffect(() => {
        const el = ref.current;
        if (!el) { return; }

        const observer = new ResizeObserver((entries) => {
            const entry = entries[0];
            if (!entry) { return; }
            const { width, height } = entry.contentRect;
            if (width > 0 && height > 0) {
                setSize({ width: Math.round(width), height: Math.round(height) });
            }
        });
        observer.observe(el);
        return () => { observer.disconnect(); };
    }, []);

    return { ref, width: size.width, height: size.height };
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

/**
 * Root topology detail panel.
 *
 * Subscribes to extension messages for topology data, manages zoom state,
 * and composes the force graph with overlay controls and a stats bar.
 */
export function TopologyDetail({ data: propData, embedded }: TopologyDetailProps): React.JSX.Element {
    const msgData = useExtensionMessage<TopologyDetailData>('topologyDetailUpdate');
    const data = propData ?? msgData;

    const [zoom, setZoom] = useState(1.0);
    const { ref, width, height } = useContainerSize();

    const handleRefresh = useCallback(() => {
        getVSCodeAPI().postMessage({ type: 'refresh' });
    }, []);
    const handleZoomIn = useCallback(() => setZoom((z) => clampZoom(z + ZOOM_STEP)), []);
    const handleZoomOut = useCallback(() => setZoom((z) => clampZoom(z - ZOOM_STEP)), []);
    const handleZoomReset = useCallback(() => setZoom(1.0), []);
    const handleSelectNode = useCallback((id: string) => {
        getVSCodeAPI().postMessage({ type: 'selectAgent', did: id });
    }, []);

    const content = data ? (
        <div className="flex flex-col h-full">
            <div ref={ref} className="relative flex-1 min-h-0">
                <ForceGraph
                    nodes={data.nodes} edges={data.edges}
                    width={width} height={height} zoom={zoom} onSelectNode={handleSelectNode}
                />
                <TopologyLegend />
                <TopologyControls zoom={zoom} onZoomIn={handleZoomIn} onZoomOut={handleZoomOut} onReset={handleZoomReset} />
            </div>
            <StatsBar data={data} />
        </div>
    ) : <LoadingState />;

    if (embedded) { return content; }

    return (
        <DetailShell title="Agent Topology" timestamp={data?.fetchedAt ?? null} onRefresh={handleRefresh}>
            {content}
        </DetailShell>
    );
}
