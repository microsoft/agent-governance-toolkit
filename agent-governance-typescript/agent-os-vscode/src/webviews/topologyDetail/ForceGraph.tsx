// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Force Graph
 *
 * Imperative SVG renderer for the force-directed topology graph.
 * React manages lifecycle; the simulation mutates SVG directly via refs.
 * Nodes are colored by trust tier and sized by the simulation engine.
 *
 * DOM elements are created once per data change, then updated in-place
 * each animation frame (setAttribute only -- zero createElement per tick).
 */

import React, { useRef, useEffect, useCallback } from 'react';
import type { TopologyNode, TopologyEdge } from '../shared/types';
import { createSimulation, toSimNode } from '../shared/forceSimulation';
import type { SimNode, SimEdge, Simulation } from '../shared/forceSimulation';

interface ForceGraphProps {
    nodes: TopologyNode[];
    edges: TopologyEdge[];
    width: number;
    height: number;
    zoom: number;
    onSelectNode?: (id: string) => void;
}

// ---------------------------------------------------------------------------
// Trust tier color mapping using VS Code theme tokens
// ---------------------------------------------------------------------------

/** Return a CSS color variable based on the trust score tier. */
function trustFill(trust: number): string {
    if (trust >= 750) { return 'var(--vscode-testing-iconPassed)'; }
    if (trust >= 400) { return 'var(--vscode-list-warningForeground)'; }
    return 'var(--vscode-errorForeground)';
}

/** Truncate a label to at most 12 characters with ellipsis. */
function truncateLabel(label: string): string {
    if (label.length <= 12) { return label; }
    return label.slice(0, 11) + '\u2026';
}

// ---------------------------------------------------------------------------
// SVG element helpers
// ---------------------------------------------------------------------------

/** Clear all children from an SVG group element. */
function clearGroup(g: SVGGElement): void {
    while (g.firstChild) { g.removeChild(g.firstChild); }
}

/** Create an SVG element in the SVG namespace. */
function svgEl<K extends keyof SVGElementTagNameMap>(
    tag: K,
    attrs: Record<string, string>,
): SVGElementTagNameMap[K] {
    const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
    for (const [k, v] of Object.entries(attrs)) { el.setAttribute(k, v); }
    return el;
}

// ---------------------------------------------------------------------------
// Persistent element builders (run once per data change)
// ---------------------------------------------------------------------------

/** Build edge <line> elements, append to group, return array. */
function buildEdgeElements(g: SVGGElement, count: number): SVGLineElement[] {
    const els: SVGLineElement[] = [];
    for (let i = 0; i < count; i++) {
        const line = svgEl('line', {
            stroke: 'var(--vscode-editorWidget-border)',
            'stroke-width': '1',
            'stroke-opacity': '0.5',
        });
        g.appendChild(line);
        els.push(line);
    }
    return els;
}

/** Build node <circle> elements, append to group, return array. */
function buildNodeElements(
    g: SVGGElement,
    simNodes: readonly SimNode[],
    onClick: ((id: string) => void) | undefined,
): SVGCircleElement[] {
    const els: SVGCircleElement[] = [];
    for (const node of simNodes) {
        const circle = svgEl('circle', {
            r: String(node.radius),
            fill: trustFill(node.trust),
            cursor: 'pointer',
        });
        if (onClick) { circle.addEventListener('click', () => onClick(node.id)); }
        g.appendChild(circle);
        els.push(circle);
    }
    return els;
}

/** Build label <text> elements, append to group, return array. */
function buildLabelElements(
    g: SVGGElement,
    simNodes: readonly SimNode[],
    labels: Map<string, string>,
): SVGTextElement[] {
    const els: SVGTextElement[] = [];
    for (const node of simNodes) {
        const text = svgEl('text', {
            'text-anchor': 'middle',
            fill: 'var(--ml-text-muted)',
            'font-size': '10',
            'font-family': 'var(--ml-font)',
        });
        text.textContent = truncateLabel(labels.get(node.id) ?? node.id);
        g.appendChild(text);
        els.push(text);
    }
    return els;
}

// ---------------------------------------------------------------------------
// Per-frame position update (zero DOM creation)
// ---------------------------------------------------------------------------

/** Update edge line positions from the node map. */
function updateEdgePositions(
    els: SVGLineElement[],
    simEdges: readonly SimEdge[],
    nodeMap: Map<string, SimNode>,
): void {
    for (let i = 0; i < els.length; i++) {
        const edge = simEdges[i];
        const src = nodeMap.get(edge.source);
        const tgt = nodeMap.get(edge.target);
        if (!src || !tgt) { continue; }
        const el = els[i];
        el.setAttribute('x1', String(src.x));
        el.setAttribute('y1', String(src.y));
        el.setAttribute('x2', String(tgt.x));
        el.setAttribute('y2', String(tgt.y));
    }
}

/** Update node circle and label positions. */
function updateNodePositions(
    circleEls: SVGCircleElement[],
    labelEls: SVGTextElement[],
    simNodes: readonly SimNode[],
): void {
    for (let i = 0; i < circleEls.length; i++) {
        const node = simNodes[i];
        circleEls[i].setAttribute('cx', String(node.x));
        circleEls[i].setAttribute('cy', String(node.y));
        labelEls[i].setAttribute('x', String(node.x));
        labelEls[i].setAttribute('y', String(node.y + node.radius + 12));
    }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/**
 * Force-directed graph SVG component.
 *
 * Runs a physics simulation via requestAnimationFrame and renders
 * edges and nodes imperatively for performance.
 */
export function ForceGraph(props: ForceGraphProps): React.JSX.Element {
    const { nodes, edges, width, height, zoom, onSelectNode } = props;
    const svgRef = useRef<SVGSVGElement>(null);
    const groupRef = useRef<SVGGElement>(null);
    const simRef = useRef<Simulation | null>(null);
    const rafRef = useRef<number>(0);

    const onSelectRef = useRef(onSelectNode);
    onSelectRef.current = onSelectNode;

    const labelMap = useRef(new Map<string, string>());
    const edgeEls = useRef<SVGLineElement[]>([]);
    const nodeEls = useRef<SVGCircleElement[]>([]);
    const labelEls = useRef<SVGTextElement[]>([]);
    const nodeMapRef = useRef<Map<string, SimNode>>(new Map());

    const animate = useCallback(() => {
        const sim = simRef.current;
        if (!sim) { return; }

        const settled = sim.tick();
        const simNodes = sim.nodes();
        nodeMapRef.current = new Map(simNodes.map((n) => [n.id, n]));
        updateEdgePositions(edgeEls.current, sim.edges(), nodeMapRef.current);
        updateNodePositions(nodeEls.current, labelEls.current, simNodes);

        if (!settled) { rafRef.current = requestAnimationFrame(animate); }
    }, []);

    useEffect(() => {
        const g = groupRef.current;
        if (!g) { return; }

        const simNodes = nodes.map((n) => toSimNode(n.id, n.trust));
        const simEdges: SimEdge[] = edges.map((e) => ({
            source: e.source, target: e.target, weight: 1.0,
        }));

        labelMap.current = new Map(nodes.map((n) => [n.id, n.label]));
        simRef.current = createSimulation(simNodes, simEdges, { width, height });

        clearGroup(g);
        edgeEls.current = buildEdgeElements(g, simEdges.length);
        nodeEls.current = buildNodeElements(g, simNodes, onSelectRef.current);
        labelEls.current = buildLabelElements(g, simNodes, labelMap.current);
        nodeMapRef.current = new Map(simNodes.map((n) => [n.id, n]));

        cancelAnimationFrame(rafRef.current);
        rafRef.current = requestAnimationFrame(animate);

        return () => { cancelAnimationFrame(rafRef.current); };
    }, [nodes, edges, width, height, animate]);

    const tx = width / 2;
    const ty = height / 2;
    const transform = `translate(${tx},${ty}) scale(${zoom}) translate(${-tx},${-ty})`;

    return (
        <svg
            ref={svgRef}
            viewBox={`0 0 ${width} ${height}`}
            style={{ width: '100%', height: '100%' }}
            role="img"
            aria-label="Agent topology graph"
        >
            <g ref={groupRef} transform={transform} />
        </svg>
    );
}
