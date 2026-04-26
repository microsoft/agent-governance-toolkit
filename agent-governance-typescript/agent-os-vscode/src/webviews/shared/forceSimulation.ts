// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Pure force-directed graph simulation engine.
 *
 * No DOM, no React, no browser APIs. Just physics.
 * Used by the topology visualization to compute node positions.
 */

export interface SimNode {
    id: string;
    x: number;
    y: number;
    vx: number;
    vy: number;
    radius: number;
    trust: number; // 0-1000, affects radius and color
}

export interface SimEdge {
    source: string;
    target: string;
    weight: number; // 0-1, affects spring strength
}

export interface SimConfig {
    repulsion: number;    // repulsive force constant (default: 2000)
    springLength: number; // rest length for springs (default: 100)
    stiffness: number;    // spring stiffness (default: 0.005)
    gravity: number;      // centripetal gravity (default: 0.01)
    damping: number;      // velocity damping (default: 0.9)
    maxFrames: number;    // frames until auto-settle (default: 120)
    width: number;        // simulation bounds width (default: 800)
    height: number;       // simulation bounds height (default: 600)
}

export interface Simulation {
    /** Advance one frame. Returns true when settled. */
    tick(): boolean;
    /** Get current node positions. */
    nodes(): readonly SimNode[];
    /** Get edges (unchanged from input). */
    edges(): readonly SimEdge[];
    /** Reset with new data. Frame counter resets. */
    reset(nodes: SimNode[], edges: SimEdge[]): void;
}

const DEFAULT_CONFIG: SimConfig = {
    repulsion: 2000,
    springLength: 100,
    stiffness: 0.005,
    gravity: 0.01,
    damping: 0.9,
    maxFrames: 120,
    width: 800,
    height: 600,
};

const MAX_VELOCITY = 15;
const SETTLE_THRESHOLD = 0.5;

/** Create a SimNode from raw topology data. Radius = 8 + (trust / 1000) * 12. */
export function toSimNode(id: string, trust: number): SimNode {
    const clampedTrust = Math.max(0, Math.min(1000, trust));
    return {
        id,
        x: 0,
        y: 0,
        vx: 0,
        vy: 0,
        radius: 8 + (clampedTrust / 1000) * 12,
        trust: clampedTrust,
    };
}

function initCirclePositions(
    nodeList: SimNode[],
    width: number,
    height: number,
): void {
    const cx = width / 2;
    const cy = height / 2;
    const r = Math.min(width, height) * 0.3;
    const count = nodeList.length;

    for (let i = 0; i < count; i++) {
        const angle = (2 * Math.PI * i) / Math.max(count, 1);
        nodeList[i].x = cx + r * Math.cos(angle);
        nodeList[i].y = cy + r * Math.sin(angle);
        nodeList[i].vx = 0;
        nodeList[i].vy = 0;
    }
}

function applyRepulsion(nodeList: SimNode[], repulsion: number): void {
    for (let i = 0; i < nodeList.length; i++) {
        for (let j = i + 1; j < nodeList.length; j++) {
            const a = nodeList[i];
            const b = nodeList[j];
            const dx = b.x - a.x;
            const dy = b.y - a.y;
            const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
            const force = repulsion / (dist * dist);
            const fx = (dx / dist) * force;
            const fy = (dy / dist) * force;
            a.vx -= fx;
            a.vy -= fy;
            b.vx += fx;
            b.vy += fy;
        }
    }
}

function applyAttraction(
    nodeList: SimNode[],
    edgeList: readonly SimEdge[],
    springLength: number,
    stiffness: number,
): void {
    const nodeMap = new Map<string, SimNode>();
    for (const node of nodeList) {
        nodeMap.set(node.id, node);
    }

    for (const edge of edgeList) {
        const src = nodeMap.get(edge.source);
        const tgt = nodeMap.get(edge.target);
        if (!src || !tgt) { continue; }

        const dx = tgt.x - src.x;
        const dy = tgt.y - src.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist === 0) { continue; }

        const displacement = dist - springLength;
        const force = displacement * stiffness * edge.weight;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        src.vx += fx;
        src.vy += fy;
        tgt.vx -= fx;
        tgt.vy -= fy;
    }
}

function applyGravity(
    nodeList: SimNode[],
    gravity: number,
    width: number,
    height: number,
): void {
    const cx = width / 2;
    const cy = height / 2;

    for (const node of nodeList) {
        node.vx += (cx - node.x) * gravity;
        node.vy += (cy - node.y) * gravity;
    }
}

function applyVelocities(
    nodeList: SimNode[],
    damping: number,
    width: number,
    height: number,
): void {
    for (const node of nodeList) {
        node.vx *= damping;
        node.vy *= damping;
        node.vx = Math.max(-MAX_VELOCITY, Math.min(MAX_VELOCITY, node.vx));
        node.vy = Math.max(-MAX_VELOCITY, Math.min(MAX_VELOCITY, node.vy));
        node.x += node.vx;
        node.y += node.vy;
        clampToBounds(node, width, height);
    }
}

function clampToBounds(node: SimNode, width: number, height: number): void {
    const minX = node.radius;
    const maxX = width - node.radius;
    const minY = node.radius;
    const maxY = height - node.radius;

    if (node.x < minX) { node.x = minX; node.vx = -node.vx; }
    if (node.x > maxX) { node.x = maxX; node.vx = -node.vx; }
    if (node.y < minY) { node.y = minY; node.vy = -node.vy; }
    if (node.y > maxY) { node.y = maxY; node.vy = -node.vy; }
}

function isSettled(nodeList: readonly SimNode[]): boolean {
    for (const node of nodeList) {
        if (Math.abs(node.vx) + Math.abs(node.vy) >= SETTLE_THRESHOLD) {
            return false;
        }
    }
    return true;
}

export function createSimulation(
    initialNodes: SimNode[],
    initialEdges: SimEdge[],
    config?: Partial<SimConfig>,
): Simulation {
    const cfg: SimConfig = { ...DEFAULT_CONFIG, ...config };
    let nodeList: SimNode[] = [];
    let edgeList: SimEdge[] = [];
    let frame = 0;

    function ingest(nodes: SimNode[], edges: SimEdge[]): void {
        nodeList = nodes.map((n) => ({ ...n }));
        edgeList = edges.map((e) => ({ ...e }));
        frame = 0;
        initCirclePositions(nodeList, cfg.width, cfg.height);
    }

    ingest(initialNodes, initialEdges);

    return {
        tick(): boolean {
            frame++;
            applyRepulsion(nodeList, cfg.repulsion);
            applyAttraction(nodeList, edgeList, cfg.springLength, cfg.stiffness);
            applyGravity(nodeList, cfg.gravity, cfg.width, cfg.height);
            applyVelocities(nodeList, cfg.damping, cfg.width, cfg.height);
            return frame >= cfg.maxFrames || isSettled(nodeList);
        },
        nodes(): readonly SimNode[] {
            return nodeList;
        },
        edges(): readonly SimEdge[] {
            return edgeList;
        },
        reset(nodes: SimNode[], edges: SimEdge[]): void {
            ingest(nodes, edges);
        },
    };
}
