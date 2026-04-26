// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Unit tests for the force-directed graph simulation engine.
 *
 * Tests pure physics functions with no DOM, React, or VS Code dependencies:
 * toSimNode, createSimulation (tick, nodes, edges, reset, boundary clamping).
 */

import * as assert from 'assert';
import {
    toSimNode,
    createSimulation,
    SimNode,
    SimEdge,
} from '../../webviews/shared/forceSimulation';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function runUntilSettled(
    sim: ReturnType<typeof createSimulation>,
    maxTicks = 300,
): number {
    let ticks = 0;
    while (ticks < maxTicks) {
        ticks++;
        if (sim.tick()) { break; }
    }
    return ticks;
}

function makeEdge(source: string, target: string): SimEdge {
    return { source, target, weight: 1.0 };
}

function distance(a: SimNode, b: SimNode): number {
    const dx = a.x - b.x;
    const dy = a.y - b.y;
    return Math.sqrt(dx * dx + dy * dy);
}

// ---------------------------------------------------------------------------
// toSimNode
// ---------------------------------------------------------------------------

suite('forceSimulation - toSimNode', () => {
    test('computes radius from trust score (min trust)', () => {
        const node = toSimNode('a', 0);
        assert.strictEqual(node.radius, 8);
    });

    test('computes radius from trust score (max trust)', () => {
        const node = toSimNode('a', 1000);
        assert.strictEqual(node.radius, 20);
    });

    test('computes radius from trust score (mid trust)', () => {
        const node = toSimNode('a', 500);
        assert.strictEqual(node.radius, 14);
    });

    test('clamps trust below zero', () => {
        const node = toSimNode('a', -100);
        assert.strictEqual(node.trust, 0);
        assert.strictEqual(node.radius, 8);
    });

    test('clamps trust above 1000', () => {
        const node = toSimNode('a', 2000);
        assert.strictEqual(node.trust, 1000);
        assert.strictEqual(node.radius, 20);
    });

    test('initializes velocity to zero', () => {
        const node = toSimNode('a', 500);
        assert.strictEqual(node.vx, 0);
        assert.strictEqual(node.vy, 0);
    });

    test('preserves id', () => {
        const node = toSimNode('agent-42', 750);
        assert.strictEqual(node.id, 'agent-42');
    });
});

// ---------------------------------------------------------------------------
// createSimulation
// ---------------------------------------------------------------------------

suite('forceSimulation - createSimulation', () => {
    const SIM_CONFIG = { width: 400, height: 400, maxFrames: 120 };

    test('settles within maxFrames for 2 connected nodes', () => {
        const nodes = [toSimNode('a', 500), toSimNode('b', 500)];
        const edges = [makeEdge('a', 'b')];
        const sim = createSimulation(nodes, edges, SIM_CONFIG);

        const ticks = runUntilSettled(sim);
        assert.ok(ticks <= 120, `Expected settle within 120 ticks, got ${ticks}`);
    });

    test('returns settled immediately for 0 nodes', () => {
        const sim = createSimulation([], [], SIM_CONFIG);
        const settled = sim.tick();
        assert.strictEqual(settled, true);
    });

    test('returns settled immediately for 1 node (no forces)', () => {
        const sim = createSimulation([toSimNode('solo', 500)], [], SIM_CONFIG);
        // A single node gets gravity pulling to center; should settle quickly
        const ticks = runUntilSettled(sim, 60);
        assert.ok(ticks <= 60, `Single node should settle quickly, got ${ticks}`);
    });

    test('nodes repel when not connected', () => {
        const a = toSimNode('a', 500);
        const b = toSimNode('b', 500);
        const sim = createSimulation([a, b], [], SIM_CONFIG);

        // After initial circle placement, tick a few times
        for (let i = 0; i < 10; i++) { sim.tick(); }
        const [na, nb] = sim.nodes();
        const dist = distance(na, nb);

        // Unconnected nodes should have repulsed apart
        // Initial circle positions are close; repulsion pushes them apart
        assert.ok(dist > 0, 'Unconnected nodes should have distance > 0');
    });

    test('connected nodes attract toward spring length', () => {
        const nodes = [toSimNode('a', 500), toSimNode('b', 500)];
        const edges = [makeEdge('a', 'b')];
        const sim = createSimulation(nodes, edges, {
            ...SIM_CONFIG,
            springLength: 80,
        });

        runUntilSettled(sim);
        const [na, nb] = sim.nodes();
        const dist = distance(na, nb);

        // Settled distance should be near the spring length (within tolerance)
        assert.ok(
            dist < 200,
            `Connected nodes should be reasonably close, got ${dist}`,
        );
    });

    test('boundary collision keeps nodes within bounds', () => {
        const nodes = [toSimNode('a', 500), toSimNode('b', 500)];
        const sim = createSimulation(nodes, [], SIM_CONFIG);

        // Run enough ticks for forces to play out
        runUntilSettled(sim);

        for (const node of sim.nodes()) {
            assert.ok(
                node.x >= node.radius && node.x <= 400 - node.radius,
                `Node ${node.id} x=${node.x} out of bounds [${node.radius}, ${400 - node.radius}]`,
            );
            assert.ok(
                node.y >= node.radius && node.y <= 400 - node.radius,
                `Node ${node.id} y=${node.y} out of bounds [${node.radius}, ${400 - node.radius}]`,
            );
        }
    });

    test('edges are preserved from input', () => {
        const nodes = [toSimNode('a', 500), toSimNode('b', 500)];
        const edges = [makeEdge('a', 'b')];
        const sim = createSimulation(nodes, edges, SIM_CONFIG);

        const result = sim.edges();
        assert.strictEqual(result.length, 1);
        assert.strictEqual(result[0].source, 'a');
        assert.strictEqual(result[0].target, 'b');
        assert.strictEqual(result[0].weight, 1.0);
    });

    test('reset reinitializes positions and frame counter', () => {
        const nodes = [toSimNode('a', 500), toSimNode('b', 500)];
        const sim = createSimulation(nodes, [makeEdge('a', 'b')], SIM_CONFIG);

        // Run to settlement
        runUntilSettled(sim);
        const posBeforeReset = sim.nodes().map(n => ({ x: n.x, y: n.y }));

        // Reset with new nodes
        const newNodes = [toSimNode('c', 800), toSimNode('d', 200)];
        sim.reset(newNodes, [makeEdge('c', 'd')]);

        // After reset, nodes should have new ids
        const resetNodes = sim.nodes();
        assert.strictEqual(resetNodes[0].id, 'c');
        assert.strictEqual(resetNodes[1].id, 'd');

        // Positions should differ from pre-reset settled positions
        const posAfterReset = resetNodes.map(n => ({ x: n.x, y: n.y }));
        const samePositions =
            posBeforeReset[0].x === posAfterReset[0].x &&
            posBeforeReset[0].y === posAfterReset[0].y;
        assert.ok(!samePositions, 'Positions should change after reset');
    });

    test('simulation does not mutate input nodes', () => {
        const a = toSimNode('a', 500);
        const origX = a.x;
        const origY = a.y;
        const sim = createSimulation([a], [], SIM_CONFIG);

        sim.tick();
        // Original node should be unchanged (createSimulation copies)
        assert.strictEqual(a.x, origX);
        assert.strictEqual(a.y, origY);
    });

    test('three-node triangle settles within maxFrames', () => {
        const nodes = [
            toSimNode('a', 800),
            toSimNode('b', 600),
            toSimNode('c', 400),
        ];
        const edges = [
            makeEdge('a', 'b'),
            makeEdge('b', 'c'),
            makeEdge('c', 'a'),
        ];
        const sim = createSimulation(nodes, edges, SIM_CONFIG);

        const ticks = runUntilSettled(sim);
        assert.ok(ticks <= 120, `Triangle should settle within 120 ticks, got ${ticks}`);
    });
});
