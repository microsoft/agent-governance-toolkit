// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Unit tests for MockTopologyBackend.
 *
 * Validates the shape, bounds, and drift behavior of the simulated
 * agent mesh topology data feed.
 */

import * as assert from 'assert';
import { createMockTopologyBackend } from '../../mockBackend/MockTopologyBackend';

suite('MockTopologyBackend Test Suite', () => {
    suite('getAgents', () => {
        test('returns an array with length > 0', () => {
            const backend = createMockTopologyBackend();
            const agents = backend.getAgents();
            assert.ok(Array.isArray(agents), 'getAgents should return an array');
            assert.ok(agents.length > 0, 'agents array should not be empty');
        });

        test('each agent has a did string starting with did:mesh:', () => {
            const backend = createMockTopologyBackend();
            const agents = backend.getAgents();
            for (const agent of agents) {
                assert.ok(typeof agent.did === 'string', 'did should be a string');
                assert.ok(agent.did.startsWith('did:mesh:'),
                    `did "${agent.did}" should start with "did:mesh:"`);
            }
        });

        test('each agent trustScore is between 0 and 1000', () => {
            const backend = createMockTopologyBackend();
            // Call multiple times to exercise drift
            for (let i = 0; i < 5; i++) {
                const agents = backend.getAgents();
                for (const agent of agents) {
                    assert.ok(agent.trustScore >= 0 && agent.trustScore <= 1000,
                        `trustScore ${agent.trustScore} for ${agent.did} should be between 0 and 1000`);
                }
            }
        });

        test('each agent ring is 0, 1, 2, or 3', () => {
            const backend = createMockTopologyBackend();
            for (let i = 0; i < 5; i++) {
                const agents = backend.getAgents();
                for (const agent of agents) {
                    assert.ok([0, 1, 2, 3].includes(agent.ring),
                        `ring ${agent.ring} for ${agent.did} should be 0, 1, 2, or 3`);
                }
            }
        });

        test('each agent has capabilities array', () => {
            const backend = createMockTopologyBackend();
            const agents = backend.getAgents();
            for (const agent of agents) {
                assert.ok(Array.isArray(agent.capabilities),
                    `capabilities for ${agent.did} should be an array`);
            }
        });

        test('each agent has registeredAt and lastActivity strings', () => {
            const backend = createMockTopologyBackend();
            const agents = backend.getAgents();
            for (const agent of agents) {
                assert.ok(typeof agent.registeredAt === 'string',
                    'registeredAt should be a string');
                assert.ok(typeof agent.lastActivity === 'string',
                    'lastActivity should be a string');
            }
        });

        test('trust scores change between calls (drift behavior)', () => {
            const backend = createMockTopologyBackend();
            const first = backend.getAgents();
            const firstScores = first.map(a => a.trustScore);
            let drifted = false;
            for (let i = 0; i < 20; i++) {
                const next = backend.getAgents();
                const nextScores = next.map(a => a.trustScore);
                if (nextScores.some((s, idx) => s !== firstScores[idx])) {
                    drifted = true;
                    break;
                }
            }
            assert.ok(drifted, 'Trust scores should drift between calls');
        });
    });

    suite('getBridges', () => {
        test('returns an array with length > 0', () => {
            const backend = createMockTopologyBackend();
            // Must call getAgents first to initialize callCount
            backend.getAgents();
            const bridges = backend.getBridges();
            assert.ok(Array.isArray(bridges), 'getBridges should return an array');
            assert.ok(bridges.length > 0, 'bridges array should not be empty');
        });

        test('each bridge has protocol, connected, and peerCount', () => {
            const backend = createMockTopologyBackend();
            backend.getAgents();
            const bridges = backend.getBridges();
            for (const bridge of bridges) {
                assert.ok(typeof bridge.protocol === 'string',
                    'protocol should be a string');
                assert.ok(typeof bridge.connected === 'boolean',
                    'connected should be a boolean');
                assert.ok(typeof bridge.peerCount === 'number',
                    'peerCount should be a number');
                assert.ok(bridge.peerCount >= 0,
                    `peerCount ${bridge.peerCount} should be >= 0`);
            }
        });

        test('includes expected protocol names', () => {
            const backend = createMockTopologyBackend();
            backend.getAgents();
            const bridges = backend.getBridges();
            const protocols = bridges.map(b => b.protocol);
            assert.ok(protocols.includes('A2A'), 'Should include A2A bridge');
            assert.ok(protocols.includes('MCP'), 'Should include MCP bridge');
            assert.ok(protocols.includes('IATP'), 'Should include IATP bridge');
        });
    });

    suite('getDelegations', () => {
        test('returns an array', () => {
            const backend = createMockTopologyBackend();
            const delegations = backend.getDelegations();
            assert.ok(Array.isArray(delegations), 'getDelegations should return an array');
        });

        test('returns at least one delegation', () => {
            const backend = createMockTopologyBackend();
            const delegations = backend.getDelegations();
            assert.ok(delegations.length > 0, 'Should have at least one delegation');
        });

        test('each delegation has fromDid, toDid, capability, expiresIn', () => {
            const backend = createMockTopologyBackend();
            const delegations = backend.getDelegations();
            for (const d of delegations) {
                assert.ok(typeof d.fromDid === 'string', 'fromDid should be a string');
                assert.ok(typeof d.toDid === 'string', 'toDid should be a string');
                assert.ok(typeof d.capability === 'string', 'capability should be a string');
                assert.ok(typeof d.expiresIn === 'string', 'expiresIn should be a string');
            }
        });

        test('delegation DIDs start with did:mesh:', () => {
            const backend = createMockTopologyBackend();
            const delegations = backend.getDelegations();
            for (const d of delegations) {
                assert.ok(d.fromDid.startsWith('did:mesh:'),
                    `fromDid "${d.fromDid}" should start with "did:mesh:"`);
                assert.ok(d.toDid.startsWith('did:mesh:'),
                    `toDid "${d.toDid}" should start with "did:mesh:"`);
            }
        });

        test('expiresIn values change between calls (drift behavior)', () => {
            const backend = createMockTopologyBackend();
            const first = backend.getDelegations();
            const firstExpiry = first.map(d => d.expiresIn);
            let changed = false;
            for (let i = 0; i < 20; i++) {
                const next = backend.getDelegations();
                const nextExpiry = next.map(d => d.expiresIn);
                if (nextExpiry.some((e, idx) => e !== firstExpiry[idx])) {
                    changed = true;
                    break;
                }
            }
            assert.ok(changed, 'Delegation expiresIn values should change between calls');
        });
    });

    suite('returns fresh copies', () => {
        test('getAgents returns a new array each call', () => {
            const backend = createMockTopologyBackend();
            const a1 = backend.getAgents();
            const a2 = backend.getAgents();
            assert.notStrictEqual(a1, a2, 'Should return a new array reference');
        });

        test('getBridges returns a new array each call', () => {
            const backend = createMockTopologyBackend();
            backend.getAgents();
            const b1 = backend.getBridges();
            const b2 = backend.getBridges();
            assert.notStrictEqual(b1, b2, 'Should return a new array reference');
        });

        test('getDelegations returns a new array each call', () => {
            const backend = createMockTopologyBackend();
            const d1 = backend.getDelegations();
            const d2 = backend.getDelegations();
            assert.notStrictEqual(d1, d2, 'Should return a new array reference');
        });
    });
});
