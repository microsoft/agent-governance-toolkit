// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Mock Topology Backend Service
 *
 * Simulates a live agent mesh with agents registering/deregistering,
 * trust scores shifting, bridges connecting/disconnecting, and
 * delegations expiring. Provides a realistic visual feed.
 */

import {
    AgentTopologyDataProvider,
    AgentNode,
    BridgeStatus,
    DelegationChain,
    ExecutionRing,
} from '../views/topologyTypes';
import { clamp, drift } from './mockUtils';

/** ISO timestamp for N minutes ago. */
function minutesAgo(n: number): string {
    return new Date(Date.now() - n * 60_000).toISOString();
}

/**
 * Creates an AgentTopologyDataProvider that simulates a live mesh.
 * Trust scores drift, bridges flap, delegations expire and renew.
 */
export function createMockTopologyBackend(): AgentTopologyDataProvider {
    const agents: AgentNode[] = [
        {
            did: 'did:mesh:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
            trustScore: 920,
            ring: ExecutionRing.Ring1Supervisor,
            registeredAt: '2026-03-20T08:15:00Z',
            lastActivity: minutesAgo(2),
            capabilities: ['tool_call', 'file_read', 'policy_evaluate'],
        },
        {
            did: 'did:mesh:f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6',
            trustScore: 580,
            ring: ExecutionRing.Ring2User,
            registeredAt: '2026-03-18T11:42:00Z',
            lastActivity: minutesAgo(8),
            capabilities: ['tool_call'],
        },
        {
            did: 'did:mesh:0a1b2c3d4e5f0a1b2c3d4e5f6a7b8c9d',
            trustScore: 310,
            ring: ExecutionRing.Ring3Sandbox,
            registeredAt: '2026-03-21T16:00:00Z',
            lastActivity: minutesAgo(25),
            capabilities: [],
        },
        {
            did: 'did:mesh:b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9',
            trustScore: 750,
            ring: ExecutionRing.Ring2User,
            registeredAt: '2026-03-22T09:30:00Z',
            lastActivity: minutesAgo(1),
            capabilities: ['tool_call', 'file_write'],
        },
    ];

    const bridges: BridgeStatus[] = [
        { protocol: 'A2A', connected: true, peerCount: 4 },
        { protocol: 'MCP', connected: true, peerCount: 2 },
        { protocol: 'IATP', connected: false, peerCount: 0 },
    ];

    const delegations: DelegationChain[] = [
        {
            fromDid: agents[0].did,
            toDid: agents[1].did,
            capability: 'tool_call',
            expiresIn: '2h',
        },
        {
            fromDid: agents[0].did,
            toDid: agents[2].did,
            capability: 'file_read',
            expiresIn: '30m',
        },
        {
            fromDid: agents[3].did,
            toDid: agents[1].did,
            capability: 'file_write',
            expiresIn: '1h',
        },
    ];

    let callCount = 0;

    return {
        getAgents(): AgentNode[] {
            callCount++;
            for (const a of agents) {
                a.trustScore = Math.round(drift(a.trustScore, 20, 100, 980));
                a.lastActivity = minutesAgo(Math.floor(Math.random() * 15));
                // Occasional ring change
                if (callCount % 10 === 0 && a.trustScore < 400) {
                    a.ring = ExecutionRing.Ring3Sandbox;
                } else if (a.trustScore > 800) {
                    a.ring = ExecutionRing.Ring1Supervisor;
                }
            }
            return [...agents];
        },

        getBridges(): BridgeStatus[] {
            // Flap IATP bridge occasionally
            bridges[2].connected = callCount % 5 === 0;
            bridges[2].peerCount = bridges[2].connected ? 1 : 0;
            // Drift peer counts
            bridges[0].peerCount = clamp(
                bridges[0].peerCount + (Math.random() > 0.7 ? 1 : 0) - (Math.random() > 0.8 ? 1 : 0),
                2, 8,
            );
            return [...bridges];
        },

        getDelegations(): DelegationChain[] {
            // Simulate expiry countdown
            const times = ['2h', '1h 45m', '1h 30m', '1h', '45m', '30m', '15m', '5m'];
            for (const d of delegations) {
                d.expiresIn = times[Math.floor(Math.random() * times.length)];
            }
            return [...delegations];
        },
    };
}
