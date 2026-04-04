// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Agent Topology Types, Helpers, and Mock Data
 *
 * Value types, tree item class, helper functions, and mock data provider
 * for the agent mesh topology tree view.
 */

import * as vscode from 'vscode';

// ---------------------------------------------------------------------------
// Data interfaces
// ---------------------------------------------------------------------------

/** Execution ring levels matching the hypervisor privilege model. */
export enum ExecutionRing {
    Ring0Root = 0,
    Ring1Supervisor = 1,
    Ring2User = 2,
    Ring3Sandbox = 3,
}

export const RING_LABELS: Record<ExecutionRing, string> = {
    [ExecutionRing.Ring0Root]: 'Ring 0: Root',
    [ExecutionRing.Ring1Supervisor]: 'Ring 1: Supervisor',
    [ExecutionRing.Ring2User]: 'Ring 2: User Space',
    [ExecutionRing.Ring3Sandbox]: 'Ring 3: Sandbox',
};

/** A single agent in the mesh. */
export interface AgentNode {
    /** Full DID in did:mesh: format. */
    did: string;
    /** Trust score 0-1000. */
    trustScore: number;
    /** Current execution ring. */
    ring: ExecutionRing;
    /** ISO-8601 registration timestamp. */
    registeredAt: string;
    /** ISO-8601 last activity timestamp. */
    lastActivity: string;
    /** Capabilities this agent may exercise. */
    capabilities: string[];
    /** Circuit breaker state (from agent-failsafe fleet data). */
    circuitState?: 'closed' | 'open' | 'half-open';
    /** Total tasks processed. */
    taskCount?: number;
    /** Average response latency in ms. */
    avgLatencyMs?: number;
    /** Trust stage: CBT, KBT, or IBT. */
    trustStage?: string;
}

/** Status of a protocol bridge. */
export interface BridgeStatus {
    /** Protocol name (e.g. "A2A", "MCP", "IATP"). */
    protocol: string;
    /** Whether the bridge is currently connected. */
    connected: boolean;
    /** Number of connected peers. */
    peerCount: number;
}

/** An active delegation between two agents. */
export interface DelegationChain {
    /** DID of the delegating agent. */
    fromDid: string;
    /** DID of the receiving agent. */
    toDid: string;
    /** Delegated capability name. */
    capability: string;
    /** Human-readable expiry (e.g. "2h", "30m"). */
    expiresIn: string;
}

/** Data source contract consumed by the tree view. */
export interface AgentTopologyDataProvider {
    getAgents(): AgentNode[];
    getBridges(): BridgeStatus[];
    getDelegations(): DelegationChain[];
}

// ---------------------------------------------------------------------------
// Tree item types
// ---------------------------------------------------------------------------

export type TopologyItemKind =
    | 'root-agents'
    | 'root-bridges'
    | 'root-delegations'
    | 'agent'
    | 'agent-detail'
    | 'bridge'
    | 'delegation';

export class TopologyItem extends vscode.TreeItem {
    constructor(
        label: string,
        collapsibleState: vscode.TreeItemCollapsibleState,
        public readonly kind: TopologyItemKind,
        public readonly data?: AgentNode | BridgeStatus | DelegationChain | string,
    ) {
        super(label, collapsibleState);
        this.contextValue = kind;
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Truncate a DID for display, keeping the prefix visible. */
export function truncateDid(did: string, maxLen: number = 22): string {
    if (did.length <= maxLen) {
        return did;
    }
    return did.slice(0, maxLen) + '...';
}

/** Return a ThemeIcon colored by trust score tier. */
export function trustIcon(score: number): vscode.ThemeIcon {
    if (score > 700) {
        return new vscode.ThemeIcon('person', new vscode.ThemeColor('testing.iconPassed'));
    }
    if (score >= 400) {
        return new vscode.ThemeIcon('person', new vscode.ThemeColor('list.warningForeground'));
    }
    return new vscode.ThemeIcon('person', new vscode.ThemeColor('errorForeground'));
}

// ---------------------------------------------------------------------------
// Mock data provider
// ---------------------------------------------------------------------------

function mockAgents(): AgentNode[] {
    return [
        {
            did: 'did:mesh:a1b2c3d4e5f6a7b8c9d0e1f2',
            trustScore: 920,
            ring: ExecutionRing.Ring1Supervisor,
            registeredAt: '2026-03-20T08:15:00Z',
            lastActivity: '2026-03-22T14:32:11Z',
            capabilities: ['tool_call', 'file_read', 'policy_evaluate'],
        },
        {
            did: 'did:mesh:f1e2d3c4b5a6f7e8d9c0b1a2',
            trustScore: 580,
            ring: ExecutionRing.Ring2User,
            registeredAt: '2026-03-18T11:42:00Z',
            lastActivity: '2026-03-22T13:05:44Z',
            capabilities: ['tool_call'],
        },
        {
            did: 'did:mesh:0a1b2c3d4e5f0a1b2c3d4e5f',
            trustScore: 310,
            ring: ExecutionRing.Ring3Sandbox,
            registeredAt: '2026-03-21T16:00:00Z',
            lastActivity: '2026-03-22T09:17:33Z',
            capabilities: [],
        },
    ];
}

function mockBridges(): BridgeStatus[] {
    return [
        { protocol: 'A2A', connected: true, peerCount: 4 },
        { protocol: 'MCP', connected: true, peerCount: 2 },
        { protocol: 'IATP', connected: false, peerCount: 0 },
    ];
}

function mockDelegations(): DelegationChain[] {
    return [
        {
            fromDid: 'did:mesh:a1b2c3d4e5f6a7b8c9d0e1f2',
            toDid: 'did:mesh:f1e2d3c4b5a6f7e8d9c0b1a2',
            capability: 'tool_call',
            expiresIn: '2h',
        },
        {
            fromDid: 'did:mesh:a1b2c3d4e5f6a7b8c9d0e1f2',
            toDid: 'did:mesh:0a1b2c3d4e5f0a1b2c3d4e5f',
            capability: 'file_read',
            expiresIn: '30m',
        },
    ];
}

/** Create a mock data provider with realistic test data. */
export function createMockTopologyProvider(): AgentTopologyDataProvider {
    return {
        getAgents: mockAgents,
        getBridges: mockBridges,
        getDelegations: mockDelegations,
    };
}
