// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import * as assert from 'assert';
import { AgentOSTopologyClient } from '../../services/AgentOSTopologyClient';
import { ExecutionRing } from '../../views/topologyTypes';
import { FakeTransport } from './FakeTransport';

suite('AgentOSTopologyClient', () => {
    const validPayload = {
        agents: [
            { did: 'did:mesh:abc', trust_score: 720, created_at: '2026-03-20T08:00:00Z', last_activity: '2026-03-24T10:00:00Z', capabilities: ['read'] },
            { did: 'did:mesh:def', trust_score: 350, capabilities: [] },
        ],
        bridges: [{ protocol: 'A2A', connected: true, peer_count: 4 }],
        delegations: [{ from_did: 'did:mesh:abc', to_did: 'did:mesh:def', capability: 'read', expires_in: '1h' }],
    };

    test('getAgents returns empty array initially', () => {
        const transport = new FakeTransport();
        transport.setNext({ ok: false, data: undefined, durationMs: 0 });
        const client = new AgentOSTopologyClient(transport);
        assert.deepStrictEqual(client.getAgents(), []);
    });

    test('after refresh, getAgents returns translated agents', async () => {
        const transport = new FakeTransport();
        transport.setNext({ ok: true, data: validPayload, durationMs: 5 });
        const client = new AgentOSTopologyClient(transport);

        await client.refreshForTest();

        const agents = client.getAgents();
        assert.strictEqual(agents.length, 2);
        assert.strictEqual(agents[0].did, 'did:mesh:abc');
        assert.strictEqual(agents[0].trustScore, 720);
        assert.strictEqual(agents[0].ring, ExecutionRing.Ring1Supervisor);
        assert.strictEqual(agents[1].ring, ExecutionRing.Ring3Sandbox);
    });

    test('getBridges and getDelegations return cached data', async () => {
        const transport = new FakeTransport();
        transport.setNext({ ok: true, data: validPayload, durationMs: 5 });
        const client = new AgentOSTopologyClient(transport);

        await client.refreshForTest();

        const bridges = client.getBridges();
        assert.strictEqual(bridges.length, 1);
        assert.strictEqual(bridges[0].protocol, 'A2A');
        assert.strictEqual(bridges[0].peerCount, 4);

        const delegations = client.getDelegations();
        assert.strictEqual(delegations.length, 1);
        assert.strictEqual(delegations[0].fromDid, 'did:mesh:abc');
        assert.strictEqual(delegations[0].toDid, 'did:mesh:def');
        assert.strictEqual(delegations[0].expiresIn, '1h');
    });
});
