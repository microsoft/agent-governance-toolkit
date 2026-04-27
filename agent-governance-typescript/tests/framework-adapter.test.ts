// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { AgentMeshClient } from '../src/client';
import { GenericFrameworkAdapter } from '../src/framework-adapter';
import { GovernanceMetrics } from '../src/metrics';
import { ExecutionRing } from '../src/types';

describe('GenericFrameworkAdapter', () => {
  it('runs allowed invocations through governance and captures traces', async () => {
    const client = AgentMeshClient.create('adapter-agent', {
      policyRules: [
        { action: 'framework.tool_call.search', effect: 'allow' },
      ],
    });
    const metrics = new GovernanceMetrics({ enabled: true });
    const adapter = new GenericFrameworkAdapter(client, { metrics });

    const result = await adapter.run(
      {
        name: 'search',
        kind: 'tool_call',
        input: { query: 'status' },
      },
      async () => ({ items: 3 }),
    );

    expect(result.allowed).toBe(true);
    expect(result.output).toEqual({ items: 3 });
    expect(result.trace.spans).toHaveLength(1);
    expect(metrics.getSnapshot().counters['trace.captures']).toBe(1);
  });

  it('blocks denied invocations before the handler runs', async () => {
    const client = AgentMeshClient.create('adapter-agent', {
      policyRules: [
        { action: '*', effect: 'deny' },
      ],
    });
    const adapter = new GenericFrameworkAdapter(client);
    const handler = jest.fn(async () => 'should-not-run');

    const result = await adapter.run(
      {
        name: 'dangerous-tool',
        kind: 'tool_call',
      },
      handler,
    );

    expect(result.allowed).toBe(false);
    expect(handler).not.toHaveBeenCalled();
    expect(result.trace.success).toBe(false);
  });

  it('supports custom action resolution for future framework adapters', async () => {
    const client = AgentMeshClient.create('adapter-agent', {
      policyRules: [
        { action: 'langchain.invoke.chat_model', effect: 'allow' },
      ],
    });
    const adapter = new GenericFrameworkAdapter(client, {
      actionResolver: (invocation) => `langchain.invoke.${invocation.name}`,
    });

    const result = await adapter.run(
      {
        name: 'chat_model',
        kind: 'llm_inference',
      },
      async () => 'ok',
    );

    expect(result.allowed).toBe(true);
    expect(result.action).toBe('langchain.invoke.chat_model');
  });

  it('exposes begin/complete hooks for framework-specific wrappers', async () => {
    const client = AgentMeshClient.create('adapter-agent', {
      policyRules: [
        { action: 'framework.tool_call.lookup', effect: 'allow' },
      ],
      execution: {
        agentRing: ExecutionRing.Ring2,
        actionRings: {
          'framework.tool_call.lookup': ExecutionRing.Ring2,
        },
      },
    });
    const adapter = new GenericFrameworkAdapter(client);

    const handle = await adapter.beginInvocation({
      name: 'lookup',
      kind: 'tool_call',
      input: { id: '123' },
    });
    const result = handle.complete({ output: { found: true } });

    expect(handle.allowed).toBe(true);
    expect(result.trace.traceId).toBeDefined();
    expect(result.output).toEqual({ found: true });
  });

  it('allows an explicitly matching agentId', async () => {
    const client = AgentMeshClient.create('adapter-agent', {
      policyRules: [
        { action: 'framework.tool_call.lookup', effect: 'allow' },
      ],
    });
    const adapter = new GenericFrameworkAdapter(client);
    const handler = jest.fn(async () => ({ found: true }));

    const result = await adapter.run(
      {
        name: 'lookup',
        kind: 'tool_call',
        agentId: client.identity.did,
        input: { id: '123' },
      },
      handler,
    );

    expect(result.allowed).toBe(true);
    expect(handler).toHaveBeenCalledTimes(1);
    expect(result.invocation.agentId).toBe(client.identity.did);
    expect(result.trace.agentId).toBe(client.identity.did);
  });

  it('binds omitted agentId to the client identity', async () => {
    const client = AgentMeshClient.create('adapter-agent', {
      policyRules: [
        { action: 'framework.tool_call.lookup', effect: 'allow' },
      ],
    });
    const adapter = new GenericFrameworkAdapter(client);
    const handler = jest.fn(async () => ({ found: true }));

    const result = await adapter.run(
      {
        name: 'lookup',
        kind: 'tool_call',
        input: { id: '123' },
      },
      handler,
    );

    expect(result.allowed).toBe(true);
    expect(handler).toHaveBeenCalledTimes(1);
    expect(result.invocation.agentId).toBe(client.identity.did);
    expect(result.trace.agentId).toBe(client.identity.did);
  });

  it('treats an empty-string agentId as no caller assertion', async () => {
    const client = AgentMeshClient.create('adapter-agent', {
      policyRules: [
        { action: 'framework.tool_call.lookup', effect: 'allow' },
      ],
    });
    const adapter = new GenericFrameworkAdapter(client);
    const handler = jest.fn(async () => ({ found: true }));

    const result = await adapter.run(
      {
        name: 'lookup',
        kind: 'tool_call',
        agentId: '',
        input: { id: '123' },
      },
      handler,
    );

    expect(result.allowed).toBe(true);
    expect(handler).toHaveBeenCalledTimes(1);
    expect(result.invocation.agentId).toBe(client.identity.did);
    expect(result.trace.agentId).toBe(client.identity.did);
  });

  it('fails closed when a caller asserts a different agentId', async () => {
    const client = AgentMeshClient.create('adapter-agent', {
      policyRules: [
        { action: 'framework.tool_call.lookup', effect: 'allow' },
      ],
    });
    const metrics = new GovernanceMetrics({ enabled: true });
    const adapter = new GenericFrameworkAdapter(client, { metrics });
    const handler = jest.fn(async () => ({ found: true }));

    const result = await adapter.run(
      {
        name: 'lookup',
        kind: 'tool_call',
        agentId: 'did:agentmesh:spoofed:1234',
        input: { id: '123' },
      },
      handler,
    );

    expect(result.allowed).toBe(false);
    expect(handler).not.toHaveBeenCalled();
    expect(result.reason).toContain('Caller-asserted agentId');
    expect(result.invocation.agentId).toBe(client.identity.did);
    expect(result.trace.agentId).toBe(client.identity.did);
    expect(result.governanceResult.decision).toBe('deny');
    expect(result.governanceResult.auditEntry.agentId).toBe(client.identity.did);
    expect(metrics.getSnapshot().events.some((event) =>
      event.name === 'trust.score' && event.attributes.agentId === client.identity.did
    )).toBe(true);
  });
});
