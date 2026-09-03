// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { AgentMeshClient } from '../src/client';
import { GenericFrameworkAdapter } from '../src/framework-adapter';
import { toFrameworkInvocation } from '../src/webmcp';

describe('toFrameworkInvocation', () => {
  it('maps a WebMCP tool call to a governed action with the default prefix', () => {
    const invocation = toFrameworkInvocation(
      { name: 'email.createDraft', annotations: { readOnlyHint: false } },
      { to: 'someone@example.com' },
    );

    expect(invocation.name).toBe('email.createDraft');
    expect(invocation.kind).toBe('tool_call');
    expect(invocation.action).toBe('webmcp.email.createDraft');
    expect(invocation.input).toEqual({ to: 'someone@example.com' });
    expect(invocation.attributes).toEqual({ readOnlyHint: false });
  });

  it('supports a custom action prefix', () => {
    const invocation = toFrameworkInvocation(
      { name: 'search' },
      {},
      undefined,
      { actionPrefix: 'easely.webmcp' },
    );

    expect(invocation.action).toBe('easely.webmcp.search');
  });

  it('passes through unmerged/proposed annotations under a dedicated namespace', () => {
    const invocation = toFrameworkInvocation(
      { name: 'checkout.pay', annotations: { consequentialHint: true, untrustedContentHint: false } },
      {},
    );

    expect(invocation.attributes).toEqual({
      untrustedContentHint: false,
      webmcpAnnotations: { consequentialHint: true },
    });
  });

  it('carries a best-effort agent origin without treating it as verified identity', () => {
    const invocation = toFrameworkInvocation(
      { name: 'checkout.pay' },
      {},
      { agentOrigin: 'google.com' },
    );

    expect(invocation.attributes).toEqual({ assertedAgentOrigin: 'google.com' });
  });

  it('does not let a page-supplied annotation shadow a reserved attribute name', () => {
    const invocation = toFrameworkInvocation(
      {
        name: 'transfer',
        annotations: {
          readOnlyHint: true,
          untrustedContentHint: true,
          assertedAgentOrigin: 'https://trusted.example',
        },
      },
      {},
      { agentOrigin: 'google.com' },
    );

    expect(invocation.attributes).toEqual({
      readOnlyHint: true,
      untrustedContentHint: true,
      assertedAgentOrigin: 'google.com',
      webmcpAnnotations: { assertedAgentOrigin: 'https://trusted.example' },
    });
  });

  it('runs through GenericFrameworkAdapter like any other framework invocation', async () => {
    const client = AgentMeshClient.create('webmcp-agent', {
      policyRules: [{ action: 'webmcp.email.createDraft', effect: 'allow' }],
    });
    const adapter = new GenericFrameworkAdapter(client);

    const invocation = toFrameworkInvocation(
      { name: 'email.createDraft', annotations: { readOnlyHint: false } },
      { to: 'someone@example.com' },
    );

    const result = await adapter.run(invocation, async () => ({ draftId: 'draft-1' }));

    expect(result.allowed).toBe(true);
    expect(result.output).toEqual({ draftId: 'draft-1' });
  });

  it('denies the handler from running when policy blocks the mapped action', async () => {
    const client = AgentMeshClient.create('webmcp-agent', {
      policyRules: [{ action: '*', effect: 'deny' }],
    });
    const adapter = new GenericFrameworkAdapter(client);
    const handler = jest.fn(async () => 'should-not-run');

    const invocation = toFrameworkInvocation({ name: 'checkout.pay' }, { amount: 100 });
    const result = await adapter.run(invocation, handler);

    expect(result.allowed).toBe(false);
    expect(handler).not.toHaveBeenCalled();
  });
});
