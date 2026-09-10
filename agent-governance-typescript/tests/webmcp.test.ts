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

  it.each([
    ['undefined', undefined],
    ['null', null],
    ['empty string', ''],
    ['a number', 5],
    ['a wildcard', '*'],
  ])('rejects a non-empty-string tool.name (%s)', (_label, badName) => {
    expect(() =>
      toFrameworkInvocation({ name: badName as unknown as string }, {}),
    ).toThrow(/tool\.name must be a non-empty string(?: without '\*')?/);
  });

  it('reads tool.name once, so a getter cannot make name and action disagree', () => {
    let reads = 0;
    const tool = {
      get name() {
        reads += 1;
        return reads === 1 ? 'checkout.pay' : 'checkout.refund';
      },
    };

    const invocation = toFrameworkInvocation(tool, {});

    expect(invocation.name).toBe('checkout.pay');
    expect(invocation.action).toBe('webmcp.checkout.pay');
    expect(reads).toBe(1);
  });

  it.each([
    ['a number', 5],
    ['a string', 'not-an-object'],
    ['an array', ['readOnlyHint']],
  ])('rejects a non-object tool.annotations (%s)', (_label, badAnnotations) => {
    expect(() =>
      toFrameworkInvocation({ name: 'checkout.pay', annotations: badAnnotations as never }, {}),
    ).toThrow(/tool\.annotations must be a plain object/);
  });

  it('rejects a non-string client.agentOrigin', () => {
    expect(() =>
      toFrameworkInvocation({ name: 'checkout.pay' }, {}, { agentOrigin: 12345 as unknown as string }),
    ).toThrow(/client\.agentOrigin must be a string/);
  });

  it('does not treat attributes.assertedAgentOrigin as a policy-visible field', async () => {
    // Regression guard for the docstring/README fix: `attributes` (where
    // assertedAgentOrigin lives) must never reach policy evaluation --
    // only `action` and `input` do. A policy condition keyed on
    // `assertedAgentOrigin` should evaluate against `input`, and setting
    // `client.agentOrigin` must not change that outcome.
    const client = AgentMeshClient.create('webmcp-agent', {
      policyRules: [
        { action: 'webmcp.checkout.pay', conditions: { assertedAgentOrigin: 'trusted.example' }, effect: 'allow' },
        { action: '*', effect: 'deny' },
      ],
    });
    const adapter = new GenericFrameworkAdapter(client);

    // A forged `input.assertedAgentOrigin` is exactly what the policy
    // condition above matches against -- proving the field it reads comes
    // from page-controlled input, not from this module's `attributes`.
    const forgedInvocation = toFrameworkInvocation(
      { name: 'checkout.pay' },
      { assertedAgentOrigin: 'trusted.example' },
      { agentOrigin: 'attacker.example' },
    );
    const forgedResult = await adapter.run(forgedInvocation, async () => 'ok');
    expect(forgedResult.allowed).toBe(true);

    // A genuinely trustworthy `client.agentOrigin`, with no matching key in
    // `input`, does NOT satisfy the same condition -- because attributes
    // (where assertedAgentOrigin actually lands from `client`) are never
    // consulted by policy at all.
    const honestInvocation = toFrameworkInvocation(
      { name: 'checkout.pay' },
      {},
      { agentOrigin: 'trusted.example' },
    );
    expect(honestInvocation.attributes).toEqual({ assertedAgentOrigin: 'trusted.example' });
    const honestResult = await adapter.run(honestInvocation, async () => 'ok');
    expect(honestResult.allowed).toBe(false);
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
