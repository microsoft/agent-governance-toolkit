// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// ── WebMCP invocation mapping ──
//
// WebMCP (https://github.com/webmachinelearning/webmcp) lets a web page
// register client-side tools via `document.modelContext.registerTool()`.
// The `execute()` callback for such a tool runs inside the page's own
// script and typically performs its real work by calling back into the
// site's own backend (see webmachinelearning/webmcp#105, "Server-Side
// Verification"). That backend call is the seam where AGT governance
// applies: `toFrameworkInvocation()` shapes a WebMCP tool call into a
// `FrameworkInvocation` so it can be run through the existing
// `GenericFrameworkAdapter`, the same way any other framework tool call
// is governed. This module does not attempt to run policy evaluation
// inside the browser page itself.
//
// Only the two annotations that are merged into the WebMCP spec today
// (`readOnlyHint`, `untrustedContentHint`) are read explicitly. Anything
// else on `annotations` is passed through under `attributes.webmcpAnnotations`
// so callers can act on proposed-but-unmerged hints (e.g. `consequentialHint`,
// webmachinelearning/webmcp#217) without this module hard-coding a shape
// that hasn't landed yet. It is namespaced rather than flattened onto
// `attributes` directly so that a page-supplied annotation name can never
// collide with (and shadow) `attributes.assertedAgentOrigin` in the audit
// trace -- annotations come from the same untrusted page as the tool call
// itself.
//
// IMPORTANT -- this namespacing is an audit-trail-integrity measure only,
// not an origin-verification mechanism, and it does not protect policy
// evaluation: `GenericFrameworkAdapter.beginInvocation()` passes
// `attributes` only into the trace span (see framework-adapter.ts); policy
// conditions are evaluated by `AgentMeshClient.executeWithGovernance()`
// against `action` and `input` alone (client.ts's `policy.evaluate(action,
// input)`), and `input` is the tool call's own page-controlled arguments
// (the second parameter to `toFrameworkInvocation`). A page can put any key
// it wants in `input`, including e.g. `assertedAgentOrigin`, and a policy
// condition that keys on that field would match the forged value --
// `attributes.assertedAgentOrigin` set here is never consulted. Do not
// write policy conditions that trust identity-shaped fields inside
// `input`. If a caller needs to gate on the page's origin, that
// verification must happen in the embedding application *before* calling
// `toFrameworkInvocation`/`adapter.run()` at all (e.g. failing closed and
// never reaching this module), since WebMCP itself does not yet define a
// verified client/origin binding (webmachinelearning/webmcp#96, #105) --
// `client.agentOrigin` here is a best-effort hint, not something this
// module can verify.

import { FrameworkInvocation } from './framework-adapter';

/** Minimal shape of a WebMCP `ModelContextTool`, as much as this module needs. */
export interface WebMcpToolLike {
  name: string;
  annotations?: {
    readOnlyHint?: boolean;
    untrustedContentHint?: boolean;
    [extra: string]: unknown;
  };
}

/**
 * Minimal shape of a WebMCP `ModelContextClient`. Identity fields here are
 * proposals, not merged spec (webmachinelearning/webmcp#96, #105) — treat
 * any of them as best-effort hints, never as verified identity.
 */
export interface WebMcpClientLike {
  agentOrigin?: string;
}

export interface WebMcpInvocationOptions {
  /** Prefix used for the resulting governance action name. Defaults to "webmcp". */
  actionPrefix?: string;
}

/**
 * Maps a WebMCP tool invocation into a `FrameworkInvocation` suitable for
 * `GenericFrameworkAdapter.run()` / `beginInvocation()`.
 */
export function toFrameworkInvocation(
  tool: WebMcpToolLike,
  input: Record<string, unknown> = {},
  client?: WebMcpClientLike,
  options: WebMcpInvocationOptions = {},
): FrameworkInvocation {
  const actionPrefix = options.actionPrefix ?? 'webmcp';

  // Read tool.name exactly once: a getter could otherwise return different
  // values on successive reads, letting the `name` and `action` fields on
  // the resulting invocation disagree. Reject anything that is not a
  // non-empty string so a missing/malformed name (undefined, null, '', 5)
  // can never silently become a real, policy-matchable action like
  // `webmcp.undefined`. Also reject a literal '*' -- it would flow into
  // the constructed action string and could be confused with the wildcard
  // pattern semantics the policy engine itself uses (policy.ts's
  // `matchAction`), rather than being a real tool name.
  const name = tool.name;
  if (typeof name !== 'string' || name.length === 0 || name.includes('*')) {
    throw new Error(
      `toFrameworkInvocation: tool.name must be a non-empty string without '*', got ${JSON.stringify(name)}`,
    );
  }

  // tool.annotations and client.agentOrigin both originate from the
  // untrusted page. Read each exactly once into a local, the same as
  // `name` above: a getter could otherwise return a different value on
  // each access, letting it pass the type check below and then land a
  // different (unchecked) value in `attributes`. Type-check the snapshot
  // explicitly rather than trusting the TypeScript interface at runtime
  // (a plain JS caller, or a page lying through a proxy, can hand us
  // anything): an unexpected shape here (e.g. an array/primitive for
  // `annotations`, or a non-string `agentOrigin`) fails loudly instead of
  // silently destructuring into `{}` or flowing a wrong-typed value into
  // `attributes`.
  const annotations = tool.annotations;
  const agentOrigin = client?.agentOrigin;

  if (
    annotations !== undefined &&
    (typeof annotations !== 'object' || annotations === null || Array.isArray(annotations))
  ) {
    throw new Error(
      `toFrameworkInvocation: tool.annotations must be a plain object if provided, got ${JSON.stringify(annotations)}`,
    );
  }
  if (agentOrigin !== undefined && typeof agentOrigin !== 'string') {
    throw new Error(
      `toFrameworkInvocation: client.agentOrigin must be a string if provided, got ${JSON.stringify(agentOrigin)}`,
    );
  }

  const { readOnlyHint, untrustedContentHint, ...restAnnotations } = annotations ?? {};

  const attributes: Record<string, unknown> = {};
  if (readOnlyHint !== undefined) attributes.readOnlyHint = readOnlyHint;
  if (untrustedContentHint !== undefined) attributes.untrustedContentHint = untrustedContentHint;
  if (agentOrigin !== undefined) attributes.assertedAgentOrigin = agentOrigin;
  if (Object.keys(restAnnotations).length > 0) attributes.webmcpAnnotations = restAnnotations;

  return {
    name,
    kind: 'tool_call',
    action: `${actionPrefix}.${name}`,
    input,
    attributes,
  };
}
