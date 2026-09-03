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
// collide with (and shadow) a reserved attribute name such as
// `assertedAgentOrigin` -- annotations come from the same untrusted page
// as the tool call itself.

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
  const { readOnlyHint, untrustedContentHint, ...restAnnotations } = tool.annotations ?? {};

  const attributes: Record<string, unknown> = {};
  if (readOnlyHint !== undefined) attributes.readOnlyHint = readOnlyHint;
  if (untrustedContentHint !== undefined) attributes.untrustedContentHint = untrustedContentHint;
  if (client?.agentOrigin !== undefined) attributes.assertedAgentOrigin = client.agentOrigin;
  if (Object.keys(restAnnotations).length > 0) attributes.webmcpAnnotations = restAnnotations;

  return {
    name: tool.name,
    kind: 'tool_call',
    action: `${actionPrefix}.${tool.name}`,
    input,
    attributes,
  };
}
