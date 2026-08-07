---
title: "ADR 0026: Azure Functions PDP behind AI Gateway for Foundry prompt-based agents"
last_reviewed: 2026-05-24
owner: agt-maintainers
---

# ADR 0026: Azure Functions PDP behind AI Gateway for Foundry prompt-based agents

- Status: proposed
- Date: 2026-05-24

## Context

Microsoft Foundry prompt-based agents can invoke MCP tools from the Foundry
backend. Because the tool call originates server-side in Foundry, the
invocation does not naturally traverse the same AI Gateway (Azure API
Management) policy boundary that mediates model traffic. This creates an
asymmetric governance posture: model requests pass through centralized policy
enforcement, while MCP tool calls can bypass it. RFC #2470 raised this gap
and asked for an AGT-recommended pattern that keeps both surfaces inside a
unified Policy Enforcement Point (PEP) / Policy Decision Point (PDP)
boundary, using Azure-native primitives (AI Gateway + Azure Functions) that
customers can adopt today without waiting for native Foundry support.

Several constraints shape the decision:

- the pattern must compose with existing AI Gateway / APIM policy primitives
  (`send-request`, `choose`, `set-header`) rather than require new gateway
  features,
- decision latency directly inflates every model and tool call, so the PDP
  contract must enable short-circuiting and caching,
- the PDP is on the runtime critical path and therefore must default to
  fail-closed with explicit opt-in for fail-open,
- the request context sent to the PDP must be the minimum needed for a
  decision (no raw prompts by default) to limit blast radius,
- the contract must be versioned from day one so the integration can evolve
  without breaking deployed gateway policies.

## Decision

Adopt AI Gateway (APIM) as the PEP and an Azure Function as the PDP for
Foundry prompt-based agent governance, and document this as the
recommended pattern. The pattern is delivered as:

1. this ADR, recording the limitation and the recommended architecture;
2. a runnable reference sample under
   [`examples/foundry-ai-gateway-pdp/`](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/foundry-ai-gateway-pdp)
   containing an APIM policy fragment, a minimal Python Azure Function
   implementing the decision contract, a Bicep / `azd` template, and a
   small latency harness.

The PDP contract is:

- request envelope carries `schemaVersion: "1.0"`, `agentId`, `callerIdentity`,
  `tenantId`, `environment`, `operation` (`model.invoke` or `tool.invoke`),
  `target` (model or MCP tool name), `inputDigest` (SHA-256 of prompt or tool
  args; never the raw text by default), `correlationId`, and `traceparent`;
- response carries `decision` (`allow` | `deny` | `allow_with_conditions` |
  `require_approval`), `reasonCode`, optional `conditions[]`, optional
  `auditAnnotations`, and a `ttlSeconds` hint for gateway-side caching of
  repeated identical decisions;
- the gateway authenticates to the Function using its managed identity plus
  Easy Auth (Microsoft Entra ID) — function keys are not used;
- on transport error, timeout, schema mismatch, or any non-`allow*` decision,
  the gateway fails closed and emits an audit record with the correlation ID;
- fail-open is supported only as an explicit per-route opt-in and must be
  scoped to non-sensitive operations.

MCP traffic is kept inside the gateway boundary by registering the APIM
gateway URL as the MCP server endpoint surfaced to Foundry, so backend tool
invocations traverse the same PEP as model traffic. The reference sample
documents this configuration; alternatives (sidecar MCP proxy) are listed
as non-recommended fallbacks.

## Consequences

Customers get a concrete, Azure-native pattern that closes the Foundry MCP
governance gap today, using only APIM + Functions and without forking
Foundry or each MCP server. The decision contract is small and versioned,
which keeps the PDP implementation language-agnostic and allows AGT to grow a
typed PDP SDK later (tracked as a follow-up `integrations/foundry-ai-gateway/`
component) without breaking deployed gateway policies. Every model and tool
call gains a synchronous Function hop, so adopters must size the Function
plan against their latency SLO and rely on the `ttlSeconds` cache hint for
repeated decisions. The fail-closed default trades availability for
enforcement integrity, which is the correct default for a governance
boundary but must be communicated clearly in operator docs. Because the PDP
sees a digest of prompt/tool input rather than the raw payload by default,
PDP logic that needs the full text must opt in explicitly and accept the
associated data-handling obligations.
