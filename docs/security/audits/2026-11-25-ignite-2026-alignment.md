---
title: "2026-11-25 — Ignite 2026 Alignment: Fail-Closed Fixes, MCP 2026-07-28 Envelopes, Agent 365 Bridge"
last_reviewed: 2026-11-25
owner: agt-maintainers
---

# 2026-11-25 — Ignite 2026 Alignment: Fail-Closed Fixes, MCP 2026-07-28 Envelopes, Agent 365 Bridge

PR: TBD (branch `feat/ignite-2026-alignment`)

## What changed and why

A review against the Microsoft Agent 365 capabilities announced at Ignite 2026
and the released MCP `2026-07-28` specification found three fail-open paths and
several integration gaps.

**Fail-open paths closed**

- **Rust `PolicyEngine`** allowed every action when no policy profile was
  loaded. It now denies, matching the other SDKs
  ([2026-06-10 default-deny parity](2026-06-10-policy-default-deny-parity.md));
  `PolicyEngine::allow_all()` is the explicit opt-in.
- **Python Cedar evaluation** (`agentmesh.governance.policy`) fell through to
  the engine default, possibly `allow`, when a Cedar policy raised. It now
  denies.
- **Entra token verification** accepted tokens without a client ID. It now
  requires `azp` (v2) or `appid` (v1). An unparseable
  `AGENTMESH_ENTRA_REQUIRE_AGENT_IDENTITY` value applies the strictest setting
  instead of being ignored.

**New controls**

- **MCP envelope validation.** `agent_os.mcp_stateless` and
  `MCPGateway.intercept_request` reject requests whose `MCP-Protocol-Version`,
  `Mcp-Method`, `Mcp-Name` or `Mcp-Param-*` headers disagree with the body
  (after Base64 decoding), header values with control characters, unsupported
  protocol versions and incomplete `_meta`, before any policy evaluation. This
  closes the gap where an intermediary routes on headers while the gateway
  evaluates a different body.
- **Multi round-trip governance.** `MCPGateway.intercept_input_required`
  blocks `sampling/createMessage` and `roots/list` input requests by default,
  form elicitation that asks for secrets, URL elicitation without human
  approval, unknown methods and malformed results. `requestState` is never
  inspected.
- **Entra Agent ID classification.** The verifier classifies callers from the
  `xms_act_fct` / `xms_sub_fct` facets and can require an agent identity. The
  blueprint (`xms_par_app_azp`) is logged for attribution and never used for
  authorization.
- **`agentmesh-agent365`** (community extension, alpha) — see its
  `SECURITY.md`.
- **Foundry PDP sample.** The APIM fragment no longer forwards
  `allow_with_conditions` responses whose conditions it cannot enforce.

## Threat model impact

| Dimension | Direction |
|---|---|
| Authorization default | **Strengthened.** Three implicit-allow paths now deny. |
| Header/body confusion (MCP Streamable HTTP) | **Strengthened.** Disagreement between routed headers and the evaluated body is rejected. |
| Server-initiated input (sampling, roots, elicitation) | **Strengthened.** Denied by default or gated by approval and scanning. |
| Identity | **Strengthened.** Client ID required; optional agent-only mode. Blueprint is attribution only. |
| Copilot Studio tool calls | **New control, bounded.** AGT can block tool calls; Copilot Studio still allows a call when the provider does not answer within 1,000 ms, so availability of the provider is a security dependency. |
| Outbound calls | **New, scoped.** `agentmesh-agent365` calls Microsoft Graph and Agent 365 only when used; Graph pagination refuses `nextLink` values outside the Graph root so tokens are not sent elsewhere. |
| Availability | **Operational regression risk.** Deployments relying on the old Rust default-allow, on Cedar errors resolving to allow, or on tokens without `azp`/`appid` will start denying. See `BREAKING_CHANGES.md`. |

## Test coverage

- Python: agent-mesh Entra verifier, registry, relay and Cedar tests; agent-os
  MCP gateway, response scanner, `mcp-scan` and new `mcp_stateless` tests;
  `agentmesh-agent365` tests (Copilot Studio request taken from the Microsoft
  documentation, OpenTelemetry in-memory exporter, mocked Graph transport, real
  `MCPGateway` and `EntraAgentRegistry`).
- Node: Claude Code, OpenCode and Antigravity bundled MCP server suites.
- **Rust: not verified locally** (no Rust toolchain in the authoring
  environment). The changed tests are `test_no_profile_denies_all`,
  `test_allow_all_is_explicit_opt_in`,
  `test_client_without_policy_denies_everything` and
  `test_governance_updates_trust`; CI must run them.
- Not verified against a live, licensed Agent 365 tenant.
