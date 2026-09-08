---
title: "ADR 0027: Adopt a dual-stack migration for MCP 2026-07-28"
last_reviewed: 2026-05-25
owner: agt-maintainers
---

# ADR 0027: Adopt a dual-stack migration for MCP `2026-07-28`

- Status: proposed
- Date: 2026-05-24

This ADR is proposed for OSS discussion and maintainer review before any
cross-cutting implementation work starts.

## Context

The MCP `2026-07-28` release candidate introduces breaking protocol changes
relative to the `2025-11-25` lifecycle currently assumed in parts of this
repository.

The most relevant changes are:

- protocol-level sessions are removed,
- the `initialize` / `notifications/initialized` lifecycle is no longer the
  primary flow,
- client info and capabilities move into per-request `_meta`,
- Streamable HTTP requires routable headers such as `Mcp-Method` and
  `Mcp-Name`,
- `server/discover` becomes the preferred capability discovery path,
- Tasks move out of core into an extension model, and
- roots, sampling, and logging are deprecated.

This repo has several MCP-aware surfaces that still encode the older
lifecycle. The most important ones are:

- `agent-governance-python\agent-os\src\agent_os\cli\mcp_scan.py`,
- `agent-governance-claude-code\server\agt-mcp.mjs`,
- `agent-governance-antigravity-cli\assets\extensions\agt-global-policy\mcp\server.mjs`, and
- MCP docs and tests that assume `initialize`, `notifications/initialized`,
  and `Mcp-Session-Id`.

Without adaptation, AGT will fail to interoperate cleanly with RC-compliant
MCP clients and servers, continue teaching obsolete MCP patterns in docs, and
keep governance features coupled to transport semantics that MCP is removing.

## Decision

If accepted after OSS discussion and maintainer review, AGT will adopt a
stateless-first, dual-stack MCP migration. AGT will add first-class support
for MCP `2026-07-28` while preserving compatibility with `2025-11-25` during
a bounded transition window. To do that, AGT will introduce a version-aware
MCP compatibility layer that isolates legacy and stateless protocol behavior
from higher-level governance logic. AGT MCP clients will prefer stateless
discovery and request flows, and AGT bundled MCP servers will become
stateless-first while retaining legacy compatibility shims.

The compatibility layer will:

- identify whether the peer is using legacy or stateless behavior,
- normalize discovery behavior,
- normalize request construction for list, read, and call flows,
- attach per-request `_meta` for stateless requests,
- centralize Streamable HTTP header generation, and
- isolate any legacy session handling so it does not leak into higher layers.

During migration, AGT will support two discovery flows:

1. **Legacy flow:** send `initialize`, validate `protocolVersion`,
   `capabilities`, and `serverInfo`, optionally send
   `notifications/initialized`, then continue with primitive listing.
2. **Stateless flow:** send `server/discover`, read capability and extension
   declarations, then issue self-contained requests with
   `MCP-Protocol-Version: 2026-07-28`, `Mcp-Method`, `Mcp-Name` when required,
   and per-request `_meta` carrying client info and capabilities. AGT must not
   rely on `Mcp-Session-Id` in this flow.

AGT components such as `mcp_session_auth.py` and `MCPSessionStore` will be
treated as application-level auth or state helpers rather than protocol-session
helpers. They may still exist for AGT-managed access control or state handles,
but they should not be described as required MCP transport semantics.

## Consequences

AGT will be able to interoperate with MCP `2026-07-28` clients and servers
without breaking existing `2025-11-25` integrations immediately. Governance
features will become less coupled to wire-level lifecycle assumptions, and the
docs will align with the future MCP direction instead of reinforcing obsolete
patterns.

This comes with transition cost. Protocol support will be more complex until
legacy behavior is retired, tests will need to cover both legacy and stateless
paths, and naming around "sessions" will need cleanup to avoid confusion
between application auth/state and MCP transport semantics.

Because this is a cross-cutting change spanning scanner behavior, bundled
servers, docs, and tests, it should be treated as a maintainer-reviewed design
decision rather than an implementation detail. The ADR is intended to make that
review explicit in the open before code changes land.

Implementation should proceed in coordinated work streams:

- update `agent-governance-python\agent-os\src\agent_os\cli\mcp_scan.py` to
  use a supported-version model, add `server/discover`, move client metadata
  into per-request `_meta`, stop depending on `Mcp-Session-Id`, generate
  `Mcp-Method` / `Mcp-Name`, and preserve explicit fallback to the legacy
  lifecycle;
- update `agent-governance-claude-code\server\agt-mcp.mjs` and
  `agent-governance-antigravity-cli\assets\extensions\agt-global-policy\mcp\server.mjs`
  to implement `server/discover`, become stateless-first, keep `initialize` as
  a compatibility path, and treat `notifications/initialized` as a no-op
  compatibility shim; and
- update docs and tests to describe `2026-07-28` as the preferred target,
  explain the dual-stack transition, stop teaching `Mcp-Session-Id` as part of
  the normal lifecycle, and distinguish AGT application auth/state from MCP
  protocol sessions.

The migration is complete when AGT can inspect `2026-07-28` MCP servers
without relying on `initialize` or `Mcp-Session-Id`, bundled MCP servers
interoperate with stateless clients, existing `2025-11-25` integrations still
work during the transition window, and repo docs no longer describe the legacy
session-based lifecycle as the default.
