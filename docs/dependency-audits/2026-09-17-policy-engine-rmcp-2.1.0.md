---
title: "Dependency audit: rmcp 1.7.0 to 2.1.0 in policy-engine"
last_reviewed: 2026-09-17
owner: MohammadHaroonAbuomar
---

# 2026-09-17 - rmcp 1.7.0 to 2.1.0 in `policy-engine/integrations/mcp`

Supersedes Dependabot PR #4013, which could not carry this document.

## Which dependencies changed and why

| Package | From | To | Manifest |
|---|---|---|---|
| `rmcp` | 1.7.0 | 2.1.0 | `policy-engine/integrations/mcp/Cargo.toml`, `policy-engine/Cargo.lock` |
| `rmcp-macros` | 1.7.0 | 2.2.0 | `policy-engine/Cargo.lock` (transitive, pulled by `rmcp`) |

The requirement in `Cargo.toml` moves from `"1.7"` to `"2.0"`, matching the
caret style the other `policy-engine/integrations/*` crates use for
third-party dependencies. The lockfile change is limited to the two `rmcp`
entries (version and checksum); no other package moves.

Reason: GitHub published two high-severity advisories against `rmcp <
2.0.0` on 2026-09-16, and Dependabot opened alerts #553 to #556 on the two
manifests above. 2.0.0 is the first release patched for those two advisories; this change pins 2.1.0 because of the third advisory below. Newer 2.x and 3.x
releases exist; this change takes the smallest step that clears the
advisories.

## Security advisory relevance

- GHSA-9g45-5xwm-f3wc (moderate, published 2026-09-17): custom HTTP headers leaked to cross-origin redirect targets in `rmcp < 2.1.0`. The previous target of this audit, 2.0.0, is affected; 2.1.0 (released 2026-07-02) is the first patched version and is what this change pins.

Both advisories are fixed in 2.0.0 and closed by this change.

- GHSA-9pj6-vhgr-3mwh / CVE-2026-63128, CVSS 7.5 (high). Unauthenticated
  session-table leak in the Streamable HTTP server transport.
  `StreamableHttpService::handle_post` in
  `transport/streamable_http_server/tower.rs` created a session before it
  validated the request body and returned early on a non-initialize
  request without closing it, so each such POST left a permanent entry in
  `LocalSessionManager`. Remote denial of service by memory exhaustion.
  Fixed upstream in rust-sdk #934.
- GHSA-33f5-2c5q-wgwj / CVE-2026-63127, CVSS 8.2 (high). The OAuth client
  in `transport/auth.rs` did not check the `resource` field of the
  Protected Resource Metadata document (RFC 9728 sections 3.3 and 7.3), so
  a hostile MCP server could point the OAuth flow at a legitimate
  authorization server and receive the resulting tokens. Fixed upstream in
  rust-sdk #937 (with a related SSRF guard in #935).

Reachability in this repository: neither vulnerable module is compiled.
`policy-engine/integrations/mcp/Cargo.toml` declares `rmcp = "2.1.0"` with no
feature list, so only the default features `base64`, `macros` and `server`
are enabled (`cargo tree -e features` shows the single edge
`rmcp feature "default"`). The Streamable HTTP server sits behind
`transport-streamable-http-server` and the OAuth client behind `auth`, which
pulls `oauth2`, `reqwest` and `url`. The lockfile's `rmcp` entry depends
only on `async-trait`, `base64`, `chrono`, `futures`, `pastey`,
`pin-project-lite`, `rmcp-macros`, `schemars`, `serde`, `serde_json`,
`thiserror`, `tokio`, `tokio-util` and `tracing`; none of `axum`, `hyper`,
`reqwest` or `oauth2` is reachable from it. The `hyper` and `reqwest`
entries elsewhere in the lock belong to `async-openai`, `rig-core` and
`ureq-proto`. The upgrade therefore removes the alerts rather than closing a
live exposure, but it also keeps the crate on a supported line.

## Provenance and version

`rmcp` 2.1.0 was published to crates.io on 2026-07-02, and 2.0.0 on 2026-06-29 (80 days before this
change) by `alexhancock`, whose crates.io login matches the GitHub account,
from https://github.com/modelcontextprotocol/rust-sdk (tag `rmcp-v2.0.0`).
It is not yanked. The lockfile checksum
`d52d21e5b342699bc4de690e6104fc4e43255e4e8420ff0f2cbb963aac09da6f` matches
the crates.io record. `rmcp-macros` 2.2.0 was published 2026-07-08 from the
same repository.

The version clears the repo's 7-day cooling-off rule by a wide margin, but
`scripts/check_release_age.py` reports it as `UNVERIFIED`: the script treats
the caret spec `"2.0"` as an exact pin, requests
`crates.io/api/v1/crates/rmcp/2.0`, and gets HTTP 400 because `2.0` is not
a version. That is a scanner false negative for range specs, not a registry
failure. Fixing the script would trip the supply-chain workflow's
scanner-plus-manifest guard if done in this PR, so it is left for a
separate change.

## Breaking change risk assessment

Risk: low. `rmcp` 2.0.0 lists three breaking changes: model types aligned to
the MCP 2025-11-25 spec (#927), an `Audio` variant added to
`PromptMessageContent` (#865), and deprecation of the roots, sampling and
logging types (#923). Along with #927, `CallToolResult::success` now takes
`Vec<ContentBlock>` instead of `Vec<Content>`, and `IntoContents::into_contents`
returns the same type.

The crate uses 14 `rmcp` items across `src/lib.rs`, `tests/guarded_tool.rs`
and `examples/mcp_smoke.rs`: `ServerHandler`, `CallToolRequestParams`,
`CallToolResult`, `IntoContents`, `JsonObject`, `ListToolsResult`,
`PaginatedRequestParams`, `ServerInfo`, `Tool`, `MaybeSendFuture`,
`RequestContext`, `RoleServer`, `ErrorData` and `ToolRouter`. None is
deprecated in 2.0.0. The one call to `CallToolResult::success` passes the
output of `into_contents()`, so the `Content` to `ContentBlock` rename is
absorbed by the trait and no source change is needed. No prompt, roots,
sampling or logging type is used.

Validation, run from `policy-engine/` as `policy-engine-ci.yml` does:

- `cargo fmt --all -- --check`: clean.
- `cargo clippy --locked -p agent_control_specification_mcp --all-targets -- -D warnings`: clean.
- `cargo test --locked -p agent_control_specification_mcp`: 1 passed.
- `cargo build --locked -p agent_control_specification_mcp --example mcp_smoke`: builds.
- `cargo clippy --workspace --all-targets -- -D warnings`: clean.
- `cargo check --locked -p agent_control_specification_core --no-default-features --lib`
  and `cargo check --locked -p agent_control_specification_otel --lib`: clean.
- `cargo test --workspace` (with `opa` on PATH): 123 passed, 0 failed.

## Rollback plan

Revert the two files to `rmcp = "1.7"` and the 1.7.0 lock entries. The
Dependabot alerts reopen; no data or API migration is involved.
