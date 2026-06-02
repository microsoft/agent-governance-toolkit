# Dependency audit — Claude Code package lockfile

## Which dependencies changed and why

- `agent-governance-claude-code/package-lock.json` changed for the new public-preview Claude Code governance package.
  - Direct dependency locked: `@microsoft/agent-governance-sdk@3.6.0`.
  - The resolved transitive dependencies come only from the published AGT SDK tarball and are committed so CI, release, and local installs are reproducible.
  - Reason: the Claude Code package is a new first-party npm package in this repository and needs a committed lockfile for deterministic builds and release automation.
- The package originally used `@modelcontextprotocol/sdk`, but that dependency was removed from the final lockfile.
  - Newer MCP SDK releases pull `json-schema-typed@8.0.2`, which carries a `BSD-2-Clause AND JSON` license string that fails this repository's dependency review policy.
  - Older MCP SDK releases that avoid that license issue fail GitHub advisory checks.
  - The package now uses a small built-in stdio MCP server implementation instead of carrying the incompatible SDK dependency.

## Security advisory relevance

- No advisory-driven upgrade is being introduced in this lockfile.
- `npm audit --audit-level=moderate` for `agent-governance-claude-code` reports no vulnerabilities in the resolved dependency graph.
- The final lockfile avoids the MCP SDK entirely because no currently acceptable SDK release satisfied both the repository's license policy and GitHub advisory gate.
- No CVE-specific remediation is claimed by this lockfile change.

## Breaking change risk assessment

- `agent-governance-claude-code/package-lock.json`
  - Low to moderate risk.
  - The change adds the pinned dependency graph for a new package and removes the external MCP SDK dependency in favor of an internal stdio MCP server implementation.
  - Runtime impact is bounded to the new Claude Code governance package.
- The Claude package uses a narrow MCP surface (`initialize`, `tools/list`, `tools/call`, and `ping`), so replacing the SDK with a built-in implementation keeps the compatibility risk contained to that local server entrypoint.
- Overall assessment: acceptable for this PR because the lockfile is required for deterministic builds, the final dependency graph passes the vulnerability gate, and the removed MCP SDK avoids the repository's disallowed license combination.
