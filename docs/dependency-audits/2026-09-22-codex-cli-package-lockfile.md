---
title: New agent-governance-codex-cli lockfile; js-yaml 4.3.2 in CLI packages
last_reviewed: 2026-09-22
owner: thatjosh
---

# New agent-governance-codex-cli lockfile; js-yaml 4.3.2 in CLI packages

**Date:** 2026-09-22
**PR:** #3409
**Related issue:** #3408
**Lockfiles changed:**
- `agent-governance-codex-cli/package-lock.json` (new file)
- `agent-governance-claude-code/package-lock.json`
- `agent-governance-opencode/package-lock.json`
- `agent-governance-antigravity-cli/package-lock.json`
- `agent-governance-copilot-cli/package-lock.json`

## Which Dependencies Changed And Why

This PR introduces the `agent-governance-codex-cli` package and therefore a new
`package-lock.json`. Its dependency tree follows the sibling CLI packages
(`agent-governance-claude-code`, `agent-governance-opencode`,
`agent-governance-antigravity-cli`, and `agent-governance-copilot-cli`):

| Package | Version | Scope | Reason |
|---|---|---|---|
| `@microsoft/agent-governance-sdk` | 5.0.0 | production (direct) | Governance policy/audit runtime, matching the Claude Code, Copilot CLI, and Antigravity CLI packages |
| `@noble/ciphers`, `@noble/curves`, `@noble/ed25519`, `@noble/hashes` | 2.2.0 / 2.2.0 / 3.1.0 / 2.2.0 | production (transitive via SDK) | Audit-chain signing and hashing |
| `js-yaml` | 4.3.2 (transitive, via npm `overrides`) | production | SDK 5.0.0 requests 5.2.1; the override intentionally resolves the audited 4.3.2 version used by the CLI family to address the current dependency-review advisories |
| `argparse` | 2.0.1 | production (transitive via js-yaml) | Unchanged js-yaml dependency |

The OpenCode package remains on its existing SDK 3.7.0 dependency. Regenerating
the sibling lockfiles also synchronized stale root package metadata and the
OpenCode package name; no package version changes were made to those manifests
in this PR.

## Security Advisory Relevance

**CVE-2026-59869 / GHSA-52cp-r559-cp3m** (high): YAML merge-key chains can
force quadratic CPU consumption in js-yaml >= 4.0.0, < 4.3.0. The CLI
packages pin `js-yaml` to 4.3.2 via `overrides` (see
`2026-06-16-security-python-multipart-js-yaml.md`, which addressed the earlier
CVE-2026-53550). Because this package's lockfile is created in this change, it
adopts 4.3.2 directly, and the sibling CLI overrides are kept in sync. The one
other js-yaml 4.2.0 consumer, mcp-proxy's devDependency, is covered by
Dependabot PR #3433.

Practical exposure in this package is nil: js-yaml is loaded whenever the SDK
is imported, but no code path here invokes YAML parsing. Policy and audit files
are JSON/JSONL, and `PolicyEngine.loadYaml()`/`loadFromYAML()`/`GovernanceVerifier`
are never called, so no input reaches YAML parsing. The override is a deliberate
4.3.2 resolution from the SDK's requested 5.2.1 because the CLI family is
standardized on the audited 4.3.2 package and this adapter does not use YAML APIs;
the dependency-review gate also requires the lockfile to avoid vulnerable versions.

## Breaking Change Risk Assessment

Risk is low. The Codex package moves its direct SDK dependency to the same 5.0.0
release used by the other current CLI packages; OpenCode remains on 3.7.0.
All other dependencies resolve to the exact versions already used by the sibling
packages. The js-yaml override is a patch-level security update, and this
package never invokes YAML parsing. The package tests cover the regenerated
lockfile and the Codex process-boundary hooks.

## Rollback Plan

To roll back this dependency update, revert the Codex SDK change and the five
package.json overrides, then regenerate each corresponding package-lock.json.
This is not recommended: older js-yaml versions remain vulnerable to current
advisories, and the dependency-review gate will fail on the affected lockfiles.
