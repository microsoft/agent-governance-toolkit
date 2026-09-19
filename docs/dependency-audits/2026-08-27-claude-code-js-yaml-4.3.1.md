---
title: Claude Code js-yaml 4.3.1 Update
last_reviewed: 2026-08-27
owner: agt-maintainers
---

# Claude Code js-yaml 4.3.1 Update

<!-- cspell:ignore xmqj -->

## Which Dependencies Changed And Why

- `agent-governance-claude-code/package.json` updates the existing transitive
  `js-yaml` override from `4.2.0` to `4.3.1`.
- `agent-governance-claude-code/package-lock.json` resolves `js-yaml` at
  `4.3.1` and records its registry integrity and funding metadata.
- Regenerating the lockfile also aligns the root package metadata from stale
  version `4.0.0` to the manifest's current version `5.0.0`.
- No other dependency version or runtime source changes.

The override remains necessary because
`@microsoft/agent-governance-sdk 4.0.0` requests `js-yaml 4.1.1` transitively.

## Security Advisory Relevance

- S360 work item `332699` and Component Governance alert `17967443` report
  `CVE-2026-59869` for `js-yaml 4.2.0` in this package lockfile.
- S360 work item `341591` and Component Governance alert `18612941` report
  `GHSA-5p4m-2wfm-xmqj` for the same installed package instance.
- `npm ls js-yaml` confirms the SDK dependency resolves to overridden
  `js-yaml 4.3.1`, and `npm ci` reports zero vulnerabilities.

## Breaking Change Risk Assessment

- Risk is low because `js-yaml` receives a patch-level update within 4.x and
  remains an override of the same transitive dependency.
- No hook, MCP server, CLI behavior, or public package API changes.
- `npm run check` and `npm test` pass all 17 Claude Code tests.