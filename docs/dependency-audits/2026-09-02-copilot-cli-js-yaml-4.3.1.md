---
title: Copilot CLI js-yaml 4.3.1 Dependency Audit
last_reviewed: 2026-09-02
owner: agt-maintainers
---

<!-- cspell:words xmqj -->

# Copilot CLI js-yaml 4.3.1 Dependency Audit

## Which dependencies changed and why

- `js-yaml` changes from `4.2.0` to `4.3.1` in the Copilot CLI dependency graph.
- The package remains transitive through `@microsoft/agent-governance-sdk@4.0.0`; the existing npm override selects the patched version without adding a dependency.
- The lockfile root version changes from the stale `4.0.0` value to `5.0.0`, matching the existing package manifest. This metadata normalization does not change the dependency graph.
- The lockfile was regenerated to keep installation reproducible and to remove the vulnerable parser version.

## Security advisory relevance

- CVE-2026-59869 affects `js-yaml` versions from `4.0.0` through versions before `4.3.0`. Version `4.3.1` contains the fix.
- GHSA-5p4m-2wfm-xmqj affects `js-yaml` versions from `4.0.0` through versions before `4.3.1`. Version `4.3.1` is the first patched 4.x release.
- The single upgrade therefore remediates S360 work items `332696` and `341590` for the Copilot CLI lockfile.
- `npm audit` reports zero vulnerabilities after the lockfile update.

## Breaking change risk assessment

- Risk is low because the dependency remains within the `js-yaml` 4.x API line and is selected through the existing override mechanism.
- The change does not modify Copilot CLI source code, package exports, runtime configuration, or the first-party SDK version.
- Clean installation, syntax validation, and all 18 Copilot CLI tests pass with `js-yaml 4.3.1`.
- Rollback consists of reverting the override and lockfile together, but doing so would restore both high-severity findings.
