---
title: Monorepo Version 5.0.1 Lockfile Refresh
last_reviewed: 2026-09-09
owner: agt-maintainers
---

# Monorepo Version 5.0.1 Lockfile Refresh

## Which Dependencies Changed And Why

- `agent-governance-python/requirements/ci-test.txt` updates `typing-extensions` from 4.15.0 to 4.16.0. AnyIO 4.15.1 requires `typing-extensions>=4.16.0` on Python versions below 3.15; the previous shared CI pin downgraded the environment after package installation and caused Agent OS and Agent Mesh test collection to fail when AnyIO imported `typing_extensions.sentinel`.
- The npm lockfiles changed because first-party package versions were synchronized to 5.0.1. No resolved third-party package version, URL, or integrity hash changed. npm also normalized root metadata, including removing redundant lockfile copies of the existing `js-yaml` override; the override remains declared in each package manifest.
- `agent-governance-opencode/package-lock.json` aligns its root package name with `@microsoft/agent-governance-opencode`, matching its package manifest.
- `agent-governance-rust/Cargo.lock` updates the first-party `agentmesh` and `agentmesh-mcp` workspace package versions from 5.0.0 to 5.0.1. No third-party crate selection changed.

## Security Advisory Relevance

- This dependency update is compatibility-driven; no CVE or security advisory remediation is claimed.
- Retaining the `js-yaml` 4.2.0 override preserves the existing security constraint while npm removes redundant lockfile metadata.
- The remaining lockfile changes affect first-party package identity and version metadata only.

## Breaking Change Risk Assessment

- Risk is low. `typing-extensions` 4.16.0 supplies the API required by the already-selected AnyIO version and restores compatibility across the Python 3.11, 3.12, and 3.13 CI matrix.
- The npm and Cargo changes do not alter third-party dependency resolution.
- Public APIs and serialized formats are unchanged by the lockfile refresh.