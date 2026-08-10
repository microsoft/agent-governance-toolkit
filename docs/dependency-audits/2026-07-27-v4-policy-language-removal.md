---
title: Dependency changes from removing the v4 policy language
last_reviewed: 2026-07-27
owner: liamcrumm
---

# Dependency changes from removing the v4 policy language

## Which Dependencies Changed And Why

No third-party dependency was upgraded. The change adds one first-party ACS
package, pins one missing transitive dependency, and deletes lockfiles that
belonged to removed examples. The Rust crate's ACS dependency is audited
separately in `2026-07-27-rust-acs-dependency.md`.

- `agentmesh-integrations/mastra-agentmesh/package-lock.json` gains
  `agent-control-specification` `0.3.1-beta.0`, the published ACS npm package,
  because the TypeScript surface now evaluates ACS manifests directly.
- `agent-governance-python/requirements/ci-policy-test.txt` pins
  `pygments==2.20.0`. `pytest==9.0.3` requires `pygments>=2.7.2`, and the file
  installs with `--require-hashes`, which rejects an unpinned transitive
  dependency. The policy test job runs only on pull requests that touch policy
  paths, so the gap surfaced only when this change touched them.
- Four `requirements.txt` files are deleted along with the examples that used
  them. No package is removed from any shipped surface.

## Security Advisory Relevance

No CVE or advisory is addressed here.

`pygments` `2.20.0` was published on 2026-03-29, so it is well past the
seven-day cooling-off period this repository requires, and it is pinned by
exact version with both wheel and sdist hashes. Adding it does not change what
CI installs at runtime; pip was already resolving it as a `pytest` dependency
and failing only because it lacked a hash.

The ACS npm package is first-party and MIT licensed, under the
`agent-control-specification` name already registered to this project.

## Breaking Change Risk Assessment

Low for dependency consumers, and unrelated to the breaking change this stack
carries.

The npm lockfile pins a beta
of the project's own SDK, matching the version the other TypeScript surfaces
already use. The `pygments` pin only affects CI, and it was verified by
installing the file with `--require-hashes` in a clean virtual environment.

The user-visible breaking change in this stack is the removal of the v4 policy
language itself, which `BREAKING_CHANGES.md` covers.
