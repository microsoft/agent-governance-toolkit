# Dependency Audit: remove malicious `openclaw` from policy-engine Node SDK

**Date:** 2026-06-02
**PR:** #2784
**Lockfiles changed:**

- `policy-engine/sdk/node/package-lock.json`

## Dependencies changed

| Package | From | To | Reason |
|---|---|---|---|
| `openclaw` | `2026.5.27` | _removed_ | Component Governance flagged `openclaw@2026.5.27` as a critical-severity malware finding |

Manifest changes in `policy-engine/sdk/node/package.json`:

- Removed `openclaw` from `devDependencies`
- Removed `openclaw` from `peerDependencies`
- Removed the corresponding entry from `peerDependenciesMeta`

Lockfile churn pulled in by `npm install --legacy-peer-deps --ignore-scripts`:

- `policy-engine/sdk/node/`: 372 transitive packages removed (508 → 136). The entire sub-tree existed only because `openclaw` brought it in; nothing else in the SDK depends on those packages.

`scripts/check_dependency_confusion.py` also updated: removed `openclaw` from the registered npm allowlist so a future re-add is caught by the dependency-confusion scan.

## Security advisory relevance

`openclaw@2026.5.27` was flagged as malware by Component Governance. No CVE was filed at the time of this PR; the finding is registry-side and the package would be unsafe to install regardless of how it is consumed.

The package was a `devDependency` and `peerDependency` of the vendored ACS Node SDK and was not published in the runtime tree of any first-party package. Even so, build-side execution (`postinstall`, test runners) is sufficient to be a supply-chain risk, so the package is removed entirely.

## Breaking change risk

**Risk: low.** Removing the npm package does not change the SDK's adapter API:

- The local `createOpenClawAdapter` source in `policy-engine/sdk/node/src/adapters.ts` defines a generic plugin shape (`on(name, handler)` / `registerHook(...)`) and never imported the npm package at any point.
- Adapter unit tests `policy-engine/sdk/node/test/adapters.test.mjs` and `adapter-mediation.test.mjs` exercise the adapter against an in-memory plugin shape and continue to pass unchanged.
- Only the two real-framework smoke proofs (`real-framework-adapters.mjs`, `standalone-real-frameworks.mjs`) dynamically imported `openclaw/plugin-sdk/core` to verify wiring against the real package; both call sites are removed in this PR. No other coverage referenced the npm package.

`npm install --legacy-peer-deps --ignore-scripts` was used to regenerate the lockfile so no postinstall scripts from any of the dropped 372 transitive packages were executed locally.

## Rollback plan

This is a security removal; rollback is not recommended. If the upstream `openclaw` package is later cleared by the registry and re-added intentionally, restore the entries in `policy-engine/sdk/node/package.json` (`devDependencies`, `peerDependencies`, `peerDependenciesMeta`), restore the `openclaw` entry in `scripts/check_dependency_confusion.py`'s npm allowlist, and re-add the smoke-test blocks in `real-framework-adapters.mjs` and `standalone-real-frameworks.mjs`. Then run `npm install --legacy-peer-deps --ignore-scripts` to regenerate the lockfile.
