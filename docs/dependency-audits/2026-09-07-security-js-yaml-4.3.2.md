# Dependency Audit: js-yaml 4.3.2 (security fix)

**Date:** 2026-09-07
**Issue:** #3671
**Landed in:** #4063, which raised the four overrides below to 4.3.2 without a dated audit. This document records why 4.3.2 is the floor.
**Lockfiles affected:**
- `agent-governance-antigravity-cli/package-lock.json`
- `agent-governance-claude-code/package-lock.json`
- `agent-governance-copilot-cli/package-lock.json`
- `agent-governance-opencode/package-lock.json`

## Dependencies changed

| Package | From | To | Scope | Reason |
|---|---|---|---|---|
| `js-yaml` | 4.2.0 (via npm overrides) | 4.3.2 (via npm overrides) | production (CLI packages) | Fix GHSA-52cp-r559-cp3m / CVE-2026-59869, GHSA-5p4m-2wfm-xmqj and GHSA-2883-xcg3-v3hh / CVE-2026-84375 |

## Security advisory relevance

**GHSA-52cp-r559-cp3m / CVE-2026-59869**: crafted YAML merge-key chains. Affects `js-yaml >=4.0.0,<4.3.0`.

**GHSA-5p4m-2wfm-xmqj**: quadratic `!!omap` resolution. Affects `js-yaml >=4.0.0,<4.3.1`.

**GHSA-2883-xcg3-v3hh / CVE-2026-84375**: `maxTotalMergeKeys` does not limit CPU use for empty merge sources. Affects `js-yaml >=4.0.0,<4.3.2`; first patched in 4.3.2. Published 2026-09-08, after this audit was first written.

The patched floor for the 4.x line is therefore **4.3.2**: 4.3.1 clears the first two advisories but not GHSA-2883-xcg3-v3hh, which is why the override is not set any lower.

The four CLI packages carry `js-yaml` transitively through `@microsoft/agent-governance-sdk` and pin it with an npm `overrides` field, added in the 2026-06-16 audit to clear GHSA-h67p-54hq-rp68. That pin is what held the tree at the affected 4.2.0, so raising the override was the fix. What removing it would do now depends on the SDK each package uses. `agent-governance-opencode` still depends on SDK 3.7.0, whose lock entry requests `js-yaml` 4.1.1, so it would resolve *down* to a version affected by all three advisories above. The other three packages depend on SDK 5.0.0, which requests `js-yaml` 5.2.1, so they would resolve *up* to the 5.x line instead, as the 2026-09-22 codex-cli lockfile audit notes.

`npm audit --package-lock-only`, per package (re-run 2026-10-03 against the lockfiles before and after #4063). npm counts vulnerable *packages*, not advisories: the two high findings "before" are `js-yaml`, which carries all three advisories above, and `@microsoft/agent-governance-sdk`, flagged through its `js-yaml` dependency.

| Package | Before | After |
|---|---|---|
| `agent-governance-antigravity-cli` | 2 high | 0 |
| `agent-governance-claude-code` | 2 high | 0 |
| `agent-governance-copilot-cli` | 2 high | 0 |
| `agent-governance-opencode` | 2 high | 0 |

## Downstream consumers

Not fixed by this change. An `overrides` field applies to the package's own tree, not to consumers installing the published packages, whose resolution follows `@microsoft/agent-governance-sdk`'s constraint instead. Three of the four packages now depend on SDK 5.0.0, whose lock entry requests `js-yaml` 5.2.1, so their consumers already get the 5.x line. Only `agent-governance-opencode` is still on SDK 3.7.0, which requests 4.1.1, so its consumers need their own override until it moves to a newer SDK. `agent-governance-typescript` declares `js-yaml` 5.4.2 on `main`.

## Breaking change risk

Risk: low. 4.2.0 → 4.3.2 stays within the 4.x series and is API-compatible. Both fixes bound resolution work — merge-key chain depth and `!!omap` resolution — so only inputs that were already pathological change behaviour.

## Rollback plan

Revert the `"overrides": {"js-yaml": "4.3.2"}` field in the four CLI `package.json` files to `"4.2.0"` and regenerate the four lockfiles with `npm install --package-lock-only`. Note that this reinstates all three advisories.
