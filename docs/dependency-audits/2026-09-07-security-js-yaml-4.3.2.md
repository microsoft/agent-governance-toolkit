# Dependency Audit: js-yaml 4.3.2 (security fix)

**Date:** 2026-09-07
**Issue:** #3671
**Lockfiles changed:**
- `agent-governance-antigravity-cli/package-lock.json`
- `agent-governance-claude-code/package-lock.json`
- `agent-governance-copilot-cli/package-lock.json`
- `agent-governance-opencode/package-lock.json`

## Dependencies changed

| Package | From | To | Scope | Reason |
|---|---|---|---|---|
| `js-yaml` | 4.2.0 (via npm overrides) | 4.3.2 (via npm overrides) | production (CLI packages) | Fix GHSA-52cp-r559-cp3m / CVE-2026-59869 and GHSA-5p4m-2wfm-xmqj |

## Security advisory relevance

**GHSA-52cp-r559-cp3m / CVE-2026-59869**: crafted YAML merge-key chains. Affects `js-yaml >=4.0.0,<4.3.0`.

**GHSA-5p4m-2wfm-xmqj**: quadratic `!!omap` resolution. Affects `js-yaml >=4.0.0,<4.3.1`.

The patched floor for the 4.x line is therefore 4.3.1; 4.3.2 is the current patch on that line.

The four CLI packages carry `js-yaml` transitively through `@microsoft/agent-governance-sdk` and pin it with an npm `overrides` field, added in the 2026-06-16 audit to clear GHSA-h67p-54hq-rp68. That pin is what now holds the tree at the affected 4.2.0, so raising the override is the fix — removing it instead resolves *down* to the SDK's own 4.1.1, which is affected by both of these advisories and by the earlier one.

`npm audit --package-lock-only`, per package:

| Package | Before | After |
|---|---|---|
| `agent-governance-antigravity-cli` | 2 high | 0 |
| `agent-governance-claude-code` | 2 high | 0 |
| `agent-governance-copilot-cli` | 2 high | 0 |
| `agent-governance-opencode` | 2 high | 0 |

## Downstream consumers

Not fixed by this change. An `overrides` field applies to the package's own tree, not to consumers installing the published packages, whose resolution follows `@microsoft/agent-governance-sdk`'s constraint instead. The published SDK versions these packages depend on (4.0.0, and 3.7.0 for opencode) resolve `js-yaml` to 4.1.1. `agent-governance-typescript` already declares `js-yaml` 5.2.3 on `main`, so a release cut from current `main` carries a patched constraint of its own; until such a release, downstream trees need their own override.

## Breaking change risk

Risk: low. 4.2.0 → 4.3.2 stays within the 4.x series and is API-compatible. Both fixes bound resolution work — merge-key chain depth and `!!omap` resolution — so only inputs that were already pathological change behaviour.

## Rollback plan

Revert the `"overrides": {"js-yaml": "4.3.2"}` field in the four CLI `package.json` files to `"4.2.0"` and regenerate the four lockfiles with `npm install --package-lock-only`. Note that this reinstates both advisories.
