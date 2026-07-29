---
title: New agent-governance-codex-cli lockfile, js-yaml 4.3.0 override
last_reviewed: 2026-07-29
owner: thatjosh
---

# New agent-governance-codex-cli lockfile, js-yaml 4.3.0 override

**Date:** 2026-07-29
**PR:** #3409
**Lockfiles changed:**
- `agent-governance-codex-cli/package-lock.json` (new file)

## Which Dependencies Changed And Why

This PR introduces the `agent-governance-codex-cli` package and therefore a new
`package-lock.json`. The dependency tree mirrors the sibling CLI packages
(`agent-governance-claude-code`, `agent-governance-opencode`,
`agent-governance-antigravity-cli`, `agent-governance-copilot-cli`) except for
the js-yaml override — 4.3.0 here vs 4.2.0 on main (see below); opencode
additionally still locks `@microsoft/agent-governance-sdk` 3.7.0:

| Package | Version | Scope | Reason |
|---|---|---|---|
| `@microsoft/agent-governance-sdk` | 4.0.0 | production (direct) | Governance policy/audit runtime, same as sibling CLI packages |
| `@noble/ciphers`, `@noble/curves`, `@noble/ed25519`, `@noble/hashes` | 2.2.0 / 2.2.0 / 3.1.0 / 2.2.0 | production (transitive via SDK) | Audit-chain signing and hashing |
| `js-yaml` | 4.3.0 (transitive, via npm `overrides`) | production | SDK requests 4.1.1; overridden to 4.3.0 to fix CVE-2026-59869 / GHSA-52cp-r559-cp3m |
| `argparse` | 2.0.1 | production (transitive via js-yaml) | Unchanged js-yaml dependency |

No devDependencies; tests run on the Node built-in test runner.

## Security Advisory Relevance

**CVE-2026-59869 / GHSA-52cp-r559-cp3m** (high): YAML merge-key chains can
force quadratic CPU consumption in js-yaml >= 4.0.0, < 4.3.0. The sibling CLI
packages pin `js-yaml` to 4.2.0 via `overrides` (see
`2026-06-16-security-python-multipart-js-yaml.md`, which addressed the earlier
CVE-2026-53550); 4.2.0 is itself vulnerable to this newer advisory. Because
this package's lockfile is created in this PR, it adopts the patched 4.3.0
directly rather than inheriting the vulnerable pin. Raising the four sibling
packages' overrides from 4.2.0 to 4.3.0 is left to a separate cross-package
change, matching how the 2026-06-16 bump was handled.

Practical exposure in this package is nil: js-yaml is loaded whenever the SDK
is imported (top-level `require` in the SDK's `dist/verify.js`), but no code
path here ever invokes YAML parsing — policy and audit files are JSON/JSONL,
and `PolicyEngine.loadYaml()`/`loadFromYAML()`/`GovernanceVerifier` are never
called — so no input reaches `yaml.load`. The bump is defense-in-depth plus
compliance with the `dependency-review` gate, which flags vulnerable lockfile
versions regardless of reachability.

## Breaking Change Risk Assessment

Risk is low. All dependencies except js-yaml resolve to the exact versions
already locked by `agent-governance-claude-code`,
`agent-governance-antigravity-cli`, and `agent-governance-copilot-cli`
(`agent-governance-opencode` still locks SDK 3.7.0). js-yaml 4.2.0 → 4.3.0 is
a minor release within the 4.x series that tightens merge-key expansion; this
package never invokes YAML parsing (see above), so the behavior change cannot
affect it. The package's full test suite (20 tests, including
process-boundary e2e hooks) passes against the regenerated lockfile.

## Rollback Plan

Revert `agent-governance-codex-cli/package.json` `overrides` to
`"js-yaml": "4.2.0"` and regenerate `package-lock.json`. Not recommended:
4.2.0 remains vulnerable to GHSA-52cp-r559-cp3m and the `dependency-review`
CI gate will fail on it.
