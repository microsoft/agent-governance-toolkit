---
title: agent-governance-sdk 4.0.0 to 5.0.0 in the three CLI packages
last_reviewed: 2026-09-03
owner: imran-siddique
---

# agent-governance-sdk 4.0.0 to 5.0.0 in the three CLI packages

Covers the lockfile changes in #3686, #3683 and #3681, which bump
`@microsoft/agent-governance-sdk` from `4.0.0` to `5.0.0` in
`agent-governance-claude-code`, `agent-governance-antigravity-cli` and
`agent-governance-copilot-cli` respectively. One document because the three are
the same change to three copies of the same dependency.

## Which Dependencies Changed And Why

One first-party direct dependency, and one third-party transitive dependency
underneath it.

- `@microsoft/agent-governance-sdk` `4.0.0` to `5.0.0` in all three packages.
  This closes a version-line inconsistency rather than adopting new
  functionality: each of the three CLI packages is already published at
  `5.0.0` itself while pinning the `4.0.0` SDK. The `[5.0.0]` CHANGELOG entry
  describes the monorepo-wide alignment that moved every first-party Python,
  TypeScript, .NET and Rust package from `4.1.0` to `5.0.0` so the released
  version line matches the documentation, which already describes Agent Control
  Specification as the AGT 5.0 policy layer.
- `js-yaml`'s *declared* version moves `4.1.1` to `5.2.1`, as the SDK's own pin.
  **The installed version does not move.** All three packages declare
  `"overrides": { "js-yaml": "4.2.0" }` in `package.json`, on `main` and here, so
  each lockfile resolves `node_modules/js-yaml` to `4.2.0` before and after this
  bump. Verified with `npm ci` followed by `npm ls js-yaml`, which reports
  `js-yaml@4.2.0 overridden` under `@microsoft/agent-governance-sdk@5.0.0`.
  Comparing the two published manifests, `@noble/ciphers` `2.2.0`,
  `@noble/curves` `2.2.0`, `@noble/ed25519` `3.1.0`, `@noble/hashes` `2.2.0`,
  `engines.node >=18.0.0` and the MIT license are all identical between `4.0.0`
  and `5.0.0`. So the SDK is the only dependency this bump actually changes.

Each CLI package declares exactly one dependency, the SDK, so there is no other
surface to consider.

## Security Advisory Relevance

**This bump changes nothing about the `js-yaml` these packages install, and so
clears no advisory.** The override holds the parser at `4.2.0` regardless of
what the SDK declares, which means the two HIGH advisories in range before the
bump are still in range after it.

`npm audit` against this branch's own tree reports both, and no others:

- `GHSA-5p4m-2wfm-xmqj`, HIGH, quadratic CPU consumption in `!!omap`
  resolution, affecting `>= 4.0.0, < 4.3.1`, first patched in `4.3.1`.
- `GHSA-52cp-r559-cp3m`, HIGH, YAML merge-key chains forcing quadratic CPU
  consumption, affecting `>= 4.0.0, < 4.3.0`, first patched in `4.3.0`.

`GHSA-pm4m-ph32-ghv5` (HIGH, `>= 5.0.0, <= 5.2.1`, first patched in `5.2.2`)
does **not** apply here, because `5.2.1` is never installed. Neither do
`GHSA-724g-mxrg-4qvm` or `GHSA-g796-fgmg-93mv`, both scoped to the `5.x` line.

All of these are the same class: algorithmic-complexity denial of service
reachable only through parsing attacker-influenced YAML.

**The residual exposure is closed elsewhere, not by this PR.** #3843, #3844 and
#3875 move the override from `4.2.0` to `4.3.1` in the antigravity, Claude Code
and Copilot CLI packages respectively, which clears both advisories above.
Those PRs touch the same `package.json` and `package-lock.json` files as this
one, so they and this PR conflict with each other and should be sequenced
rather than merged in parallel.

**The source fix already landed, the published artifact has not.**
`agent-governance-typescript/package.json` on `main` pins `js-yaml` `5.2.3`,
via #3623 on 2026-08-12, so the SDK source is clear. What these three packages
resolve is the *published* `@microsoft/agent-governance-sdk` `5.0.0`, released
to npm on 2026-08-03, whose manifest pins `js-yaml` `5.2.1`. That artifact is
immutable. It is also moot while the override is in place, which is the point:
these packages have not been exposed to the `5.x` advisory at any time.

Recording it here so the gap between what the SDK declares and what consumers
install is visible rather than assumed. An earlier revision of this document
read the declared version and concluded the bump exchanged two HIGH advisories
for one. That was wrong, and @prayagupa caught it in review.

## Breaking Change Risk Assessment

Low, and lower than the version numbers suggest.

The SDK major is a version-line alignment, not an API break. The CHANGELOG
entry for `[5.0.0]` records a coordinated renumbering across all first-party
packages plus widening internal cross-package caps from `<5.0` to `<6.0`. It
does not describe a removed or changed API, and the published `4.0.0` and
`5.0.0` manifests agree on runtime requirements, so no consumer is being asked
to move Node versions.

The genuine major underneath, `js-yaml` `4.x` to `5.x`, **is not reached**.
The override holds the installed parser at `4.2.0`, so the SDK's move to a
`5.x` pin has no runtime effect in these three packages. None of the three
depends on `js-yaml` directly, none imports it, and each declares the SDK as
its only dependency, so the parser is reached solely through whatever the SDK
already does with it, at the version the override selects.

Residual risk worth stating plainly: the three packages have been shipping at
`5.0.0` while pinned to the `4.0.0` SDK, so this is the first time the
published CLI version and its published SDK agree. If anything in the v5
alignment did change behaviour, these are the packages where it shows up first.
That argues for landing the three together rather than one at a time.
