---
title: agent-governance-sdk 4.0.0 to 5.0.0 in the three CLI packages
last_reviewed: 2026-08-12
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
- `js-yaml` `4.1.1` to `5.2.1`, transitively, as the SDK's own pin. This is the
  only third-party change the bump carries. Comparing the two published
  manifests, `@noble/ciphers` `2.2.0`, `@noble/curves` `2.2.0`,
  `@noble/ed25519` `3.1.0`, `@noble/hashes` `2.2.0`, `engines.node >=18.0.0`
  and the MIT license are all identical between `4.0.0` and `5.0.0`.
- The lockfiles also drop a second, separate `js-yaml` `4.2.0` entry that the
  older tree resolved. After this change each package resolves a single
  `js-yaml`.

Each CLI package declares exactly one dependency, the SDK, so there is no other
surface to consider.

## Security Advisory Relevance

**This bump does not clear the CLI packages of a known advisory. It exchanges
two for one, and the incoming version is itself unpatched.**

Outgoing, `js-yaml` `4.1.1` is in range for two HIGH advisories:

- `GHSA-5p4m-2wfm-xmqj`, quadratic CPU consumption in `!!omap` resolution,
  affecting `>= 4.0.0, < 4.3.1`, first patched in `4.3.1`.
- `GHSA-52cp-r559-cp3m`, YAML merge-key chains forcing quadratic CPU
  consumption, affecting `>= 4.0.0, < 4.3.0`, first patched in `4.3.0`.

Incoming, `js-yaml` `5.2.1` is in range for one HIGH advisory:

- `GHSA-pm4m-ph32-ghv5`, exponential parsing time in flow collections,
  affecting `>= 5.0.0, <= 5.2.1`, **first patched in `5.2.2`**.

`5.2.1` is clear of `GHSA-724g-mxrg-4qvm` (MODERATE, `<= 5.2.0`) and of
`GHSA-g796-fgmg-93mv` (MODERATE, `<= 5.1.0`), which is presumably why the SDK
landed on that pin. `GHSA-pm4m-ph32-ghv5` was published against the `5.x` line
afterwards. The current `js-yaml` release is `5.2.3`.

All four advisories are the same class: algorithmic-complexity denial of
service reachable only through parsing attacker-influenced YAML. The direction
of travel is right, from two HIGH to one, and it should not be read as the
bump making these packages advisory-free.

**The source fix already landed, the published artifact has not.**
`agent-governance-typescript/package.json` on `main` now pins `js-yaml`
`5.2.3`, via #3623 on 2026-08-12. So the SDK source is clear of all four
advisories above.

What these three packages resolve is the *published* `@microsoft/agent-governance-sdk`
`5.0.0`, released to npm on 2026-08-03, whose manifest pins `js-yaml` `5.2.1`.
That artifact is immutable, so nothing in these lockfiles can reach `5.2.3`
until a new SDK version is published.

No follow-up PR is needed, and overriding `js-yaml` in three CLI lockfiles
would be the wrong fix: it would pin around the SDK in three places and drift
the moment the next SDK release lands. The residual exposure closes on the next
publish. Recording it here so the gap between "fixed on main" and "fixed in what
consumers install" is visible rather than assumed.

## Breaking Change Risk Assessment

Low, and lower than the version numbers suggest.

The SDK major is a version-line alignment, not an API break. The CHANGELOG
entry for `[5.0.0]` records a coordinated renumbering across all first-party
packages plus widening internal cross-package caps from `<5.0` to `<6.0`. It
does not describe a removed or changed API, and the published `4.0.0` and
`5.0.0` manifests agree on runtime requirements, so no consumer is being asked
to move Node versions.

The genuine major underneath is `js-yaml` `4.x` to `5.x`, and the risk there
sits with the SDK rather than with these three packages. None of the three
depends on `js-yaml` directly, none imports it, and each declares the SDK as
its only dependency, so the parser is reached solely through whatever the SDK
already does with it. A `js-yaml` behaviour change would surface as an SDK
behaviour change, in a version of the SDK that has been published since
2026-08-03.

Residual risk worth stating plainly: the three packages have been shipping at
`5.0.0` while pinned to the `4.0.0` SDK, so this is the first time the
published CLI version and its published SDK agree. If anything in the v5
alignment did change behaviour, these are the packages where it shows up first.
That argues for landing the three together rather than one at a time.
