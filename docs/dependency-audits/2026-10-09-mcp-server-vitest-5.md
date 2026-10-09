---
title: MCP server Vitest 5 consolidated dependency audit
last_reviewed: 2026-10-09
owner: Ricky-G
---

<!-- cspell:words vite jridgewell magicast obug picomatch tinybench tinyexec istanbuljs estree EALLOWREMOTE -->

# MCP server Vitest 5 consolidated dependency audit

## Which dependencies changed and why

This is the user-approved consolidation of Dependabot PRs #3960 and #4117,
not two competing lockfile updates. Both originals remain open. This
proposed registry-neutral lock is for draft evaluation only: hosted
verification of the unchanged supply-chain gates and Node 22 installation
is required before it can become ready for review or merge.

Scope: `agent-governance-python/agent-os/extensions/mcp-server`, plus this
required audit document. The baseline is main commit
`17595e649abdfa703962c2f8c241826f68318109`.

| Dependency | Baseline | Intended version | Reason |
|---|---|---|---|
| `vitest` | 4.1.11 | 5.0.3 | Preserve #4117's latest eligible runner upgrade |
| `@vitest/coverage-v8` | 4.1.10 | 5.0.3 | Preserve #3960's coverage upgrade and satisfy its exact runner peer |
| `vite` | Transitive 8.0.16 | Explicit dev dependency 8.0.16 | Retain the existing version when CI uses `--legacy-peer-deps` |
| `nanoid` | Transitive 3.3.16 | 3.3.19, lock-only | Fix a known advisory in the retained required Vite toolchain |

No runtime dependency, other package, shared workflow, security policy, or
validator is changed. The existing TypeScript 7 compiler and TypeScript 6
compatibility aliases must remain unchanged.

Both live diffs, complete paginated discussions and timelines, and resolved
thread queries were read:

| Original | Observed head | Discussion |
|---|---|---|
| #3960 | `c5550236bbca5931f1d36a06bf40d8f7b9e3dd5f` | 5 issue comments, 28 timeline events, no reviews or inline/resolved threads |
| #4117 | `36b19c3112996f87e42f28238b505fa5800c7cb6` | 4 issue comments, 21 timeline events, no reviews or inline/resolved threads |

#3960's maintainer discussion identifies the missing required Vite peer:
both original lock diffs remove Vite. Making the already-installed 8.0.16
version explicit addresses that failure without a Vite version bump.
The Node 22 CI prerequisite from #4006 is already on main.
#3960 also predates main's TypeScript/tooling updates; regenerating from main,
rather than copying its stale lock, preserves those changes.

Both originals fail the legitimate semver-major Dependency Audit Trail gate:
their lockfiles change without a dependency audit document. The failure logs
are Actions runs `35917104507` and `37796326465`. This document supplies the
required evidence; no exemption or gate change is proposed.

## Release age, provenance, and transitive changes

The seven-day cutoff for the initial review is
`2026-10-01T22:50:41.670Z`. Exact registry publication timestamps were checked
before installing the upgraded graph. No fallback or runner downgrade is
needed: both 5.0.3 releases are older than seven days.

| Selected package | Version | Published, UTC |
|---|---|---|
| `vitest` | 5.0.3 | 2026-09-30 11:30:42 |
| `@vitest/coverage-v8` | 5.0.3 | 2026-09-30 11:29:29 |
| `@vitest/mocker` | 5.0.3 | 2026-09-30 11:29:00 |
| `@vitest/spy` | 5.0.3 | 2026-09-30 11:30:17 |
| `@vitest/istanbul-lib-coverage` | 1.0.2 | 2026-09-27 10:55:51 |
| `@vitest/istanbul-lib-report` | 1.0.2 | 2026-09-27 10:56:18 |
| `@babel/parser` | 7.29.9 | 2026-09-18 13:50:33 |
| `@babel/types` | 7.29.8 | 2026-07-31 15:07:29 |
| `@jridgewell/sourcemap-codec` | 1.6.0 | 2026-08-28 01:14:47 |
| `ast-v8-to-istanbul` | 1.0.7 | 2026-09-21 14:30:05 |
| `chai` | 6.3.0 | 2026-09-30 19:18:04 |
| `es-module-lexer` | 2.3.2 | 2026-08-17 01:57:36 |
| `expect-type` | 1.4.0 | 2026-06-25 13:41:23 |
| `magic-string` | 1.4.2 | 2026-09-23 12:01:20 |
| `magicast` | 0.5.5 | 2026-09-11 03:31:09 |
| `obug` | 2.2.1 | 2026-09-09 05:52:50 |
| `picomatch` | 4.0.7 | 2026-08-24 14:36:23 |
| `std-env` | 4.3.0 | 2026-09-29 12:40:32 |
| `tinybench` | 6.2.0 | 2026-09-09 19:54:16 |
| `tinyexec` | 1.3.1 | 2026-09-03 08:50:07 |
| `tinyrainbow` | 3.2.0 | 2026-09-30 10:40:46 |
| `why-is-node-running` | 3.2.1 | 2024-10-29 17:08:48 |
| `vite`, unchanged version | 8.0.16 | 2026-06-01 09:50:43 |
| `nanoid`, scoped security refresh | 3.3.19 | 2026-09-10 18:00:48 |

The upstream Vitest release tag points to GitHub-verified release commit
`33cadea62e8763c455c7fca38d9ab1dda87c5f75`. Published package names, versions,
repository identities, dependencies and scripts were compared with the
official tagged `vitest-dev/vitest` manifests. Vitest 5's Istanbul forks
are official `vitest-dev/istanbuljs` packages, licensed MIT; their introduction
is documented in the upstream release notes. The Nano ID 3.3.19 annotated
tag is also GitHub-verified and its package manifest is MIT-licensed.

The graph removes Vitest 4's separately packaged runner, assertion,
snapshot, utility and formatting dependencies as upstream bundles them
into Vitest 5. It replaces the previous Istanbul reporting dependencies
with the official Vitest forks. Unrelated package versions remain fixed.
The only additional security refresh changes `node_modules/nanoid`;
a snapshot comparison confirmed every other entry and root metadata
unchanged by that command.

Every newly selected package's registry scripts and repository metadata
were inspected. No new `preinstall`, `install`, or `postinstall` hooks are
introduced. The only `hasInstallScript` entry is unchanged, Darwin-only
`fsevents@2.3.3`. `tinyexec` has an authoring-time `prepare` script; these
are registry tarballs, not Git dependencies, and installation uses the
existing CI `--ignore-scripts` policy.

## Security advisory relevance

The baseline and initially upgraded graph both contain:

```text
vite@8.0.16 -> postcss@8.5.23 -> nanoid@3.3.16
```

`GHSA-2v37-7h3g-55p8` reports a high-severity infinite-loop risk in Nano ID
custom generators. Its upstream advisory identifies `<3.3.18` as affected
and 3.3.18 as the first fixed 3.x release. This is an unchanged baseline
issue in the required retained development toolchain, not a newly
introduced runtime vulnerability. The coordinator approved the minimal
lock-only refresh to eligible 3.3.19. No override, audit suppression, Vite
bump, or PostCSS bump is used. The installed upgraded graph reports zero
vulnerabilities.

## Breaking change risk assessment

Vitest 5 requires Node.js `^22.12.0 || ^24.0.0 || >=26.0.0` and Vite
`^6.4.0 || ^7.0.0 || ^8.0.0`. Local validation uses Node 26.7.0 and npm
12.0.2; existing package CI uses Node 22. Hosted Node 22 verification is
still required. Production runtime engine declarations are not changed.

The package has no pre-existing tests, custom Vitest configuration,
browser environment, snapshots, mocks, deprecated runner imports, or
coverage thresholds to migrate. The upstream migration guide was
reviewed for changed mock defaults, removed entry points, precise coverage
globs, and configuration lookup behavior.

The new 16-test suite checks actual installed runner/coverage versions,
the explicit Vite dependency, and real template-library behavior, including
filtering, search, unknown inputs, suggestions and compliance frameworks.
It contains no production changes or mocks. On the baseline, 14 behavior
tests pass and exactly two toolchain regressions fail. After upgrading,
all 16 pass with real V8 coverage. Empty test discovery no longer succeeds,
coverage runs once instead of entering watch mode, and lint includes tests.

## Validation evidence

Package commands are run from the MCP server directory.

| Command | Baseline result | Actual upgraded graph result |
|---|---|---|
| `npm ci --legacy-peer-deps --ignore-scripts` | Passed | Passed cleanly on the exact final 307-package SHA512 lock; lock unchanged |
| `npm run build` | Passed | Passed |
| `npm test` | Passed with zero tests; new suite fails the two intended regressions | 16/16 passed |
| `npm run lint` | Passed | Passed, including new tests |
| `npm run typecheck` | Passed | Passed |
| `npm run test:coverage -- --run` | Failed: no tests and mixed-version warning | Replaced by the single-run command below |
| `npm run test:coverage` | Watch-mode baseline script not used unattended | 16/16 passed with actual 5.0.3 V8 provider |
| `npm ls vitest @vitest/coverage-v8 vite nanoid` | Nano ID trace inspected | Passed: 5.0.3 / 5.0.3 / 8.0.16 / 3.3.19 |
| `npm audit --json` | Failed: one high Nano ID advisory | Passed: zero vulnerabilities |
| `npm audit signatures` | Not run | Blocked: configured mirror is not a supported signing registry |

Coverage for `src/services/template-library.ts` is 100% lines, 100%
functions, 98.75% statements and 97.05% branches. This is an imported-service
coverage result, not a whole-server claim.

Before adding this document, repository-wide `python scripts\docs\check_links.py`
passed (307 files, 2,852 links) and
`python scripts\docs\check_frontmatter.py --strict` passed (294 files).
Both commands still pass after the changes. Explicit changed-document
link validation passes (two files, six links), and strict frontmatter
validation of this audit passes. Dependency audits are excluded from
the default published-docs discovery, so the explicit audit check matters.

The new test file also passes strict TypeScript 7 checking:
`node node_modules\@typescript\native\bin\tsc --ignoreConfig --noEmit --module esnext --moduleResolution bundler --target ES2022 --strict --skipLibCheck --resolveJsonModule --esModuleInterop tests\vitest-upgrade.test.ts`.
`--ignoreConfig` is required by TypeScript 7 for an explicit-file check;
the existing package configuration was separately checked by the normal
build and typecheck commands.

The final frozen install preserved the lockfile's SHA256:
`90cc658af0af3ba84e4c6777afd440566d59bf60979b1cb84aa2ab386aa57199`.
All functional commands above were rerun against this exact final lock,
not only against an earlier experimental representation.

## Proposed registry-neutral format and remaining hosted gates

The configured registry is `https://packagefeedproxy.microsoft.io/npm/`.
Its version metadata emits environment-specific Microsoft feed tarball
URLs and omits SHA512 for several entries. The initial generated lock's
feed URLs were rejected with `EALLOWREMOTE`. Remote-fetch permissions,
registry configuration and TLS settings have not been changed.

Npm's supported
`--omit-lockfile-registry-resolved` option produced the identical exact
version graph using registry package names. The initial unrefined
representation was correctly rejected: it lost required canonical
resolved URLs for three existing TypeScript aliases, and mirror metadata
produced 16 SHA1-only entries. It was not committed.

The user subsequently approved a registry-neutral format only with all
existing checks passing. The final proposed representation retains
the three existing aliases' canonical URLs verbatim from main and preserves
exact same-package/version SHA512 values already present in main or the
two original npm-generated Dependabot locks. All corroborating sources
agree. Bulk metadata-preservation tooling applies those existing values to
the fresh native-generated graph; it does not construct digests or URLs or
restore a stale full lockfile.

All 16 corresponding raw tarballs in npm's existing content-addressed cache
were independently read, SHA512-checked, and checked for matching embedded
package names and versions without extraction or execution. All 16 matched.
This yields 307 SHA512 entries and zero findings from the unchanged
integrity/alias parser. A clean ordinary frozen install then verified the
actual final representation and its package bytes successfully.

For provenance, the source labels below identify immutable npm-generated
lockfile blobs at the existing MCP server path:

| Source | Commit | Lockfile blob |
|---|---|---|
| main | `17595e649abdfa703962c2f8c241826f68318109` | `2b716ba5e6d964e498db9acb1ff3abbf2c59bb8f` |
| #3960 | `c5550236bbca5931f1d36a06bf40d8f7b9e3dd5f` | `ac282e36c11c58952a27461bd963ff494c708e78` |
| #4117 | `36b19c3112996f87e42f28238b505fa5800c7cb6` | `fe82ccf9440d9126d8b5cc09e00add2a6c55066a` |

These are the exact lock entry paths and versions whose genuine existing
SHA512 values are preserved; values are independently corroborated by all
matching source blobs, not inferred from another version:

| Lock entry | Version | Selected source |
|---|---|---|
| `node_modules/@babel/helper-string-parser` | 7.29.7 | main |
| `node_modules/@babel/helper-validator-identifier` | 7.29.7 | main |
| `node_modules/@babel/types` | 7.29.8 | #3960 |
| `node_modules/@jridgewell/resolve-uri` | 3.1.2 | main |
| `node_modules/@jridgewell/sourcemap-codec` | 1.6.0 | #3960 |
| `node_modules/@jridgewell/trace-mapping` | 0.3.31 | main |
| `node_modules/@types/chai` | 5.2.3 | main |
| `node_modules/@types/deep-eql` | 4.0.2 | main |
| `node_modules/assertion-error` | 2.0.1 | main |
| `node_modules/es-module-lexer` | 2.3.2 | #3960 |
| `node_modules/estree-walker` | 3.0.3 | main |
| `node_modules/expect-type` | 1.4.0 | #3960 |
| `node_modules/js-tokens` | 10.0.0 | main |
| `node_modules/obug` | 2.2.1 | #3960 |
| `node_modules/picomatch` | 4.0.7 | #3960 |
| `node_modules/tinyexec` | 1.3.1 | #4117 |

The canonical URLs for `node_modules/@typescript/native` (7.0.2),
`node_modules/@typescript/old` (6.0.3), and `node_modules/typescript`
(6.0.2) are preserved verbatim from the main blob; their names, versions,
integrity values and approved declarations remain unchanged.

These structural and tarball checks do not waive independent upstream
registry verification. No scanner, alias rule, hash rule, allowlist,
permission or conditional-approval requirement is changed.

Hosted evaluation of the initial proposed head
`664e886ea92d14a2284aa734f24bea2ded785e68` supplied the missing independent
evidence. The Node 22 job actually installed the final lock, built the server,
ran Vitest 5.0.3 and passed all 16 tests. The upstream integrity job checked
all 304 affected entries and reported that every hash matches primary
registry metadata. Hosted release-age, install-script, Scorecard and
Dependency Audit Trail checks also passed. These are actual executed checks,
not skipped-job or local-parser proxies.

Job evidence: Node 22 `113599142226` in CI run `37861810913`;
primary-registry integrity `113599073359` in run `37861810865`.
The two failures on that initial head were the missing registered-Vite
catalog entry and spelling of ten genuine technical names. The latter is
addressed by this document's exact local terminology declaration, following
existing dependency-audit prior art, without disabling spelling checks or
changing shared dictionaries. Latest-head hosted checks still must pass;
the registered-name catalog prerequisite remains separately owned.

The unchanged gates were run on the committed proposal from the repository
root. Network-dependent failures below are not successful verifications:

| Command | Result |
|---|---|
| `bash scripts\ci\vendored-patch-audit.sh origin/main` | Passed: the changed lockfile has this genuine audit document |
| `bash scripts\ci\no-stubs.sh origin/main` | Passed |
| `bash scripts\ci\no-custom-crypto.sh origin/main` | Passed |
| `bash scripts\ci\security-audit-required.sh origin/main` | Passed: no capability paths changed |
| `bash scripts\ci\no-unauthed-registration.sh origin/main` | Passed: no Python files changed |
| `python scripts\check_build_hooks.py --base origin/main --strict` | Passed |
| `python scripts\check_release_age.py --base origin/main --min-age-days 7` | Blocked, exit 1: three direct pins unverifiable through primary-registry TLS |
| `python scripts\check_install_scripts.py --base origin/main --strict --max-deps 2000` | Blocked, exit 1: 24 candidates unverifiable through primary-registry TLS |
| `python scripts\check_lockfile_integrity.py --base origin/main --max-deps 2000` | Blocked, exit 1: all 304 affected-entry findings are primary-registry network failures; zero alias/weak-digest findings |
| `python scripts\check_dependency_scorecard.py --base-ref origin/main --head-ref HEAD --min-score 5.0 --max-deps 50` | Exit 0, warn-only: Vite score lookup remains TLS-unverified |
| Scoped strict dependency-confusion command below | Failed, exit 1: the existing registered-name catalog omits `vite` |

```powershell
python scripts\check_dependency_confusion.py --strict agent-governance-python\agent-os\extensions\mcp-server\package.json agent-governance-python\agent-os\extensions\mcp-server\package-lock.json agent-governance-python\agent-os\extensions\mcp-server\README.md docs\dependency-audits\2026-10-09-mcp-server-vitest-5.md
```

The unmodified primary-registry lookups in the repository age and
integrity validators also fail TLS handshake validation locally.
The explicit runner/coverage age command is therefore blocked:
`python scripts\check_release_age.py --explicit npm:vitest@5.0.3 --explicit npm:@vitest/coverage-v8@5.0.3 --min-age-days 7`.
Configured-mirror age evidence is not described as a passing primary-registry
gate. Npm signing attestations and historical maintainer continuity cannot
be independently verified through this mirror.

Required next step: run the unchanged integrity, release-age, install-script,
dependency-review and Node 22 checks in hosted CI on the latest proposed head.
Keep the PR in draft and both originals open until those checks really
pass; a draft is not permission to release a failing graph. Local TLS
limitations and unsupported npm signing verification are disclosed rather
than counted as successful checks.

There is also a narrowly scoped shared catalog prerequisite:
`REGISTERED_NPM_PACKAGES` in `scripts/check_dependency_confusion.py` omits
the genuine registered package `vite`, although Vite 8.0.16 is already in
main's transitive graph. CI runs this checker with `--strict`, so the
necessary new explicit declaration will be rejected until a separately
owned catalog correction records that verified package name and its
regression coverage. This replacement does not edit the shared checker,
add skip flags, remove Vite, or reduce check severity to hide the failure.
The prerequisite has been reported to the coordinator for separate
maintainer ownership.

## Attribution, sources, and rollback

Credit Dependabot for the original proposed upgrades and the #3960
maintainer discussion for the Vite prerequisite. GitHub Copilot performed
this user-directed investigation and implementation; human review and
maintainer approval remain pending. No CLA or human-review attestation is
made.

Sources inspected:

- `https://github.com/microsoft/agent-governance-toolkit/pull/3960`
- `https://github.com/microsoft/agent-governance-toolkit/pull/4117`
- `https://github.com/vitest-dev/vitest/releases/tag/v5.0.3`
- `https://github.com/vitest-dev/vitest/blob/v5.0.3/docs/guide/migration/index.md`
- `https://github.com/vitest-dev/vitest/releases/tag/v5.0.0`
- `https://github.com/vitest-dev/istanbuljs`
- `https://github.com/advisories/GHSA-2v37-7h3g-55p8`
- `https://github.com/ai/nanoid/tree/3.3.19`

If a future published update must be reverted, revert its scoped manifest
and lockfile changes together, then repeat frozen installation and the
package build/test/lint/typecheck commands. Do not revert unrelated
TypeScript or runtime dependency updates.
