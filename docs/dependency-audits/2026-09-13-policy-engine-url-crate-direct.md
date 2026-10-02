---
title: "Dependency audit: url 2.5.8 becomes a direct dependency of the ACS Rust SDK"
last_reviewed: 2026-09-13
owner: agt-maintainers
---

# 2026-09-13 - url 2.5.8 as a direct dependency of `agent_control_specification`

Part of the follow-up to the policy-engine retarget (#3939, follow-up #3940).

## What changed and why

`policy-engine/sdk/rust/Cargo.toml` now lists `url = "=2.5.8"` as a direct
dependency. The SSRF guard on manifest URL loading (`reject_blocked_fetch_host`)
hand-split the URL authority and parsed it with `str::parse::<IpAddr>()`,
which only understands dotted-quad. The upstream fetcher parses the same
URL with the `url` crate, which canonicalizes non-canonical IPv4 literals
(`127.1`, `0x7f000001`, `2130706433`, octal forms), so those literals passed
the guard and reached loopback. The guard now parses with the same crate the
fetcher uses and evaluates the canonical host, so both sides agree.

## Provenance and version

`url` 2.5.8 was already present in all three affected lockfiles as a
transitive dependency of `agent-control-spec`, `reqwest` and `hyper`; the
lockfile change is one line per file adding the `agent_control_specification`
edge to the existing package entry. No new package, no checksum change. The
crate is maintained by the servo project (https://github.com/servo/rust-url),
released 2026-01-06 (250 days before this change), and clears the repo's
7-day cooling-off check (`scripts/check_release_age.py`: all 9 dependencies OK).

## Breaking-change risk assessment

None. The version is pinned exactly to the one already resolved in the
lockfiles, so the dependency graph is unchanged apart from the new edge.
The guard's behavior change (canonical-host evaluation, widened blocked set)
is documented in `BREAKING_CHANGES.md` and covered by the extended
`manifest_from_url_blocks_ssrf_targets` test and the loopback-listener
no-connect test.

## Security advisory relevance

No advisory drove this change; it closes a bypass found in the group review
of #3939. `cargo audit` on the workspace reports no advisory for url 2.5.8.
