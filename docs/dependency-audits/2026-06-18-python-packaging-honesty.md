---
title: Python packaging metadata alignment (version pins and requirements.txt)
last_reviewed: 2026-06-18
owner: liamcrumm
---

# Python packaging metadata alignment

## Which Dependencies Changed And Why

This PR standardizes Python packaging metadata. The dependency-relevant changes are:

- `examples/cedarling-governed/requirements.txt` — removed the
  `cedarling_agentmesh>=3.5.0` requirement. That distribution name is 404 on
  PyPI (verified), so `pip install -r requirements.txt` could not resolve it.
  It is replaced with a comment pointing at the in-repo source install. The
  external `cedarling-python>=0.0.4` and `agent-os-kernel>=3.5.0` lines are
  unchanged.
- Internal first-party version pins across the `agent-governance-python`
  packages were bumped from `>=4.0.0,<5.0` to `>=4.1.0,<5.0` so that every
  internal `agent-governance-toolkit-*` reference tracks the current 4.1.0
  release line. Third-party pins (for example `cedarpy>=4.0.0,<5.0`) were not
  touched.

No lockfile hashes, no new third-party packages, and no transitive dependency
trees changed. The SBOM diff bot reported "No dependency changes detected".

## Security Advisory Relevance

- No CVEs are addressed. This is a metadata-honesty and consistency change.
- Removing the unresolvable `cedarling_agentmesh` requirement reduces the risk
  of a future dependency-confusion install against an unclaimed PyPI name.

## Breaking Change Risk Assessment

- Low for the requirements.txt change. The removed name was unresolvable, so no
  working install relied on it; the example now installs the integration from
  source.
- Low for the internal pin bump. The whole monorepo is already at 4.1.0, so
  `>=4.1.0,<5.0` is satisfied by every first-party package today. The only
  user-visible effect is that consumers cannot mix a 4.0.x first-party package
  with these 4.1.0 packages, which the consolidation already discourages.
