---
title: "Studio sidecar runtime dependency audit"
last_reviewed: 2026-10-12
owner: studio-team
---

# Studio sidecar runtime dependency audit

Draft #4281 layer above unmerged #4170. No npm dependency, lockfile, install-hook
scanner or `fsevents` exception is changed.

Studio directly declares the real core/compliance/ACS distributions and Click,
FastAPI and Uvicorn; it does not install the deprecated mesh distribution or rely
on a development extra. `runtime-constraints.txt` records the complete third-party
runtime resolution used by clean-install tests. The first dry resolution selected
`aiohttp 3.14.4` (six days old); it was **not installed**, and the resolution was
pinned to stable `3.14.3`. Public PyPI release metadata was checked for every
resolved third-party dependency; all selected releases were at least seven days
old on 2026-10-12 (the youngest, `rpds-py 2026.9.1`, was released 2026-10-04).
No new obscure integration dependency or install-script exception was added.

Core, compliance, Studio and the unpublished native ACS `0.4.0b0` wheels are
built from the same source checkout. The native wheel is not replaced with an
older public release. OPA `0.70.0` is the existing Engine API CI runtime;
its Windows and Linux SHA-256 digests and reproducible install commands are
documented in the [draft usage page](../studio/sidecar.md).

FastAPI `0.141.1` (2026-07-29), Uvicorn `0.52.4` (2026-08-19) and Click `8.4.2`
(2026-06-24) were selected as stable existing runtime versions. Their owners and
upstream project identities match the existing AGT runtime dependencies. Runtime
resolution introduces no new project-specific external integration.
This release-age/dependency review is not a claim that the pending scaffold
supply-chain exception or this sidecar's security reviews have been approved.
