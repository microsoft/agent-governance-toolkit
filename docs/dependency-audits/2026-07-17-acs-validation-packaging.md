---
title: ACS validation packaging and Cargo lock alignment
last_reviewed: 2026-07-17
owner: liamcrumm
---

# ACS validation packaging and Cargo lock alignment

## Which Dependencies Changed And Why

No third-party dependency was added or upgraded.

- `acs-generator` now requires `agent-control-specification>=0.3.1b1,<0.4.0`.
  The generator imports the validation API first published by the Python SDK in
  `0.3.1b1`, so the previous `0.3.1b0` floor was not a valid install contract.
- `policy-engine/Cargo.lock` removes an unused `pyo3-build-config` `0.28.3`
  entry. The Python binding and its build dependency both use `pyo3` `0.29`;
  regenerating the workspace lockfile leaves only `pyo3-build-config` `0.29.0`.

## Security Advisory Relevance

No CVE or RustSec advisory is addressed. The lockfile change removes an unused
version and does not introduce a new package or change the active PyO3 version.
The Python dependency-floor change points to the repository's own MIT-licensed
SDK package.

## Breaking Change Risk Assessment

Risk is low for the lockfile cleanup because the removed package was not in the
active dependency graph. The workspace passes Cargo's `--locked` check after
the cleanup.

The generator version moves to `0.4.0b0` because it is now CLI-only. Requiring
the Python SDK `0.3.1b1` is intentionally stricter and prevents an installation
that would otherwise fail at import time.

## Rollback Plan

Revert the Python package versions and generator dependency floor together.
Restoring the unused `pyo3-build-config` `0.28.3` lock entry is not recommended
because the current workspace then requires a lockfile update under
`cargo --locked`.
