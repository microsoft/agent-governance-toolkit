---
title: "Dependency audit: new requirements.txt for the k8s-agent-sandbox-governed example"
last_reviewed: 2026-09-15
owner: karimad
---

# 2026-09-15 - requirements.txt for examples/k8s-agent-sandbox-governed

## Which dependencies changed and why

New file `examples/k8s-agent-sandbox-governed/requirements.txt`, added by
this PR alongside the new `k8s-agent-sandbox-governed` example:

- `agent-governance-toolkit[full]` >= 5.0.0 — the toolkit itself, used to
  call `govern()` on every command before it is dispatched to the sandbox.
- `k8s-agent-sandbox` >= 0.1.0 — the `kubernetes-sigs/agent-sandbox` client
  library, used to drive pod-level sandbox execution. Confirmed registered
  on PyPI (https://pypi.org/project/k8s-agent-sandbox/) with project URLs
  pointing to https://github.com/kubernetes-sigs/agent-sandbox; also added
  to `scripts/check_dependency_confusion.py`'s `REGISTERED_PACKAGES`
  allowlist in this PR to resolve a dependency-confusion scan false
  positive.

## Security advisory relevance

No known advisory addressed. Both packages are newly introduced (no prior
pinned version to compare against) and no CVE motivated the addition.

## Breaking change risk assessment

None for existing code paths. This is a new, isolated example under
`examples/k8s-agent-sandbox-governed/` with its own `requirements.txt`; it
does not change any dependency resolved by other packages in this repo.
