---
title: "2026-10-21 — Release-stage label removal"
last_reviewed: 2026-10-21
owner: agt-maintainers
---

# 2026-10-21 — Release-stage label removal

Issue: [microsoft/agent-governance-toolkit#4373](https://github.com/microsoft/agent-governance-toolkit/issues/4373)

## What changed and why

The release-stage label discussed in issue #4373 was removed from
documentation, package metadata, docstrings and comments across the
repository. The only change under a security-gated path is the module docstring of
`agent-governance-python/agent-os/src/agent_os/mcp_gateway.py`, where the
title line lost its stage suffix and now reads "MCP Security Gateway".
No statement, import or constant changed.

## Threat model impact

None. The gateway's allow/deny filtering, parameter sanitization, rate
limiting and response scanning are untouched, and no interface was added
or removed.

## Test coverage

The `agent-os`, `agent-sre`, `agent-mesh` and `agent-hypervisor` suites were
run after the change; every result matched the same run on `main`, which is
expected since only comments, docstrings and skip reasons changed. A new
Quality Gates job runs `scripts/ci/check_no_public_preview.sh`, which fails
if the label returns outside the dated release history.
