<!-- Copyright (c) Microsoft Corporation. -->
<!-- Licensed under the MIT License. -->

# agent-mcp-governance

> **Public Preview** — Standalone Python package that exposes a focused
> governance, audit, and trust import surface from Agent OS for MCP-oriented
> Python consumers outside the full AGT monorepo.

## Overview

`agent_mcp_governance` provides a thin, typed re-export surface over the
currently available governance, audit, and trust modules in
[`agent-os-kernel`](https://pypi.org/project/agent-os-kernel/).  It is
**not** zero-dependency — it requires `agent-os-kernel >=3.0.0,<4.0.0`.

## Installation

```bash
pip install agent-mcp-governance
```

This will pull in `agent-os-kernel` automatically.

## Quick Start

```python
from agent_mcp_governance import (
    AuditEntry,
    GovernanceAuditLogger,
    GovernanceMiddleware,
    GovernancePolicy,
    PolicyEvaluator,
    TrustDecision,
    TrustRoot,
)

# 1. Governance compatibility layer
gov = GovernanceMiddleware()
evaluator = PolicyEvaluator()

# 2. Audit logging
audit = GovernanceAuditLogger()
entry = AuditEntry(agent_id="did:mesh:agent-1", action="search", decision="allow")
audit.log(entry)

# 3. Trust root policy evaluation
trust_root = TrustRoot(policies=[GovernancePolicy(allowed_tools=["search"])])
```

## API Reference

| Export | Source module | Description |
|--------|-------------|-------------|
| `GovernanceMiddleware` | `agent_os.compat` | Compatibility middleware surface for governance-aware consumers |
| `PolicyEvaluator` | `agent_os.compat` | Policy evaluator facade (real implementation when available) |
| `GovernanceAuditLogger` | `agent_os.audit_logger` | Pluggable governance audit logger |
| `AuditEntry` | `agent_os.audit_logger` | Structured governance audit record |
| `TrustRoot` | `agent_os.trust_root` | Deterministic trust authority for policy checks |
| `TrustDecision` | `agent_os.trust_root` | Result object returned by trust-root evaluations |

## Compatibility

| Python | agent-os-kernel |
|--------|----------------|
| ≥ 3.10 | ≥ 3.0.0, < 4.0.0 |

## License

[MIT](../../LICENSE) — Copyright (c) Microsoft Corporation.
