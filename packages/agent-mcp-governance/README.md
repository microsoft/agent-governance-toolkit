<!-- Copyright (c) Microsoft Corporation. -->
<!-- Licensed under the MIT License. -->

# agent-mcp-governance

> **Public Preview** — Standalone Python package that exposes the
> Agent Governance Toolkit's MCP (Model Context Protocol) governance
> primitives for use outside the full AGT monorepo.

## Overview

`agent_mcp_governance` provides a thin, typed re-export surface over the
governance, audit, and trust modules in
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
    GovernanceMiddleware,
    AuditMiddleware,
    TrustGate,
    BehaviorMonitor,
)

# 1. Governance — block prompt-injection patterns
gov = GovernanceMiddleware(
    blocked_patterns=[r"(?i)ignore previous instructions"],
    allowed_tools=["web-search", "read-file"],
    rate_limit_per_minute=60,
)

# 2. Audit — tamper-evident hash-chain logging
audit = AuditMiddleware(capture_data=True)

# 3. Trust — DID-based agent identity verification
gate = TrustGate(min_trust_score=500)

# 4. Monitoring — detect rogue agents
monitor = BehaviorMonitor(
    burst_threshold=100,
    consecutive_failure_threshold=20,
)
```

## API Reference

| Export | Source module | Description |
|--------|-------------|-------------|
| `GovernanceMiddleware` | `agent_os.governance.middleware` | Policy enforcement (rate limits, allow-lists, content filters) |
| `AuditMiddleware` | `agent_os.audit.middleware` | Tamper-evident audit logging with hash chain |
| `TrustGate` | `agent_os.trust.gate` | DID-based trust verification for agent handoffs |
| `BehaviorMonitor` | `agent_os.services.behavior_monitor` | Per-agent anomaly detection and quarantine |

## Compatibility

| Python | agent-os-kernel |
|--------|----------------|
| ≥ 3.10 | ≥ 3.0.0, < 4.0.0 |

## License

[MIT](../../LICENSE) — Copyright (c) Microsoft Corporation.
