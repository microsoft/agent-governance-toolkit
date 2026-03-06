# Agent OS Security Specification

**Version 1.0 | AAIF Compatibility Layer**

This document defines the `.agents/security.md` extension for AGENTS.md repositories.

---

## Overview

While AGENTS.md defines *what* an agent can do, `security.md` defines *how* those actions are governed at the kernel level.

```
.agents/
├── agents.md      # OpenAI/Anthropic standard (instructions)
└── security.md    # Agent OS extension (enforcement)
```

---

## Schema

### Top-Level Structure

```yaml
# .agents/security.md

kernel:
  version: "1.0"                    # Required: Spec version
  mode: strict | permissive | audit # Required: Enforcement mode

signals:                            # Required: Allowed signals
  - SIGSTOP
  - SIGKILL
  - SIGINT

policies:                           # Required: Action policies
  - action: <action_name>
    effect: allow | deny
    mode: read_only | read_write
    requires_approval: true | false
    rate_limit: "<count>/<period>"
    constraints: {}

observability:                      # Optional: Monitoring config
  metrics: true | false
  traces: true | false
  flight_recorder: true | false
```

---

## Kernel Section

### version (required)
Specification version. Currently `"1.0"`.

```yaml
kernel:
  version: "1.0"
```

### mode (required)

| Mode | Behavior |
|------|----------|
| `strict` | Policy violations trigger SIGKILL |
| `permissive` | Policy violations are logged but allowed |
| `audit` | All actions logged, no enforcement |

```yaml
kernel:
  mode: strict
```

---

## Signals Section

Defines which POSIX-style signals the kernel can send to this agent.

### Available Signals

| Signal | Code | Behavior | Catchable |
|--------|------|----------|-----------|
| `SIGSTOP` | 19 | Pause execution | No |
| `SIGCONT` | 18 | Resume execution | No |
| `SIGKILL` | 9 | Terminate immediately | No |
| `SIGTERM` | 15 | Request termination | Yes |
| `SIGINT` | 2 | Interrupt (Ctrl+C) | Yes |
| `SIGPOLICY` | 64 | Policy violation | No |
| `SIGTRUST` | 65 | Trust boundary crossed | No |

### Example

```yaml
signals:
  - SIGSTOP    # Pause for inspection
  - SIGKILL    # Terminate on violation
  - SIGINT     # Allow interruption
```

---

## Policies Section

Defines rules for each action type.

### Policy Fields

| Field | Type | Description |
|-------|------|-------------|
| `action` | string | Action name or `*` for wildcard |
| `effect` | string | `allow` or `deny` |
| `mode` | string | `read_only` or `read_write` |
| `requires_approval` | bool | Human approval needed |
| `rate_limit` | string | Rate limit (e.g., `"100/hour"`) |
| `constraints` | object | Additional constraints |

### Common Actions

| Action | Description |
|--------|-------------|
| `database_query` | SQL queries |
| `database_write` | SQL inserts/updates |
| `file_read` | Read files |
| `file_write` | Write files |
| `api_call` | External API calls |
| `send_email` | Email operations |
| `code_execution` | Run code |
| `*` | Wildcard (all actions) |

### Examples

```yaml
# Read-only database access
policies:
  - action: database_query
    effect: allow
    mode: read_only

# Require approval for writes
  - action: file_write
    effect: allow
    requires_approval: true

# Rate-limited API calls
  - action: api_call
    effect: allow
    rate_limit: "100/hour"

# Block dangerous actions
  - action: code_execution
    effect: deny

# Default allow with logging
  - action: "*"
    effect: allow
    constraints:
      log: true
```

---

## Observability Section

Configure monitoring and audit logging.

```yaml
observability:
  metrics: true           # Expose Prometheus metrics
  traces: true            # Send OpenTelemetry traces
  flight_recorder: true   # Log all actions for replay
```

### Metrics Exposed

When `metrics: true`:
- `agent_os_requests_total{action, status}`
- `agent_os_violations_total{agent_id, action, policy}`
- `agent_os_policy_check_duration_seconds`
- `agent_os_signals_total{signal, reason}`

### Traces Emitted

When `traces: true`:
- `kernel.policy_check`
- `kernel.execute`
- `kernel.signal`
- `kernel.violation`

---

## Policy Templates

### Strict (Recommended for Production)

```yaml
kernel:
  version: "1.0"
  mode: strict

signals:
  - SIGSTOP
  - SIGKILL
  - SIGINT

policies:
  - action: database_query
    effect: allow
    mode: read_only
  - action: database_write
    effect: deny
  - action: file_read
    effect: allow
  - action: file_write
    effect: allow
    requires_approval: true
  - action: api_call
    effect: allow
    rate_limit: "100/hour"
  - action: send_email
    effect: allow
    requires_approval: true
  - action: code_execution
    effect: deny

observability:
  metrics: true
  traces: true
  flight_recorder: true
```

### Permissive (Development)

```yaml
kernel:
  version: "1.0"
  mode: permissive

signals:
  - SIGSTOP
  - SIGKILL

policies:
  - action: "*"
    effect: allow
    constraints:
      log: true

observability:
  metrics: true
  traces: false
  flight_recorder: true
```

### Audit (Testing)

```yaml
kernel:
  version: "1.0"
  mode: audit

signals:
  - SIGSTOP

policies:
  - action: "*"
    effect: allow
    constraints:
      log: true
      dry_run: true

observability:
  metrics: true
  traces: true
  flight_recorder: true
```

---

## CLI Usage

```bash
# Initialize with strict template
agentos init --template strict

# Initialize with custom template
agentos init --template permissive

# Validate security config
agentos secure --verify

# Audit current configuration
agentos audit --format json
```

---

## Integration

### Python

```python
from agent_os import discover_agents, AgentsParser

# Discover configs in current directory
configs = discover_agents(".")

# Parse and convert to kernel policies
parser = AgentsParser()
policies = parser.to_kernel_policies(configs[0])

# Use with StatelessKernel
from agent_os import StatelessKernel, ExecutionContext

kernel = StatelessKernel()
context = ExecutionContext(
    agent_id="my-agent",
    policies=["read_only"]
)

result = await kernel.execute(
    action="database_query",
    params={"query": "SELECT * FROM users"},
    context=context
)
```

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: Agent Security
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: microsoft/agent-os/.github/actions/agent-os-audit@main
        with:
          fail-on-violation: true
```

---

## Compatibility

| Standard | Support |
|----------|---------|
| AGENTS.md (OpenAI) | Full |
| AGENTS.md (Anthropic) | Full |
| MCP Tools | Via mcp-kernel-server |
| MCP Resources | Via VFS mapping |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01 | Initial specification |

---

## References

- [Agent OS GitHub](https://github.com/microsoft/agent-governance-toolkit)
- [AGENTS.md Specification](https://github.com/anthropics/agents)
- [MCP Protocol](https://modelcontextprotocol.io)
- [POSIX Signals](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/signal.h.html)
