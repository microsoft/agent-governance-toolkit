# AgentConfig File Reference

`AgentConfig.from_file()` loads `.yaml`, `.yml`, and `.json` files into the
`AgentConfig` dataclass in `agent-governance-python/agent-os/src/agent_os/base_agent.py`.

Use [`../examples/agent_config.yaml`](../examples/agent_config.yaml) as the
baseline example when creating new agent configs.

## Supported file keys

| Field | Type | Required | Default | Notes |
|-------|------|----------|---------|-------|
| `agent_id` | string | Yes, in practice | `"agent"` when omitted | Must match `^[a-zA-Z0-9][a-zA-Z0-9-]{2,63}$`. Set this explicitly to avoid collisions between agents. |
| `agentId` | string | No | None | Camel-case alias accepted only when `agent_id` is absent. Prefer `agent_id` in new configs. |
| `policies` | array of strings | No | `[]` | Policy names copied into every execution context created by the agent. |
| `metadata` | mapping | No | `{}` | Free-form metadata copied into the execution context before each request. |
| `max_audit_log_size` | integer | No | `10000` | Maximum number of in-memory audit entries retained by `BaseAgent`. |
| `max_metadata_size_bytes` | integer | No | `1048576` | Per-value byte limit checked when metadata is copied into a new execution context. |

## Constructor-only fields

The `AgentConfig` dataclass also accepts `state_backend` when instantiated in
Python, but `from_file()` does not read a `state_backend` key from YAML or JSON
files. Configure custom state backends in code:

```python
from agent_os.base_agent import AgentConfig
from agent_os.state_backends import InMemoryStateBackend

config = AgentConfig(
    agent_id="agent-with-custom-state",
    state_backend=InMemoryStateBackend(),
)
```

## Validation rules

### `agent_id`

- Minimum length: 3 characters
- Maximum length: 64 characters
- First character: letter or number
- Remaining characters: letters, numbers, or `-`

Examples:

- Valid: `research-agent-01`
- Invalid: `my_agent` because `_` is not allowed
- Invalid: `ab` because it is too short

### `metadata`

Metadata is accepted as free-form YAML/JSON, but each value is size-checked
later when `BaseAgent` creates a new execution context. If any single value
exceeds `max_metadata_size_bytes`, Agent OS raises a `ValueError`.

## Valid example

```yaml
agent_id: review-agent-01
policies:
  - read_only
  - no_pii
metadata:
  environment: staging
  owner: team-platform
max_audit_log_size: 5000
max_metadata_size_bytes: 262144
```

## Invalid examples

### Invalid `agent_id`

```yaml
agent_id: my_agent
policies:
  - read_only
```

This fails validation because `agent_id` contains `_`.

### Metadata value too large at runtime

```yaml
agent_id: oversized-metadata-demo
metadata:
  huge_blob: "<very large string or object here>"
max_metadata_size_bytes: 1024
```

This file can load successfully, but `BaseAgent` raises a `ValueError` when it
builds an execution context if `huge_blob` is larger than 1024 bytes.
