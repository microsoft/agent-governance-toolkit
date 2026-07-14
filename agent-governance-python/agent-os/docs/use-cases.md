# Agent OS Use Cases

These use cases share one deployment model. Governance is declared in a native
ACS manifest and enforced through `AgtRuntime` plus an
`AdapterRuntimeSession`.

## Common runtime

```python
from agt.policies import AdapterRuntimeSession, AgtRuntime

runtime = AgtRuntime("policies/manifest.yaml")
session = AdapterRuntimeSession(
    runtime,
    agent_id="agent-1",
    session_id="session-1",
)
```

The manifest can bind Rego, Cedar, custom dispatchers, annotators, approval,
limits, and transforms to intervention points. Use ACS `extends` for policy
composition before adapter preflight.

## Code review

Bind secret detection and unsafe-operation policies to `input`,
`pre_tool_call`, and `output`. Register repository tools in the manifest tool
catalog, then evaluate each attempted tool call before execution.

```python
evaluation = session.evaluate_pre_tool_call(
    tool_name="write_file",
    args={"path": "src/app.py", "content": "replacement"},
)
```

## Regulated finance

Use a resolved enterprise manifest with explicit tool catalogs, attempted-call
budgets, approval bindings, and immutable audit export. Financial policy
bundles can deny destructive database operations and require approval for
high-impact actions.

Relevant examples are under
[`examples/policies/production`](../../../examples/policies/production) and
[`examples/policy-templates/financial-services.yaml`](../../../examples/policy-templates/financial-services.yaml).

## Multi-agent research

Create one `AdapterRuntimeSession` per agent session. Share the underlying
runtime only when its dispatchers and approval callback are thread-safe.
AgentMesh trust and transport controls remain separate from ACS policy
evaluation.

## Healthcare data processing

Bind PII and data-residency bundles to input, tool, and output intervention
points. Put sandbox filesystem, network, and resource controls in
`SandboxConfig` rather than policy objects.

```python
from agent_sandbox import SandboxConfig

config = SandboxConfig(
    network_enabled=True,
    network_allowlist=["records.example.com"],
    network_default="deny",
    read_only_fs=True,
)
```

## Enterprise support

Use input policies for prompt-injection screening, a manifest tool catalog for
support actions, attempted-call budgets for abuse resistance, and output
policies for disclosure checks. Denials expose a sanitized message while the
structured evaluation remains available to audit code.

## CI and deployment

Store manifests and bundles with the application. Run `agt lint-policy` during
CI, replay fixtures with `agt test`, and load the same resolved manifest in the
runtime. Do not translate policy folders at process startup.

```bash
agt lint-policy policies/manifest.yaml
agt test policies/manifest.yaml policies/fixtures.json
```

## Cross-cutting rules

| Concern | Native owner |
|---------|--------------|
| Policy definitions and composition | ACS manifest and `extends` |
| Session budgets | `AdapterRuntimeSession` |
| Framework lifecycle and audit hooks | Agent OS adapter |
| Sandbox resources and egress | `SandboxConfig` |
| Multi-agent trust and transport | AgentMesh |
| v4 conversion | `agt migrate v4-to-v5` |

See [Framework Integrations](integrations.md) and
[v4 policy-language removal](../../../docs/v4-removal.md).
