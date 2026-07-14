# OWASP Agentic Top 10 Mapping

Agent OS combines native ACS policy evaluation with host lifecycle controls.
The mapping below identifies the primary control surface for each risk.

| Risk | Primary controls |
|------|------------------|
| ASI01 Agent Goal Hijack | Input and output policies, prompt-injection detection, audit |
| ASI02 Tool Misuse | Manifest tool catalog, `pre_tool_call`, sandbox controls |
| ASI03 Identity and Privilege Abuse | AgentMesh identity, capability checks, approval |
| ASI04 Agentic Supply Chain | Tool identity, signatures, provenance, package controls |
| ASI05 Unexpected Code Execution | Sandbox providers, code scanning, tool policy |
| ASI06 Memory and Context Poisoning | Context validation, memory integrity, input policy |
| ASI07 Insecure Inter-Agent Communication | AgentMesh trust and encrypted transport |
| ASI08 Cascading Failures | Circuit breakers, SLOs, rate limits, session budgets |
| ASI09 Human-Agent Trust Exploitation | Approval binding, evidence, restricted audit |
| ASI10 Rogue Agents | Identity, runtime mediation, sandbox isolation, kill controls |

## Native policy example

```python
from agt.policies import AdapterRuntimeSession, AgtRuntime

runtime = AgtRuntime("policies/owasp-manifest.yaml")
session = AdapterRuntimeSession(
    runtime,
    agent_id="owasp-agent",
    session_id="owasp-session",
)

evaluation = session.evaluate_pre_tool_call(
    tool_name="execute_code",
    args={"code": "untrusted input"},
)
```

The manifest can bind policies to input, model, tool, and output intervention
points. Tool catalogs, budgets, transforms, evidence, and approval are native
ACS contracts.

## Host controls

Policy evaluation does not replace host security:

- `SandboxConfig` owns network, filesystem, resource, and provider controls.
- AgentMesh owns identity, trust, and transport.
- Agent SRE owns circuit breakers, SLOs, chaos testing, and incident response.
- Agent OS adapters own framework lifecycle ordering and sanitized errors.

## Fail-closed behavior

Unexpected policy, dispatcher, or approval errors deny the operation. Public
exceptions expose stable text while trusted audit code retains the structured
`PolicyEvaluation`.

## Verification

Use `agt test` for policy replay, adapter mediation tests for side-effect
ordering, sandbox provider tests for isolation, and red-team suites for
cross-layer attack scenarios.

This mapping is architectural guidance, not a certification claim. Validate the
controls required by the deployment's own threat model.
