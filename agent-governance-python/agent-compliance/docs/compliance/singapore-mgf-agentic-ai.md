# Singapore Model AI Governance Framework Mapping

This document maps Agent Governance Toolkit controls to the four pillars of
Singapore's Model AI Governance Framework for Agentic AI. It is implementation
guidance, not a legal opinion or certification.

## Bound risks upfront

| Need | AGT control |
|------|-------------|
| Define allowed behavior | Native ACS manifest and policy bundles |
| Restrict tools | Manifest tool catalog and `pre_tool_call` |
| Bound autonomous work | `AdapterRuntimeSession` counters and manifest limits |
| Isolate execution | Sandbox providers and `SandboxConfig` |
| Classify deployment risk | Agent Control Plane risk classification |

## Meaningful human accountability

Native ACS approval binds the approved action identity to the action that the
host enforces. Approval timeout, denial, suspension, and identity mismatch fail
closed.

```python
from agt.policies import AgtRuntime

runtime = AgtRuntime(
    "policies/singapore-mgf-manifest.yaml",
    approval_resolver=approval_resolver,
)
```

Host kill switches, pause and resume, and incident workflows remain separate
operational controls.

## Technical controls

| Need | AGT control |
|------|-------------|
| Identity and permissions | AgentMesh identity, trust, and capabilities |
| Input and output safeguards | ACS input and output intervention points |
| Tool mediation | Agent OS framework adapters |
| Resource and network limits | `SandboxConfig` |
| Reliability | Agent SRE SLOs, circuit breakers, and incident response |
| Evidence | `PolicyEvaluation.audit_record()` and tamper-evident audit sinks |

## End-user transparency

Applications can disclose agent identity, sponsor, capabilities, approval
status, and high-level denial reasons without exposing policy internals or user
data. Public policy exceptions use sanitized messages. Trusted audit systems
retain the structured evaluation.

## Validation

- Lint manifests with `agt lint-policy`.
- Replay policy fixtures with `agt test`.
- Exercise approval and fail-closed paths.
- Run adapter mediation and sandbox provider tests.
- Validate audit retention, access control, and incident procedures for the
  deployment.

Compliance depends on the configured manifest, host wiring, operational
processes, and deployment environment. The toolkit alone does not establish
conformity with the framework.
