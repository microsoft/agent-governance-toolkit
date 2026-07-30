# South Korea AI Framework Act Mapping

This document maps Agent Governance Toolkit controls to common technical
obligations under South Korea's AI Framework Act. It is implementation guidance,
not a legal opinion or certification.

## Risk classification

Record deployment risk, domain, jurisdiction, owner, and applicable controls in
manifest metadata and the deployment's governance inventory. The manifest
itself should bind policy to the intervention points that enforce the
classification.

```python
from agt.policies import AgtRuntime

runtime = AgtRuntime("policies/korea-high-impact-manifest.yaml")
```

## Transparency and records

Use versioned manifests, restricted policy audit records, AgentMesh identity,
and deployment logs to preserve who acted, what was evaluated, the verdict, and
the enforced identity. Public errors remain sanitized.

## Safety and resilience

| Need | AGT control |
|------|-------------|
| Input and output safety | ACS intervention-point policies |
| Tool restrictions | Manifest tool catalog and adapter mediation |
| Human oversight | Native approval resolver and identity binding |
| Isolation | Sandbox providers and fail-closed `SandboxConfig` |
| Reliability | Agent SRE SLOs, circuit breakers, chaos, and incidents |
| Multi-agent trust | AgentMesh identity and transport |

## Data governance

Bind data-residency, PII, and disclosure policies to input, tool, and output
intervention points. Configure filesystem, network, and resource boundaries in
the sandbox host configuration. Do not place host resource settings in policy
objects.

## Human oversight

Approval success, denial, timeout, suspension, and action-identity mismatch
must be tested. A caller-provided boolean is not trusted approval.

## Validation

- Lint manifests with `agt lint-policy`.
- Replay deterministic fixtures with `agt test`.
- Test framework side-effect ordering.
- Test sandbox isolation and network defaults.
- Review audit retention, incident reporting, user notices, and human oversight
  procedures with Korean legal and compliance owners.

Compliance depends on the configured controls and operating environment. The
toolkit does not by itself establish conformity with the Act.
