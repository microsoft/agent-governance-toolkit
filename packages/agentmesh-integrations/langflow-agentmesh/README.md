# langflow-agentmesh

Governance components for [Langflow](https://github.com/langflow-ai/langflow) — policy enforcement, trust-based routing, audit logging, and compliance checking for visual AI flows.

> Part of the [AgentMesh](https://github.com/imran-siddique/agent-os) ecosystem.

## What This Does

Adds governance guardrails to Langflow flows as custom components. Each component can be dropped into a flow to enforce policies, route by trust, log decisions, and validate compliance — **without writing code**.

| Component | Purpose | Key Feature |
|-----------|---------|-------------|
| **Governance Gate** | Policy enforcement | Tool allowlist/blocklist, content pattern scanning |
| **Trust Router** | Trust-based routing | Three outputs: trusted / review / blocked |
| **Audit Logger** | Tamper-evident logging | SHA-256 hash chain, JSONL export |
| **Compliance Checker** | Framework validation | EU AI Act, SOC2, HIPAA |

## Install

```bash
pip install langflow-agentmesh
```

With Langflow:

```bash
pip install langflow-agentmesh[langflow]
```

## Quick Start

### Governance Gate

```python
from langflow_agentmesh import GovernanceComponent

gate = GovernanceComponent(
    allowed_tools=["search", "read_file"],
    blocked_patterns=[("rm -rf", "substring"), (r".*password.*=.*", "regex")],
    max_calls=10,
)

result = gate.process(
    action="search",
    parameters={"query": "python tutorials"},
    agent_id="agent-1",
)
print(result.allowed)  # True
```

### Trust Router

```python
from langflow_agentmesh import TrustRouter

router = TrustRouter(trusted_threshold=0.7, review_threshold=0.3)

# Build trust through successful actions
router.record_success("agent-1", dimensions=["reliability", "security"])

# Route based on trust
result = router.route("agent-1", payload={"task": "deploy"})
print(result.decision.value)  # "review" or "trusted"

# Three outputs for Langflow flow branching
trusted_data = router.get_trusted_output(result)
review_data = router.get_review_output(result)
blocked_data = router.get_blocked_output(result)
```

### Audit Logger

```python
from langflow_agentmesh import AuditLogger

logger = AuditLogger()
logger.log("agent-1", "search", "allowed", context={"query": "data"})
logger.log("agent-2", "delete", "blocked", context={"reason": "policy"})

# Verify chain integrity
assert logger.verify_chain()

# Export for compliance
logger.export_jsonl_to_file("audit-trail.jsonl")
```

### Compliance Checker

```python
from langflow_agentmesh import ComplianceChecker, ComplianceFramework

checker = ComplianceChecker(frameworks=[
    ComplianceFramework.EU_AI_ACT,
    ComplianceFramework.SOC2,
    ComplianceFramework.HIPAA,
])

result = checker.check(
    action="classify",
    parameters={"data": "patient records"},
    agent_id="agent-1",
    context={"domain": "employment", "audit_enabled": True},
)

print(result.compliance_status.value)  # "requires_review"
for action in result.required_actions:
    print(f"  → {action}")
```

### YAML Policy

```yaml
# governance-policy.yaml
max_tool_calls_per_request: 10
confidence_threshold: 0.8
allowed_tools:
  - search
  - read_file
blocked_tools:
  - delete
  - drop
blocked_patterns:
  - pattern: "rm -rf"
    type: substring
  - pattern: ".*password.*=.*"
    type: regex
```

```python
from langflow_agentmesh import GovernanceComponent

gate = GovernanceComponent(policy_yaml=open("governance-policy.yaml").read())
```

## Example Langflow Flow

```
┌─────────────┐     ┌──────────────────┐     ┌──────────────┐
│  LLM Agent  │────▶│ Governance Gate  │────▶│ Trust Router  │
└─────────────┘     └──────────────────┘     └──┬───┬───┬───┘
                                                 │   │   │
                          ┌──────────────────────┘   │   └──────────┐
                          ▼                          ▼              ▼
                   ┌─────────────┐         ┌──────────────┐  ┌──────────┐
                   │  Tool Exec  │         │ Human Review │  │  Blocked │
                   └──────┬──────┘         └──────────────┘  └──────────┘
                          │
                          ▼
                   ┌─────────────────┐     ┌────────────────────┐
                   │  Audit Logger   │────▶│ Compliance Checker │
                   └─────────────────┘     └────────────────────┘
```

## Compliance Frameworks

### EU AI Act
- **Article 5**: Blocks unacceptable-risk AI practices (social scoring, subliminal manipulation)
- **Article 13**: Requires transparency notices for high-risk AI systems
- **Article 14**: Requires human oversight for high-risk domains (employment, education, law enforcement)

### SOC2
- **CC6.1**: Requires agent identity for logical access control
- **CC7.2**: Requires audit logging for system monitoring
- **CC8.1**: Requires change approval for sensitive actions (delete, deploy, modify)

### HIPAA
- **§164.502**: Detects PHI (SSN, MRN, DOB, email) and requires encryption
- **§164.502(b)**: Enforces minimum necessary data scope
- **§164.312(b)**: Requires access logging for PHI operations

## License

Apache-2.0
