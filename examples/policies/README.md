# Policies Example

Sample YAML governance policy files for AgentMesh. Each file provides an example configuration covering a specific security or compliance scenario. 

## Policies
 
| File | Description |
|------|-------------|
| `adk-governance.yaml` | Tool restrictions and delegation controls for Google ADK agents |
| `cli-security-rules.yaml` | Blocks dangerous shell and CLI patterns |
| `conversation-guardian.yaml` | Content safety rules for conversational agents |
| `mcp-security.yaml` | Security controls for MCP tool usage |
| `pii-detection.yaml` | Detects and blocks personally identifiable information |
| `prompt-injection-safety.yaml` | Guards against prompt injection attacks |
| `sandbox-safety.yaml` | Restrictions for sandboxed agent execution |
| `semantic-policy.yaml` | Semantic similarity-based policy enforcement |
| `sql-readonly.yaml` | Restricts agents to read-only SQL operations |
| `sql-safety.yaml` | Blocks destructive SQL patterns |
| `sql-strict.yaml` | Strict SQL allowlist for production databases |

## Policy Packs

Multi-file policy libraries for specific regulatory or enterprise scenarios. Each pack has its own README with file listings, usage, and jurisdiction details.

| Directory | Policies | Description |
|-----------|----------|-------------|
| [`african-regulatory/`](african-regulatory/) | 15 | African regulatory and universal agent safety controls for Nigeria, Kenya, South Africa, Uganda, Tanzania, and Ethiopia. Includes OPA Rego reference implementations and a jurisdiction router. |
| [`production/`](production/) | 5 | Ready-to-use enterprise policies (`minimal`, `enterprise`, `healthcare`, `financial`, `strict`) with graduated risk levels. |
| [`uk-regulatory/`](uk-regulatory/) | 3 | UK regulatory controls for UK GDPR/DPA 2018, ICO automated decision-making (Arts. 22A–22D), and FCA principles-based financial conduct. Includes OPA Rego reference implementations. |

## How to Use
 
These policy files can be applied to agent workflows to enforce governance rules.
 
```bash
scripts/check-policy.sh --action "web_search" --tokens 1500 --policy examples/policies/sql-safety.yaml
```

## Related
 
- [Quickstart](../quickstart/) - Runnable examples that use these policies