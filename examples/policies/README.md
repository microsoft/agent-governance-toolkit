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

## How to Use
 
These policy files can be applied to agent workflows to enforce governance rules.
 
```bash
scripts/check-policy.sh --action "web_search" --tokens 1500 --policy examples/policies/sql-safety.yaml
```

## Related
 
- [Quickstart](../quickstart/) - Runnable examples that use these policies