# Policy Examples

Sample YAML governance policy files for AgentMesh.

Each file in this directory is a self-contained policy configuration that demonstrates how to express a particular class of security or compliance control using the policy engine. They are intended as starting points — review and adapt them for your environment before deploying to production.

## Policies

| File | Description |
|------|-------------|
| [`adk-governance.yaml`](adk-governance.yaml) | Tool restrictions and delegation controls for Google ADK agents. |
| [`atr-community-rules.yaml`](atr-community-rules.yaml) | Community governance rules for agent trust and review workflows. |
| [`cli-security-rules.yaml`](cli-security-rules.yaml) | Blocks dangerous shell and CLI patterns. |
| [`conversation-guardian.yaml`](conversation-guardian.yaml) | Content safety rules for conversational agents. |
| [`embodied-action-governance.yaml`](embodied-action-governance.yaml) | Decision-layer controls for embodied or physical action requests. |
| [`lotl_prevention_policy.yaml`](lotl_prevention_policy.yaml) | Controls for limiting living-off-the-land style tool abuse. |
| [`mcp-security.yaml`](mcp-security.yaml) | Security controls for MCP tool usage. |
| [`pii-detection.yaml`](pii-detection.yaml) | Detects and blocks personally identifiable information. |
| [`prompt-injection-safety.yaml`](prompt-injection-safety.yaml) | Guards against prompt injection attacks. |
| [`sandbox-safety.yaml`](sandbox-safety.yaml) | Restrictions for sandboxed agent execution. |
| [`semantic-policy.yaml`](semantic-policy.yaml) | Semantic similarity-based policy enforcement. |
| [`sql-readonly.yaml`](sql-readonly.yaml) | Restricts agents to read-only SQL operations. |
| [`sql-safety.yaml`](sql-safety.yaml) | Blocks destructive SQL patterns. |
| [`sql-strict.yaml`](sql-strict.yaml) | Strict SQL allowlist for production databases. |

## Using this directory

1. **Browse** the `.yaml` files to find a scenario close to what you need. Each file opens with a comment block describing what it covers and any caveats.
2. **Copy** the file into your own project (or reference it by path) and edit the rules, thresholds, and matchers to fit your requirements.
3. **Load** the policy into an agent workflow via the governance runtime. The [Quickstart](../quickstart/) shows runnable end-to-end examples that consume policies from this directory.

## Policy format

All files here follow the schema defined in [`policy-engine/spec`](../../policy-engine/spec/). Refer to that spec for the full list of supported fields, matchers, and enforcement actions.

## Related

- [Quickstart](../quickstart/) — runnable examples that load policies from this directory
- [Policy Engine tutorial](../../docs/tutorials/01-policy-engine.md) — walkthrough of how policies are evaluated
