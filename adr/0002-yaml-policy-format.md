# ADR-0002: YAML-Based Policy Engine Format

## Status

Accepted

## Context

AGT's policy engine needs a configuration format for defining governance rules. The format must be:

- Human-readable and editable without tooling
- Diffable in version control (Git-friendly)
- Expressive enough for conditional rules with priorities
- Familiar to platform engineers (Kubernetes-adjacent)

Options considered:

1. **JSON**: Machine-friendly, but verbose and hard to read for complex policies. No comments.
2. **YAML**: Human-readable, supports comments, familiar to Kubernetes users. Risk of indentation errors.
3. **Rego (OPA)**: Purpose-built for policy-as-code, powerful, but steep learning curve. Would add OPA as a runtime dependency.
4. **Cedar (AWS)**: Designed for authorization, but vendor-specific and limited ecosystem.

## Decision

Use YAML with a Kubernetes-style schema (`apiVersion`, `kind`, `metadata`, `spec` or `rules`). Policy files follow the convention:

```yaml
apiVersion: governance.toolkit/v1
name: policy-name
default_action: deny
rules:
  - name: rule-name
    condition: "expression"
    action: allow
    priority: 10
```

Conditions use a safe expression evaluator (not `eval`). The policy engine merges multiple policy files with priority-based conflict resolution.

## Consequences

- **Easier**: Low barrier to entry, GitOps-compatible, no new DSL to learn, policy files are self-documenting
- **Harder**: Complex boolean logic is less elegant than Rego. YAML indentation errors can cause subtle bugs (mitigated by schema validation in CI).

## References

- `agent-governance-python/agent-os/src/agent_os/policies/`
- Issue #2276: Priority bypass bug in merge_policies (fixed)
