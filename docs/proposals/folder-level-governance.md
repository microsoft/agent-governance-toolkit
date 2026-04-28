# Proposal: Folder-Level Governance Policy Scoping

> **Status:** Draft
> **Author:** Imran Siddique
> **Issue:** [#1348](https://github.com/microsoft/agent-governance-toolkit/issues/1348)
> **Created:** 2026-04-23

## Summary

Add path-scoped policy file discovery with inheritance to AGT's `PolicyEvaluator`, enabling different governance rules for different directories within a monorepo. Modeled after EditorConfig/ESLint cascade patterns and informed by Azure Policy/AWS SCP inheritance semantics.

## Motivation

AGT currently loads policies from a single flat directory. In monorepos and large codebases, different projects need different governance rules:

- `services/billing/` needs strict PII rules and financial tool restrictions
- `services/docs/` needs permissive web search but no code execution
- `internal-tools/` inherits the org baseline with no overrides

Internal teams (Azure Core CTO org) and enterprise customers have requested this capability.

## Prior Art Analysis

| System | Discovery | Merge Strategy | Override | Stop Inheritance |
|--------|-----------|---------------|----------|-----------------|
| **EditorConfig** | Walk up from file to root | Nearest matching property wins | Child overrides parent per-property | `root = true` |
| **ESLint** | Walk up, load configs | Parent → child, child overrides same keys | Per-rule override | `root: true` |
| **.gitignore** | Walk down from root | Later/deeper wins | Deeper file beats parent | None (ignored dirs block descent) |
| **Azure Policy** | Management group → subscription → resource group | All evaluated, most restrictive wins | Child cannot loosen parent deny | `notScopes`, exemptions |
| **AWS SCPs** | Org root → OU → account | Intersection of permissions | Child cannot expand parent | Detach/relocate |
| **Kubernetes Gatekeeper** | Namespace, labels, selectors | All matching constraints evaluated | Any deny blocks | `excludedNamespaces` |

### Design Choice Rationale

AGT is a **security governance** system, so we adopt the **security-first** patterns from Azure Policy and Kubernetes:

- **Deny wins over allow** — a parent deny cannot be overridden by a child allow (matches Azure Policy)
- **Additive rules** — child policies add rules on top of parent, they don't replace the parent rule set
- **Explicit override by name** — a child can override a parent rule *only* by declaring the same rule name with `override: true`
- **Stop inheritance** — `inherit: false` in a child policy prevents loading any parent policies (like ESLint `root: true`)

## Specification

### File Discovery

The policy file name is `governance.yaml` (or `.yml`). Discovery walks **up** from the action's path to the repository root:

```
repo/
  governance.yaml              ← Level 0 (root baseline)
  services/
    governance.yaml            ← Level 1
    billing/
      governance.yaml          ← Level 2 (most specific)
      agent.py                 ← Action occurs here
```

**Algorithm:**

```python
def discover_policies(action_path: Path, root: Path) -> list[Path]:
    """Walk up from action_path to root, collecting governance.yaml files.
    
    Returns policies in root-first order (root at index 0, most specific last).
    Stops early if a policy declares 'inherit: false'.
    """
    policies = []
    current = action_path.parent if action_path.is_file() else action_path
    
    while True:
        for name in ("governance.yaml", "governance.yml"):
            candidate = current / name
            if candidate.exists():
                policies.append(candidate)
                break
        
        if current == root or current == current.parent:
            break
        current = current.parent
    
    # Reverse: root first, most specific last
    policies.reverse()
    
    # Check for 'inherit: false' — stop loading at that boundary
    final = []
    for p in reversed(policies):  # Walk from most specific to root
        final.insert(0, p)
        doc = load_policy_header(p)
        if doc.get("inherit") is False:
            break  # Don't include anything above this level
    
    return final
```

### Schema Extension

Add two optional fields to `PolicyDocument`:

```yaml
# governance.yaml
name: billing-service-policy
version: "1.0"
inherit: true          # NEW: default true. Set to false to stop parent loading.
scope: "services/billing/**"  # NEW: optional glob — only applies to matching paths

rules:
  - name: block-pii-tools
    condition:
      field: tool_name
      operator: in
      value: [export_pii, bulk_download]
    action: deny
    message: "PII export tools blocked in billing service"
    priority: 200
    override: false     # NEW: default false. Set to true to override a parent rule with same name.
```

**New fields:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `inherit` | `bool` | `true` | If `false`, parent policies are not loaded (like ESLint `root: true`) |
| `scope` | `str \| null` | `null` | Glob pattern — policy only applies when action path matches |
| `PolicyRule.override` | `bool` | `false` | If `true` and a parent rule has the same `name`, replaces the parent rule |

### Merge Algorithm

Given policies `[root, level1, level2]` (root-first order):

```python
def merge_policies(policy_chain: list[PolicyDocument]) -> list[PolicyRule]:
    """Merge a chain of policies into a flat, priority-sorted rule list.
    
    Rules:
    1. All rules from all levels are collected
    2. If a child rule has override=true and shares a name with a parent rule,
       the parent rule is removed
    3. Deny rules CANNOT be overridden (security invariant)
    4. Rules are sorted by priority descending (highest first)
    5. First matching rule wins (existing AGT behavior)
    """
    # Collect all rules with their source level
    rules_by_name: dict[str, tuple[PolicyRule, int]] = {}  # name → (rule, level)
    all_rules: list[PolicyRule] = []
    
    for level, doc in enumerate(policy_chain):
        for rule in doc.rules:
            existing = rules_by_name.get(rule.name)
            
            if existing and rule.override:
                parent_rule, parent_level = existing
                # Security invariant: deny cannot be overridden
                if parent_rule.action == PolicyAction.DENY:
                    # Keep parent deny, also add child rule (both evaluated)
                    all_rules.append(rule)
                else:
                    # Replace parent rule with child override
                    all_rules = [r for r in all_rules if r.name != rule.name]
                    all_rules.append(rule)
                    rules_by_name[rule.name] = (rule, level)
            else:
                all_rules.append(rule)
                if rule.name not in rules_by_name:
                    rules_by_name[rule.name] = (rule, level)
    
    # Sort by priority descending
    all_rules.sort(key=lambda r: r.priority, reverse=True)
    return all_rules
```

### Security Invariants

1. **Parent deny is immutable** — A child policy cannot override a parent `deny` rule. This matches Azure Policy semantics where a management-group-level deny cannot be loosened at the subscription level.

2. **No scope escalation** — A child policy cannot widen its scope beyond its directory. `scope: "../../**"` is rejected at load time.

3. **Audit trail includes chain** — Every `PolicyDecision` records the full policy chain that was evaluated, not just the matching rule. This enables compliance teams to understand why a decision was made and which levels contributed.

4. **Fast path for flat repos** — If no nested `governance.yaml` files exist (only root), the evaluator uses the existing flat code path with zero overhead.

### Integration with PolicyEvaluator

```python
class PolicyEvaluator:
    def __init__(self, policies=None, root_dir=None):
        self.policies = policies or []
        self.root_dir = Path(root_dir) if root_dir else None
        self._backends = []
    
    def evaluate(self, context: dict[str, Any]) -> PolicyDecision:
        """Evaluate policies. If root_dir is set and context contains 'path',
        use folder-scoped policy discovery. Otherwise, use flat evaluation."""
        
        if self.root_dir and "path" in context:
            action_path = Path(context["path"])
            chain = discover_policies(action_path, self.root_dir)
            docs = [PolicyDocument.from_yaml(p) for p in chain]
            merged_rules = merge_policies(docs)
            return self._evaluate_rules(merged_rules, context)
        
        # Existing flat evaluation (no breaking change)
        return self._evaluate_flat(context)
```

**Key design decision:** Path-scoped evaluation is **opt-in** via `root_dir`. Existing users who don't set `root_dir` get exactly the current behavior with no performance impact.

### Example: Monorepo Setup

```
acme-corp/
│
├── governance.yaml                    # Org baseline
│   name: acme-baseline
│   rules:
│     - name: block-shell-exec
│       condition: { field: tool_name, operator: eq, value: shell_exec }
│       action: deny
│       priority: 1000
│     - name: require-audit
│       condition: { field: action_type, operator: eq, value: tool_call }
│       action: audit
│       priority: 50
│
├── services/
│   ├── billing/
│   │   └── governance.yaml            # Billing overrides
│   │       name: billing-policy
│   │       rules:
│   │         - name: block-pii-export
│   │           condition: { field: tool_name, operator: in, value: [export_pii, bulk_download] }
│   │           action: deny
│   │           priority: 900
│   │         - name: require-audit      # Override parent audit → deny
│   │           condition: { field: action_type, operator: eq, value: tool_call }
│   │           action: deny
│   │           override: true
│   │           priority: 50
│   │           message: "All tool calls require explicit approval in billing"
│   │
│   ├── docs/
│   │   └── governance.yaml            # Docs: permissive
│   │       name: docs-policy
│   │       rules:
│   │         - name: allow-web-search
│   │           condition: { field: tool_name, operator: eq, value: web_search }
│   │           action: allow
│   │           priority: 100
│   │
│   └── sandbox/
│       └── governance.yaml            # Sandbox: isolated
│           name: sandbox-policy
│           inherit: false              # Don't inherit org baseline
│           rules:
│             - name: allow-all
│               condition: { field: action_type, operator: eq, value: tool_call }
│               action: allow
│               priority: 1
```

**Evaluation examples:**

| Action Path | Effective Policies | Result for `shell_exec` |
|---|---|---|
| `services/billing/agent.py` | baseline + billing | **DENY** (parent block-shell-exec, priority 1000) |
| `services/docs/agent.py` | baseline + docs | **DENY** (parent block-shell-exec, priority 1000) |
| `services/sandbox/agent.py` | sandbox only | **ALLOW** (inherit: false, only sandbox rules apply) |
| `lib/utils.py` | baseline only | **DENY** (baseline block-shell-exec) |

### Performance Considerations

1. **Caching:** Policy files are cached by path with mtime-based invalidation. The discovery walk is cached per-directory.
2. **Fast path:** If `root_dir` is not set, zero overhead — existing flat evaluation used.
3. **Lazy loading:** Policy files are loaded on first evaluation for a given path, not at startup.
4. **Merged rule cache:** After merging a policy chain, the resulting rule list is cached until any file in the chain changes.

### Migration Path

- **No breaking changes** — existing `PolicyEvaluator()` without `root_dir` works identically
- **Opt-in:** Set `root_dir` to enable folder-scoped discovery
- **Gradual adoption:** Start with a root `governance.yaml`, add folder-level policies as needed

## Alternatives Considered

### A. OPA-style package namespacing
Each folder defines an OPA package, and policies are scoped by package name. **Rejected:** Requires OPA knowledge, doesn't work with AGT's native YAML evaluator, and adds complexity for simple cases.

### B. Single file with path globs
One `governance.yaml` with rules that include `path` conditions. **Rejected:** Doesn't scale for large monorepos — single file becomes unwieldy and hard to review. Also doesn't allow teams to own their policies independently.

### C. Config inheritance via `extends` field
Child policies explicitly name their parent (like TypeScript `tsconfig.json`). **Rejected:** Filesystem-based discovery is simpler, more intuitive, and doesn't require knowing the parent's path or name.

## Implementation Plan

1. **Schema extension** — Add `inherit`, `scope`, `override` fields to `PolicyDocument` and `PolicyRule`
2. **Discovery module** — `agent_os.policies.discovery` with `discover_policies()` function
3. **Merge module** — `agent_os.policies.merge` with `merge_policies()` function
4. **Evaluator integration** — Add `root_dir` parameter to `PolicyEvaluator`
5. **Tests** — Unit tests for discovery, merge, security invariants, fast path, caching
6. **Tutorial** — New tutorial: "Folder-Level Governance for Monorepos"
7. **CLI** — `agent-governance validate --root .` validates all governance.yaml files in the tree

## References

- [ESLint Configuration Cascade](https://eslint.org/docs/latest/use/configure/configuration-files#cascading-and-hierarchy)
- [EditorConfig Specification](https://editorconfig.org/)
- [Azure Policy Inheritance](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/assignment-structure)
- [AWS SCP Evaluation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
- [AGT PolicyEvaluator source](../agent-governance-python/agent-os/src/agent_os/policies/evaluator.py)
