# Guide: Progressive Governance — Start Simple, Add Layers

> **Applies to:** All AGT packages · **Time:** 15 minutes · **Prerequisites:** None

---

## What You'll Learn

- The 5-level progressive complexity model for agent governance
- When to add each governance layer based on your team's risk profile

---

> **You don't need the full stack to start.** Most teams run Level 1–2 in
> production and never need Level 5. Pick the level that matches your risk.

---

## Level 1: Govern in 3 Lines

**When you need this:** You have one agent, you want to block dangerous actions,
and you need something running today.

```python
from agent_os.policies import PolicyEvaluator

evaluator = PolicyEvaluator()
evaluator.add_rules([
    {"action": "web_search", "effect": "allow"},
    {"action": "read_file", "effect": "allow"},
    {"action": "*", "effect": "deny"},
])

decision = evaluator.evaluate({"action": "delete_file"})
assert not decision.allowed  # blocked by default-deny
```

> 💡 **This is enough for 80% of teams starting out.** You get deterministic
> policy enforcement with zero infrastructure.

---

## Level 2: Add YAML Policies

**When you need this:** Your rules are growing, you want version-controlled
policies, or you need content filtering (PII, prompt injection).

```yaml
# policies/production.yaml
version: "1.0"
rules:
  - action: "web_search"
    effect: allow
  - action: "read_file"
    effect: allow
    conditions:
      path_pattern: "/data/public/**"
  - action: "*"
    effect: deny
content_filters:
  blocked_patterns:
    - '\b\d{3}-\d{2}-\d{4}\b'   # SSN
    - '\b\d{16}\b'               # Credit card numbers
```

```python
from agent_os.policies import PolicyEvaluator

evaluator = PolicyEvaluator.from_yaml("policies/production.yaml")
decision = evaluator.evaluate({"action": "read_file", "path": "/data/public/report.csv"})
```

> 💡 **Generate policies instantly** with `agent-os policy generate --template strict`.
> See [Policy Generator CLI](../../agent-governance-python/agent-os/src/agent_os/cli/cmd_policy_gen.py).

---

## Level 3: Add Agent Identity

**When you need this:** You have multiple agents, you need to know which agent
did what, or you need trust scoring between agents.

```python
from agent_os.mesh import AgentIdentity, TrustScorer

identity = AgentIdentity.create(
    name="research-agent",
    capabilities=["web_search", "read_file"],
)

scorer = TrustScorer()
score = scorer.evaluate(identity, action="web_search")
# score.trust_level → 0.95 (high — action matches declared capabilities)
```

> 💡 **Add this when you move to multi-agent systems.** Single-agent setups
> rarely need identity management.

---

## Level 4: Add Lifecycle Management

**When you need this:** Agents are created dynamically, credentials need
rotation, or you need to detect orphaned/shadow agents.

```python
from agent_os.lifecycle import AgentProvisioner, OrphanDetector

provisioner = AgentProvisioner()
agent = provisioner.create(
    name="data-analyst",
    ttl_hours=24,
    capabilities=["read_file", "web_search"],
)

detector = OrphanDetector()
orphans = detector.scan()  # finds agents with no active owner
for orphan in orphans:
    provisioner.decommission(orphan.id)
```

> 💡 **Add this when you're running agents in production at scale.** Credential
> rotation and orphan detection prevent security drift.

---

## Level 5: Full Stack

**When you need this:** Regulated industries, enterprise compliance requirements,
or you need a complete governance dashboard with SRE capabilities.

```python
from agent_os import GovernanceStack

stack = GovernanceStack(
    policies="policies/",
    identity=True,
    lifecycle=True,
    execution_rings=True,      # sandboxed execution tiers
    sre=True,                  # circuit breakers, rate limiting
    compliance=True,           # audit trail, NIST/OWASP mapping
    dashboard=True,            # real-time governance dashboard
)

# Everything from Levels 1–4, plus:
# - Execution rings (sandbox → staging → production)
# - Circuit breakers and rate limiting
# - Compliance verification and audit export
# - Real-time governance dashboard
stack.start()
```

> 💡 **Most teams never need Level 5.** It exists for regulated industries
> (finance, healthcare, government) with strict compliance requirements.

---

## Summary

| Level | What You Get | Lines of Code | When You Need It |
|-------|-------------|---------------|-----------------|
| 1 | Policy enforcement | ~5 | Day one — block dangerous actions |
| 2 | YAML policies + content filters | ~3 + YAML | Rules are growing, need version control |
| 3 | Agent identity + trust scoring | ~8 | Multi-agent systems |
| 4 | Lifecycle + orphan detection | ~10 | Production scale, credential rotation |
| 5 | Full stack (SRE, compliance, dashboard) | ~12 | Regulated industries |

## Next Steps

- [60-Second Quickstart](../../examples/quickstart/govern_in_60_seconds.py)
- [Policy Engine Tutorial](01-policy-engine.md)
- [Trust & Identity Tutorial](02-trust-and-identity.md)
- [Agent Discovery Tutorial](29-agent-discovery.md)
- [Agent Lifecycle Tutorial](30-agent-lifecycle.md)
