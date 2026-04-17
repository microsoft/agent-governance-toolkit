# Workshop: Introduction to AI Agent Governance (2-Hour Session)

> A complete workshop kit for teaching AI agent governance concepts using the Agent Governance Toolkit.

---

## Facilitator Notes

**Target audience:** Software engineers and technical leads building or deploying autonomous AI agents. Participants should have basic Python familiarity.

**Setup requirements:**
- Python 3.11+
- `pip install agent-governance-toolkit[full]`
- Git (for cloning example repository)
- Internet access (for package installation)

**Timing guide:** The agenda below is calibrated for a 2-hour session. For a 90-minute version, reduce Lab 3 to 10 minutes and skip the break.

---

## Participant Prerequisites Checklist

Before the workshop, participants should:

- [ ] Install Python 3.11 or later
- [ ] Run `pip install agent-governance-toolkit[full]` successfully
- [ ] Clone the workshop repository: `git clone https://github.com/microsoft/agent-governance-toolkit`
- [ ] Verify installation: `python -c "from agent_os import PolicyEngine; print('OK')"`
- [ ] Have a code editor (VS Code recommended)
- [ ] Basic familiarity with YAML syntax

---

## Agenda

### Part 1: Why Governance Matters (20 minutes)

**Slide 1: The Autonomy Problem**

When we give AI agents the ability to:
- Execute code
- Call external APIs
- Read and write files
- Spawn other agents

...we've moved beyond "text generation" into "autonomous action." The question shifts from "what did the model say?" to "what did the agent *do*?"

**Slide 2: Real-World Incidents**

| Year | Incident | Root Cause |
|------|----------|------------|
| 2024 | AI trading agent executes unwanted trades | No action-level policy enforcement |
| 2024 | Customer service bot offers unauthorized discounts | Prompt-only guardrails bypassed |
| 2025 | Multi-agent system spawns runaway subprocesses | No resource limits or termination control |
| 2025 | Agent exfiltrates data via tool call | No capability scoping |

**Slide 3: Why Prompt Guardrails Aren't Enough**

System prompts are requests, not constraints:
- Prompt injection can override instructions
- Model confusion can lead to unexpected behavior
- No audit trail for what went wrong
- No deterministic enforcement guarantee

**Slide 4: The Governance Stack**

```
Layer 4: Regulatory Compliance (ISO 42001, EU AI Act)
Layer 3: Agent Action Governance (policy-as-code)  ← This workshop
Layer 2: Platform Controls (rate limits, API gating)
Layer 1: Prompt Guardrails (system prompts, output validation)
```

This workshop focuses on Layer 3 — deterministic, pre-execution policy enforcement.

**Slide 5: Agent Governance Toolkit Overview**

Four core subsystems:

| Component | Purpose |
|-----------|---------|
| Agent OS | Policy engine, capability model, audit logging |
| AgentMesh | Zero-trust identity, trust scoring, protocol bridging |
| Agent Runtime | Execution sandboxing, resource limits, termination control |
| Agent SRE | SLO monitoring, chaos testing, circuit breakers |

Key properties:
- Policy evaluation latency: < 0.1ms
- 12+ framework integrations (LangChain, CrewAI, AutoGen, OpenAI Agents SDK, etc.)
- OWASP Agentic Top 10: 10/10 categories covered

---

### Lab 1: Your First Policy (20 minutes)

**Objective:** Create and test a basic allow/deny policy.

**Step 1:** Create a policy file:

```yaml
# lab1-policy.yaml
apiVersion: v1
kind: Policy
metadata:
  name: my-first-policy
spec:
  defaultAction: DENY
  rules:
    - action: "file.read"
      effect: ALLOW

    - action: "web.search"
      effect: ALLOW
      conditions:
        - field: "params.query"
          operator: "length_less_than"
          value: 200
```

**Step 2:** Write a test script:

```python
# lab1_test.py
from agent_os import PolicyEngine

engine = PolicyEngine.from_file("lab1-policy.yaml")

# Test 1: Reading files is allowed
result = engine.evaluate(action="file.read")
print(f"file.read: {'ALLOWED' if result.allowed else 'DENIED'}")
assert result.allowed

# Test 2: Writing files is denied (default-deny)
result = engine.evaluate(action="file.write")
print(f"file.write: {'ALLOWED' if result.allowed else 'DENIED'}")
assert not result.allowed

# Test 3: Short search queries are allowed
result = engine.evaluate(action="web.search", params={"query": "weather today"})
print(f"web.search (short): {'ALLOWED' if result.allowed else 'DENIED'}")
assert result.allowed

# Test 4: Long search queries are denied
result = engine.evaluate(action="web.search", params={"query": "x" * 201})
print(f"web.search (long): {'ALLOWED' if result.allowed else 'DENIED'}")
assert not result.allowed

print("\nAll tests passed!")
```

**Step 3:** Run and discuss:

```bash
python lab1_test.py
```

**Discussion points:**
- Why default-deny? (Principle of least privilege)
- What happens if you forget to add a rule for a new action?
- How does this compare to "just use a good system prompt"?

**Facilitator tip:** Ask participants to add a new rule allowing `llm.generate` with a token limit. This reinforces the pattern.

---

### Part 2: Trust and Identity Concepts (15 minutes)

**Slide 6: Why Agent Identity Matters**

In a multi-agent system, how do you know:
- Which agent made a request?
- Whether an agent is who it claims to be?
- Whether an agent is trusted enough for a specific action?

Without cryptographic identity, you're relying on self-reported metadata — an agent can simply claim "I'm the admin."

**Slide 7: Zero-Trust Identity Model**

AgentMesh provides:
- **Ed25519 cryptographic keys** — each agent has a verifiable identity
- **DID (Decentralized Identifier)** — standard-based agent identification
- **Trust scores (0-1000)** — behavioral reputation system

| Score Range | Tier | Privileges |
|-------------|------|------------|
| 900-1000 | Verified Partner | Full access |
| 700-899 | Trusted | Elevated privileges |
| 500-699 | Standard | Default |
| 300-499 | Probationary | Limited |
| 0-299 | Untrusted | Read-only or blocked |

**Slide 8: Trust Score Lifecycle**

```
New Agent (500) → Successful tasks (+score) → Trusted (700+)
                 ↘ Policy violations (-score) → Probationary (300-499)
                                                  ↘ Continued violations → Untrusted (0-299)
```

Trust scores are **earned, not assigned.** A new agent starts at Standard (500) and builds reputation through compliant behavior.

---

### Lab 2: Multi-Agent Trust (20 minutes)

**Objective:** Configure role-based policies with trust-aware enforcement.

**Step 1:** Create a multi-agent policy:

```yaml
# lab2-policy.yaml
apiVersion: v1
kind: Policy
metadata:
  name: multi-agent-trust
spec:
  defaultAction: DENY
  roles:
    researcher:
      allowed_actions: ["web.search", "web.fetch", "file.read", "llm.generate"]
    operator:
      allowed_actions: ["file.read", "file.write", "system.restart"]
    admin:
      allowed_actions: ["*"]

  rules:
    - action: "*"
      effect: ALLOW
      conditions:
        - field: "agent.role"
          operator: "in_role_actions"
          value_field: "action"

    # Sensitive actions require high trust
    - action: "system.restart"
      effect: ALLOW
      conditions:
        - field: "agent.trust_score"
          operator: "greater_or_equal"
          value: 800

    - action: "file.write"
      effect: ALLOW
      conditions:
        - field: "agent.trust_score"
          operator: "greater_or_equal"
          value: 500
```

**Step 2:** Test with different agent identities:

```python
# lab2_test.py
from agent_os import PolicyEngine

engine = PolicyEngine.from_file("lab2-policy.yaml")

# Researcher can search
result = engine.evaluate(
    action="web.search",
    agent={"role": "researcher", "trust_score": 500}
)
print(f"Researcher web.search: {'ALLOWED' if result.allowed else 'DENIED'}")

# Operator can write (with sufficient trust)
result = engine.evaluate(
    action="file.write",
    agent={"role": "operator", "trust_score": 600}
)
print(f"Operator file.write (trust 600): {'ALLOWED' if result.allowed else 'DENIED'}")

# Operator CANNOT restart with low trust
result = engine.evaluate(
    action="system.restart",
    agent={"role": "operator", "trust_score": 600}
)
print(f"Operator system.restart (trust 600): {'ALLOWED' if result.allowed else 'DENIED'}")

# Operator CAN restart with high trust
result = engine.evaluate(
    action="system.restart",
    agent={"role": "operator", "trust_score": 850}
)
print(f"Operator system.restart (trust 850): {'ALLOWED' if result.allowed else 'DENIED'}")

print("\nLab 2 complete!")
```

**Discussion points:**
- How does trust-based enforcement differ from static role-based access control?
- What happens when an agent's trust score drops mid-operation?
- How would you implement trust recovery (probation period)?

---

### Break (10 minutes)

---

### Part 3: Production Patterns (15 minutes)

**Slide 9: Production Deployment Checklist**

| Concern | Pattern | Implementation |
|---------|---------|---------------|
| Runaway agents | Rate limiting | Per-action, per-agent, per-time-window |
| High-stakes decisions | Approval workflows | Human-in-the-loop with timeout |
| Environment differences | Conditional policies | Dev (relaxed) → Staging (moderate) → Prod (strict) |
| Policy regressions | Automated testing | Unit tests for every policy rule |
| Policy evolution | Versioning | Semantic versioning with changelogs |

**Slide 10: The Testing Discipline**

Policies are code. Treat them like code:

```python
# Every policy change should have corresponding tests
class TestPaymentPolicy:
    def test_small_payment_allowed(self):
        result = engine.evaluate(action="payment.charge", params={"amount": 50})
        assert result.allowed is True

    def test_large_payment_requires_approval(self):
        result = engine.evaluate(action="payment.charge", params={"amount": 5000})
        assert result.decision == "REQUIRE_APPROVAL"
```

**Slide 11: Defense-in-Depth**

Agent governance is one layer. For production:

```
Application Layer:  Agent Governance Toolkit (policy-as-code)
     +
OS Layer:           Container isolation (Docker, gVisor, Kata)
     +
Network Layer:      Network policies, service mesh
     +
Compliance Layer:   ISO 42001, EU AI Act, NIST AI RMF
```

---

### Lab 3: Full Governance Stack (20 minutes)

**Objective:** Combine all concepts into a production-grade governance configuration.

**Step 1:** Create a combined policy:

```yaml
# lab3-production.yaml
apiVersion: v1
kind: PolicySet
metadata:
  name: production-stack
  version: "1.0.0"
spec:
  defaultAction: DENY

  roles:
    research_agent:
      allowed_actions: ["web.search", "web.fetch", "file.read", "llm.generate"]
    billing_agent:
      allowed_actions: ["payment.query", "payment.charge", "payment.refund", "llm.generate"]
    admin_agent:
      allowed_actions: ["*"]

  rules:
    # Role-based access
    - action: "*"
      effect: ALLOW
      conditions:
        - field: "agent.role"
          operator: "in_role_actions"
          value_field: "action"

    # Rate limiting
    - action: "llm.generate"
      effect: ALLOW
      conditions:
        - field: "rate"
          operator: "requests_per_minute"
          value: 60

    # Approval workflows
    - action: "payment.charge"
      effect: REQUIRE_APPROVAL
      conditions:
        - field: "params.amount"
          operator: "greater_or_equal"
          value: 1000
      approval:
        timeout_minutes: 30
        min_approvers: 1

    # Trust requirement for sensitive actions
    - action: "payment.refund"
      effect: ALLOW
      conditions:
        - field: "agent.trust_score"
          operator: "greater_or_equal"
          value: 700

    # Environment constraints
    - action: "file.write"
      effect: DENY
      conditions:
        - field: "env.name"
          operator: "equals"
          value: "production"
```

**Step 2:** Run the full test suite:

```python
# lab3_test.py
from agent_os import PolicyEngine

engine = PolicyEngine.from_file("lab3-production.yaml")

# Scenario 1: Research agent doing normal work
result = engine.evaluate(
    action="web.search",
    agent={"role": "research_agent", "trust_score": 500},
    env={"name": "production"}
)
assert result.allowed, "Research agent should search the web"

# Scenario 2: Billing agent charging small amount
result = engine.evaluate(
    action="payment.charge",
    params={"amount": 50},
    agent={"role": "billing_agent", "trust_score": 600},
    env={"name": "production"}
)
assert result.allowed, "Small payment should go through"

# Scenario 3: Billing agent charging large amount (needs approval)
result = engine.evaluate(
    action="payment.charge",
    params={"amount": 5000},
    agent={"role": "billing_agent", "trust_score": 600},
    env={"name": "production"}
)
assert result.decision == "REQUIRE_APPROVAL", "Large payment needs approval"

# Scenario 4: Low-trust agent cannot refund
result = engine.evaluate(
    action="payment.refund",
    agent={"role": "billing_agent", "trust_score": 400},
    env={"name": "production"}
)
assert not result.allowed, "Low-trust agent should not refund"

# Scenario 5: No file writes in production
result = engine.evaluate(
    action="file.write",
    agent={"role": "research_agent", "trust_score": 800},
    env={"name": "production"}
)
assert not result.allowed, "No file writes in production"

# Scenario 6: Cross-role boundary (researcher trying billing)
result = engine.evaluate(
    action="payment.charge",
    agent={"role": "research_agent", "trust_score": 800},
    env={"name": "production"}
)
assert not result.allowed, "Research agent should not charge payments"

print("Lab 3: All production scenarios passed!")
print("\nCongratulations! You've built a complete governance stack.")
```

**Discussion points:**
- Which of these patterns apply to your current projects?
- How would you extend this for your specific use case?
- What's missing from this configuration? (Hint: audit logging, policy versioning, chaos testing)

---

## Wrap-Up (5 minutes)

**Key Takeaways:**

1. **Prompt guardrails are necessary but not sufficient** — they're a request, not a constraint
2. **Default-deny with explicit allowlist** — principle of least privilege for agents
3. **Identity + trust** — know who your agents are and what they've earned
4. **Policy-as-code** — versioned, tested, auditable governance rules
5. **Defense-in-depth** — combine multiple layers for production safety

**Resources:**
- [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)
- [Architecture Documentation](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/ARCHITECTURE.md)
- [Policy-as-Code Tutorial](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/tutorials/policy-as-code/)
- [OWASP Agentic Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [Competitive Comparison](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/COMPARISON.md)

**Community:**
- Report issues or request features via GitHub Issues
- Join discussions in the repository Discussions tab
- Contributions welcome — see CONTRIBUTING.md

---

*Workshop materials version 1.0. Tested with agent-governance-toolkit v0.3+*
