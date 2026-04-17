# Introduction to AI Agent Governance — Slide Deck

> **22 slides · 2-hour workshop**
>
> Render with [Marp](https://marp.app/) (`marp slides.md --html`),
> [Slidev](https://sli.dev/), or read as plain Markdown.
>
> Slide boundaries are marked with `---`.

---

## Slide 1 — Title

# Introduction to AI Agent Governance

**A hands-on workshop using the Agent Governance Toolkit**

*2 hours · 3 labs · Python 3.10+*

> "An AI agent without governance is a tool without a safety switch."

---

## Slide 2 — Agenda

# What We'll Cover Today

| Time | Segment |
|------|---------|
| 0:00–0:20 | Why governance matters |
| 0:20–0:40 | **Lab 1** — Your first policy |
| 0:40–0:55 | Trust and identity |
| 0:55–1:15 | **Lab 2** — Multi-agent trust |
| 1:15–1:25 | Break ☕ |
| 1:25–1:40 | Production patterns |
| 1:40–2:00 | **Lab 3** — Full governance stack |

---

## Slide 3 — The Problem

# Why Governance Matters

**AI agents are different from traditional software:**

- They take actions autonomously (API calls, file writes, web searches)
- They make decisions in milliseconds — too fast for human review
- They chain together: one agent's output is another agent's input
- Mistakes can compound: a bad policy decision at step 1 affects steps 2–10

**Real consequences of ungoverned agents:**

- Data exfiltration via prompt injection
- Runaway costs from unthrottled token usage
- Accountability gaps — "the AI did it" is not a legal defence
- Regulatory violations (GDPR, HIPAA, EU AI Act)

---

## Slide 4 — The OWASP ASI Top 10

# The OWASP AI Security Top 10

The [OWASP Autonomous AI Security Initiative](https://owasp.org/www-project-ai-security-and-privacy-guide/)
identifies the most critical risks for agentic AI systems:

| # | Risk |
|---|------|
| ASI-01 | Prompt Injection |
| ASI-02 | Insecure Tool Use |
| ASI-03 | Excessive Agency |
| ASI-04 | Insecure Output Handling |
| ASI-05 | Sensitive Information Disclosure |
| ASI-06 | Model Denial of Service |
| ASI-07 | Supply Chain Vulnerabilities |
| ASI-08 | Inadequate Logging & Monitoring |
| ASI-09 | Insecure Plugin Design |
| ASI-10 | Overreliance |

**We'll mitigate all of these today.**

---

## Slide 5 — The Governance Toolkit

# The Agent Governance Toolkit (AGT)

An open-source framework for governing AI agents at runtime:

```
┌─────────────────────────────────────────┐
│            Your AI Agent                │
├─────────────────────────────────────────┤
│  Policy Engine  │  Trust & Identity     │
│  (allow/deny)   │  (who can do what)    │
├─────────────────────────────────────────┤
│  Audit Log      │  Compliance Gates     │
│  (tamper-proof) │  (pass/fail checks)   │
└─────────────────────────────────────────┘
```

**Key packages:**

| Package | Purpose |
|---------|---------|
| `agent-os-kernel` | Policy engine, middleware, MCP gateway |
| `agentmesh-platform` | Trust, identity, audit |
| `agent-governance-toolkit` | Compliance verification, CLI |

---

## Slide 6 — Three Layers of Governance

# Three Layers of Governance

**Layer 1 — Policy:** *What is the agent allowed to do?*

```yaml
rules:
  - name: block-code-execution
    condition: {field: tool_name, operator: eq, value: execute_code}
    action: deny
```

**Layer 2 — Identity:** *Who is this agent, and do I trust it?*

```python
agent = AgentIdentity.create(name="DataProcessor", sponsor="alice@corp.com")
score = RiskScorer().get_score(str(agent.did))   # 0–1000
```

**Layer 3 — Audit:** *What did it do, and can we prove it?*

```python
audit.log(event_type="tool_invocation", agent_did=agent.did, ...)
valid, _ = audit.verify_integrity()   # cryptographic proof
```

---

## Slide 7 — Lab 1 Preview

# Lab 1 — Your First Policy (20 min)

**Goal:** Write a YAML governance policy and evaluate it against simulated agent calls.

**You will:**
1. Define allow/deny rules for a customer-service agent
2. Load and evaluate the policy in Python
3. Observe which tool calls are permitted and which are blocked
4. Add a rate-limiting rule and see it fire

**File to edit:** `labs/lab1_first_policy.py`

> Open the file now and read the `TODO` comments.

---

## Slide 8 — Trust and Identity

# Trust and Identity in Multi-Agent Systems

**The core question:** When Agent B receives a request from Agent A, should it comply?

Without cryptographic identity:
- Any process can *claim* to be "the orchestrator"
- Prompt injection can impersonate privileged agents
- No way to audit which agent actually did what

**AGT answers with three primitives:**

| Primitive | What it does |
|-----------|-------------|
| **DID** | Decentralized identifier — `did:mesh:<hash>` — unique to each agent |
| **Ed25519 key** | Cryptographic signature — proves messages came from this agent |
| **Trust score** | Continuous 0–1000 rating based on observed behaviour |

---

## Slide 9 — Decentralized Identifiers

# Decentralized Identifiers (DIDs)

A DID is a stable, globally unique identifier that an agent owns:

```
did:mesh:7f3a9b2c4d5e6f7a8b9c0d1e2f3a4b5c
   ↑      ↑
method   unique ID (SHA-256 derived)
```

**Properties:**

- **Self-sovereign** — the agent generates its own DID; no central registry
- **Cryptographically bound** — the DID maps to an Ed25519 public key
- **Revocable** — sponsors can invalidate credentials instantly
- **Rotatable** — keys rotate on a short TTL (default: 15 minutes)

```python
from agentmesh import AgentDID

did = AgentDID.generate(name="SalesBot", org="Acme")
print(did)   # did:mesh:7f3a9b2c...
```

---

## Slide 10 — Trust Scores

# Trust Scores: 0–1000

Every agent starts at **500** (neutral). The score moves based on observed behaviour:

| Event | Score change |
|-------|-------------|
| Successful policy-compliant action | +5 |
| Failed policy check (warning) | −10 |
| Security violation detected | −50 |
| Human sponsor endorsement | +100 |
| Agent flagged by peer | −30 |

**Risk levels:**

| Range | Level | Implication |
|-------|-------|-------------|
| 800–1000 | Low risk | Full autonomy |
| 500–799 | Medium risk | Standard review |
| 200–499 | High risk | Human approval required |
| 0–199 | Critical | Quarantine / suspend |

---

## Slide 11 — Trust Handshakes

# Agent-to-Agent Trust Handshakes

Before agents exchange data, they prove their identity:

```python
from agentmesh.trust import TrustHandshake

handshake = TrustHandshake(
    initiator=agent_a,
    responder_did="did:mesh:responder...",
    required_capabilities=["read:orders"],
    min_trust_score=600,
)

result = handshake.execute()
print(result.trusted)      # True / False
print(result.trust_score)  # Current score of responder
```

**Under the hood:**
1. A challenges B with a nonce
2. B signs the nonce with its Ed25519 private key
3. A verifies the signature against B's registered public key
4. A checks B's trust score meets the minimum threshold

---

## Slide 12 — Human Sponsors

# Human Sponsors — Accountability by Design

Every agent must have a **named human sponsor** who is accountable for its actions:

```python
agent = AgentIdentity.create(
    name="PaymentProcessor",
    sponsor="jane.smith@corp.com",   # ← mandatory
    capabilities=["read:invoices", "write:payments"],
    organization="Finance",
)
```

**Sponsor responsibilities:**

- Receives alerts when the agent violates policies
- Must approve capability expansions
- Can revoke the agent's credentials instantly
- Is named in audit logs alongside the agent

This maps to the EU AI Act requirement for a **human in the loop** for high-risk systems.

---

## Slide 13 — Capability Scoping

# Capability Scoping — Least Privilege for Agents

Agents declare what they *need* to do; the policy engine enforces what they *can* do:

```yaml
# agent declares:
capabilities: ["read:customer_data", "write:reports"]

# policy enforces:
rules:
  - name: scope-check
    condition:
      field: requested_capability
      operator: not_in
      value: ["read:customer_data", "write:reports"]
    action: deny
    message: "Capability not in agent scope"
```

**Principle of least privilege:** agents cannot self-grant capabilities.
Capability expansions require sponsor approval.

---

## Slide 14 — Lab 2 Preview

# Lab 2 — Multi-Agent Trust (20 min)

**Goal:** Set up a two-agent system where Agent A must earn Agent B's trust before they can exchange data.

**You will:**
1. Create two agents with different capability scopes
2. Attempt a trust handshake (observe the failure when score is too low)
3. Simulate positive behaviour events to raise the trust score
4. Re-run the handshake and observe success
5. Revoke Agent A's credentials and confirm the handshake is blocked again

**File to edit:** `labs/lab2_multi_agent_trust.py`

---

## Slide 15 — Production Patterns

# Production Patterns

Moving from "it works on my laptop" to a governed production system:

| Pattern | Problem solved | AGT feature |
|---------|---------------|-------------|
| **Policy-as-Code** | Policies drift from docs | YAML policies in git |
| **Immutable audit trail** | Logs can be tampered | Merkle-chain `AuditLog` |
| **Circuit breakers** | Agent runs out of control | SLO / error-budget gates |
| **Least privilege rings** | Agents over-privileged | 4-tier privilege rings |
| **Human approval gates** | High-risk actions bypass review | `HumanApprovalMiddleware` |
| **CI compliance checks** | Governance breaks in prod | `ComplianceVerifier` |

---

## Slide 16 — Policy-as-Code

# Policy-as-Code

Store policies in version control alongside application code:

```
repo/
├── agents/
│   └── sales_agent.py
└── policies/
    ├── base-policy.yaml       # shared defaults
    ├── sales-policy.yaml      # role-specific rules
    └── tests/
        └── test_policies.py   # automated policy tests
```

Benefits:
- Policies are code-reviewed before deployment
- Changes are auditable via `git log`
- Automated tests catch regressions
- Rollback is `git revert`

```bash
# CI gate — fail the build if policies are violated
python -m pytest policies/tests/ -v
```

---

## Slide 17 — Immutable Audit Trails

# Immutable Audit Trails

Every event is recorded in a **Merkle hash chain**:

```
Entry 1 ──hash──► Entry 2 ──hash──► Entry 3 ──hash──► ...
   ↑                  ↑                  ↑
SHA-256(data)    SHA-256(prev_hash      SHA-256(prev_hash
                        + data)                + data)
```

**Tampering is detectable:**

```python
audit.verify_integrity()   # checks every hash link
# → (True, None)            if chain is intact
# → (False, "entry 3 hash mismatch")  if tampered
```

Use for: regulatory evidence, incident investigation, billing disputes.

---

## Slide 18 — Circuit Breakers and SLOs

# Circuit Breakers and SLOs

Set SLOs (Service Level Objectives) and let the toolkit enforce them:

```python
from agent_sre import SLOMonitor, CircuitBreaker

monitor = SLOMonitor(target_availability=0.99, window_days=7)
breaker = CircuitBreaker(failure_threshold=5, reset_timeout=60)

# Before each agent call:
if breaker.is_open():
    raise AgentUnavailableError("Circuit breaker open")
```

**Error budgets:**
- SLO of 99% → 1% error budget = ~7 minutes of downtime per day
- Once budget is exhausted, the circuit opens automatically
- Human approval required to reset

---

## Slide 19 — Human Approval Gates

# Human Approval Gates

Some actions are too risky for autonomous execution:

```python
from agent_os.middleware import HumanApprovalMiddleware

middleware = HumanApprovalMiddleware(
    high_risk_tools=["delete_database", "send_mass_email", "transfer_funds"],
    approval_timeout_seconds=300,
    escalation_email="security@corp.com",
)

# In your agent loop:
decision = middleware.evaluate(tool_name="transfer_funds", amount=50000)
# decision.requires_approval → True
# decision.approval_token   → "apv_abc123" (poll for human response)
```

The middleware pauses execution and waits for an out-of-band approval signal.

---

## Slide 20 — Compliance Verification

# Compliance Verification as a CI Gate

Run compliance checks in your CI/CD pipeline:

```yaml
# .github/workflows/governance.yml
- name: Governance compliance check
  run: |
    python -m agent_governance.cli verify \
      --framework OWASP-ASI \
      --agent-config agents/config.yaml \
      --fail-on critical
```

**Built-in frameworks:**

| Framework | What it checks |
|-----------|---------------|
| OWASP ASI 2026 | ASI-01 through ASI-10 controls |
| EU AI Act | High-risk system requirements |
| NIST AI RMF | Risk management controls |
| ISO 42001 | AI management system |

---

## Slide 21 — Lab 3 Preview

# Lab 3 — Full Governance Stack (20 min)

**Goal:** Wire policy, trust, and audit together into a complete governance pipeline.

**You will:**
1. Create a governed agent with policy, identity, and audit
2. Send a mix of benign and malicious tool calls through the pipeline
3. Observe the policy engine blocking dangerous calls
4. Inspect the audit trail and verify its integrity
5. Run the compliance verifier and read the report

**File to edit:** `labs/lab3_full_governance_stack.py`

---

## Slide 22 — What's Next

# What's Next

**Explore the tutorials (self-paced):**

- [Tutorial 01 — Policy Engine](../tutorials/01-policy-engine.md) — full YAML reference
- [Tutorial 02 — Trust & Identity](../tutorials/02-trust-and-identity.md) — Ed25519, DIDs, SPIFFE
- [Tutorial 04 — Audit & Compliance](../tutorials/04-audit-and-compliance.md) — Merkle chains
- [Tutorial 09 — Prompt Injection](../tutorials/09-prompt-injection-detection.md) — attack detection
- [Tutorial 18 — Compliance Verification](../tutorials/18-compliance-verification.md) — regulatory gates

**Contribute:**

- Open issues and PRs at [github.com/microsoft/agent-governance-toolkit](https://github.com/microsoft/agent-governance-toolkit)
- Read [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines

**Community:**

- Questions? [SUPPORT.md](../../SUPPORT.md)
- Share what you build! Tag `#AgentGovernanceToolkit` on social media
