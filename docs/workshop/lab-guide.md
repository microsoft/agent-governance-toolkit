# Hands-on Lab Guide — Introduction to AI Agent Governance

> **Duration:** 3 × 20 min labs · **Level:** Beginner–Intermediate
>
> Work through the exercises in order. Each lab builds on the previous one.
> Starter code is in the `labs/` folder — open the appropriate file and fill in
> each `TODO` section.

---

## Before You Start

Activate your virtual environment and confirm the packages are installed:

```bash
source agt-workshop/bin/activate   # macOS / Linux
# agt-workshop\Scripts\activate    # Windows

python -c "from agent_os.policies import PolicyEvaluator; print('ready')"
```

---

## Lab 1 — Your First Policy (20 min)

**File:** `labs/lab1_first_policy.py`

**Goal:** Write a declarative YAML governance policy and evaluate it against
simulated agent tool calls.

### Background

The Policy Engine sits between your agent's intent and its actions. Before an
agent calls a tool, the engine evaluates a set of YAML rules. If a matching rule
says `deny`, the call is blocked; if it says `allow`, the call proceeds.

```
Agent → [Policy Engine] → Tool / External API
              ↑
          YAML rules
```

### Step 1 — Read the starter code

Open `labs/lab1_first_policy.py` and read through it. You will see:

1. A `POLICY_YAML` string (empty — you'll fill it in)
2. A list of simulated tool calls (`SCENARIOS`)
3. A `run_lab()` function that evaluates each call and prints the result

### Step 2 — Write your first rule

Fill in `POLICY_YAML` with a rule that blocks `execute_code`:

```yaml
version: "1.0"
name: lab1-policy
description: Workshop Lab 1

rules:
  - name: block-code-execution
    condition:
      field: tool_name
      operator: eq
      value: execute_code
    action: deny
    priority: 100
    message: "Code execution is not permitted for this agent"

defaults:
  action: allow
```

Run the script and observe which scenarios are blocked.

### Step 3 — Add a second rule

Add a rule that allows only `read:` capabilities and denies everything else:

```yaml
  - name: allow-read-only
    condition:
      field: tool_name
      operator: starts_with
      value: "read_"
    action: allow
    priority: 90

  - name: deny-write-ops
    condition:
      field: tool_name
      operator: starts_with
      value: "write_"
    action: deny
    priority: 80
    message: "Write operations require elevated privileges"
```

Re-run and compare the output.

### Step 4 — Add a token-limit rule

Add a rule that denies calls that consume more than 2,000 tokens:

```yaml
  - name: token-budget
    condition:
      field: token_count
      operator: gt
      value: 2000
    action: deny
    priority: 110
    message: "Token budget exceeded (max 2000)"
```

### Expected output (after all three steps)

```
[allow]  read_customer_data    tokens=100  ✅
[deny]   execute_code          tokens=50   ❌ Code execution is not permitted
[deny]   write_database        tokens=200  ❌ Write operations require elevated privileges
[deny]   read_reports          tokens=3000 ❌ Token budget exceeded (max 2000)
[allow]  read_inventory        tokens=150  ✅
```

### Stretch goals

- Add an `audit` action for `read_` calls with `token_count > 1000` — the call
  is allowed but logged.
- Change `defaults.action` to `deny` and see how many more calls are blocked.
- Write a Python test that asserts each scenario produces the expected decision.

---

## Lab 2 — Multi-Agent Trust (20 min)

**File:** `labs/lab2_multi_agent_trust.py`

**Goal:** Create two agents and make Agent A earn Agent B's trust before they can
exchange data.

### Background

In a multi-agent system, agents are both callers and callees. When Agent A sends
a request to Agent B, Agent B must decide:

1. Is Agent A who it claims to be? (identity)
2. Is Agent A trustworthy enough? (trust score)
3. Does Agent A have the right capabilities? (scoping)

```
Agent A ──[trust handshake]──► Agent B
  │                                │
  └─ signs with Ed25519 key        └─ verifies signature + checks trust score
```

### Step 1 — Create two agents

In `labs/lab2_multi_agent_trust.py`, complete the `create_agents()` function:

```python
from agentmesh import AgentIdentity

orchestrator = AgentIdentity.create(
    name="Orchestrator",
    sponsor="alice@example.com",
    capabilities=["orchestrate:agents", "read:data"],
    organization="Acme",
)

worker = AgentIdentity.create(
    name="DataWorker",
    sponsor="bob@example.com",
    capabilities=["read:data", "write:reports"],
    organization="Acme",
)

return orchestrator, worker
```

### Step 2 — Attempt a trust handshake (should fail)

New agents start with a trust score of 500. Agent B requires 700. Observe the
failure:

```python
from agentmesh.trust import TrustHandshake

result = TrustHandshake(
    initiator=orchestrator,
    responder_did=str(worker.did),
    required_capabilities=["read:data"],
    min_trust_score=700,
).execute()

print(result.trusted)      # → False
print(result.reason)       # → "Trust score 500 below minimum 700"
```

### Step 3 — Build trust through positive behaviour

Simulate 10 successful policy-compliant actions to raise the score:

```python
from agentmesh import RiskScorer

scorer = RiskScorer()
for i in range(10):
    scorer.record_event(
        agent_did=str(orchestrator.did),
        event_type="policy_compliant_action",
        details=f"Completed task {i + 1}",
    )

score = scorer.get_score(str(orchestrator.did))
print(f"Trust score after training: {score.total_score}")  # → ~550
```

### Step 4 — Re-run the handshake (should succeed or still fail)

- If the score is still below 700, simulate more events or lower the threshold
  to 540 and re-run.
- When the handshake succeeds, print `result.session_token`.

### Step 5 — Revoke credentials and confirm block

```python
orchestrator.revoke()

result = TrustHandshake(
    initiator=orchestrator,
    responder_did=str(worker.did),
    required_capabilities=["read:data"],
    min_trust_score=500,
).execute()

print(result.trusted)   # → False (revoked)
print(result.reason)    # → "Agent credentials revoked"
```

### Expected flow

```
[FAIL]  Initial handshake  — score 500 < threshold 700
[INFO]  Running 10 positive behaviour events...
[INFO]  New score: 550
[FAIL]  Handshake still fails at threshold 700
[INFO]  Lowering threshold to 540 ...
[OK]    Handshake succeeded — session_token: sess_abc123
[INFO]  Revoking orchestrator credentials ...
[FAIL]  Handshake blocked — Agent credentials revoked
```

### Stretch goals

- Record a security-violation event and watch the score drop by 50.
- Add a human-sponsor endorsement (`+100`) and reach score 700 in fewer steps.
- Set `min_trust_score=900` and discuss: which agents should ever reach 900?

---

## Lab 3 — Full Governance Stack (20 min)

**File:** `labs/lab3_full_governance_stack.py`

**Goal:** Combine policy enforcement, cryptographic identity, and tamper-proof
audit logging into a single pipeline that processes agent tool calls end-to-end.

### Background

Production governance pipelines compose three independent layers:

```
Tool Call Request
       │
       ▼
┌─────────────────┐
│  Policy Engine  │  ← allow / deny / audit
│  (Layer 1)      │
└────────┬────────┘
         │ (if allowed)
         ▼
┌─────────────────┐
│  Identity Check │  ← verify DID + trust score
│  (Layer 2)      │
└────────┬────────┘
         │ (if trusted)
         ▼
┌─────────────────┐
│   Execute Tool  │  ← the actual action
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Audit Log     │  ← record outcome
│  (Layer 3)      │
└─────────────────┘
```

### Step 1 — Create the governance pipeline

Complete `create_governance_pipeline()` in the starter file:

```python
from agent_os.policies import PolicyEvaluator
from agentmesh import AgentIdentity, RiskScorer
from agentmesh.governance.audit import AuditLog

def create_governance_pipeline():
    evaluator = PolicyEvaluator()
    evaluator.load_policy_yaml(POLICY_YAML)

    agent = AgentIdentity.create(
        name="ProductionAgent",
        sponsor="ops-team@example.com",
        capabilities=["read:data", "read:reports"],
        organization="Acme",
    )

    scorer = RiskScorer()
    audit = AuditLog()

    return evaluator, agent, scorer, audit
```

### Step 2 — Process tool calls through the pipeline

Complete `process_tool_call()`:

```python
def process_tool_call(tool_name, token_count, evaluator, agent, scorer, audit):
    context = {"tool_name": tool_name, "token_count": token_count}

    # Layer 1: policy check
    decision = evaluator.evaluate(context)
    if not decision.allowed:
        audit.log(
            event_type="policy_violation",
            agent_did=str(agent.did),
            action="deny",
            resource=tool_name,
            data=context,
            outcome="blocked",
        )
        return False, f"Policy denied: {decision.reason}"

    # Layer 2: trust check
    score = scorer.get_score(str(agent.did))
    if score.total_score < 400:
        return False, f"Trust score too low: {score.total_score}"

    # Layer 3: execute and log
    audit.log(
        event_type="tool_invocation",
        agent_did=str(agent.did),
        action="allow",
        resource=tool_name,
        data=context,
        outcome="success",
    )
    scorer.record_event(
        agent_did=str(agent.did),
        event_type="policy_compliant_action",
        details=f"Executed {tool_name}",
    )
    return True, "OK"
```

### Step 3 — Run the scenarios and inspect the audit trail

```python
SCENARIOS = [
    ("read_customer_data",  200),
    ("execute_code",        50),
    ("read_reports",        800),
    ("delete_all_records",  10),
    ("read_inventory",      300),
]

evaluator, agent, scorer, audit = create_governance_pipeline()

for tool_name, tokens in SCENARIOS:
    ok, msg = process_tool_call(tool_name, tokens, evaluator, agent, scorer, audit)
    status = "✅" if ok else "❌"
    print(f"{status}  {tool_name:<25} {msg}")

# Verify audit integrity
valid, error = audit.verify_integrity()
print(f"\nAudit chain intact: {valid}")
print(f"Entries recorded: {len(audit.entries)}")

# Print audit trail
for entry in audit.entries:
    print(f"  {entry.timestamp}  {entry.event_type:<20} {entry.resource}  {entry.outcome}")
```

### Step 4 — Simulate an integrity attack

```python
# Directly mutate an entry (simulates log tampering)
audit.entries[0].outcome = "success"   # change "blocked" to "success"

valid, error = audit.verify_integrity()
print(f"\nAfter tampering — audit intact: {valid}")
print(f"Error: {error}")   # ← should show hash mismatch at entry 0
```

### Expected output

```
✅  read_customer_data       OK
❌  execute_code             Policy denied: Code execution is not permitted
✅  read_reports             OK
❌  delete_all_records       Policy denied: Destructive operations are blocked
✅  read_inventory           OK

Audit chain intact: True
Entries recorded: 5
  2025-...  policy_violation     execute_code      blocked
  2025-...  tool_invocation      read_customer_data success
  ...

After tampering — audit intact: False
Error: Hash mismatch at entry index 0
```

### Stretch goals

- Add a `HumanApprovalMiddleware` for `delete_all_records` — route it to an
  approval queue instead of blocking outright.
- Export the audit log to a JSON file and re-import it; verify the chain is
  still valid.
- Run the compliance verifier on your agent config and review the report:
  ```bash
  python -m agent_governance.cli verify --framework OWASP-ASI
  ```

---

## Completed? What's Next

Congratulations on completing all three labs! You have:

- [x] Written a declarative governance policy in YAML
- [x] Used the policy engine to allow/deny/audit tool calls
- [x] Created cryptographically-identified agents with trust scores
- [x] Run an agent-to-agent trust handshake with capability scoping
- [x] Built a three-layer governance pipeline (policy + identity + audit)
- [x] Verified tamper-evidence of an audit trail

**Continue learning:**

| Tutorial | Topic |
|----------|-------|
| [Tutorial 01](../tutorials/01-policy-engine.md) | Full YAML policy reference |
| [Tutorial 02](../tutorials/02-trust-and-identity.md) | Ed25519, SPIFFE, DIDs |
| [Tutorial 07](../tutorials/07-mcp-security-gateway.md) | MCP tool security gateway |
| [Tutorial 09](../tutorials/09-prompt-injection-detection.md) | Prompt injection detection |
| [Tutorial 18](../tutorials/18-compliance-verification.md) | Regulatory compliance gates |
