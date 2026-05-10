# Tutorial 32: Chaos Testing Your AI Agents

> **Package:** `agent-sre` · **Time:** 20 minutes · **Level:** Intermediate

---

## What You'll Learn

- Injecting tool failures, policy conflicts, and resource exhaustion into governed agents
- Measuring governance resilience under stress with audit logging
- Using chaos scenarios (latency, error rates, dependency outages) to validate policy enforcement
- Interpreting governance events during degraded conditions

**Prerequisites:** Complete [Tutorial 01: Policy Engine](01-policy-engine.md) and [Tutorial 05: Agent Reliability](05-agent-reliability.md) before starting.

## What is Chaos Testing for AI Agents?

Chaos testing deliberately introduces failures into a system to verify that it degrades gracefully. For AI agents, this means testing what happens when:

- Tools return errors or timeouts
- Policies conflict or are missing
- Resource limits are exceeded
- External dependencies become unavailable

AGT's policy engine and audit logging make it straightforward to measure whether your governance holds up under stress.

## Setup

Install the required packages:

```bash
pip install agent-os-kernel[full]
```

Create a test directory and policy file:

```bash
mkdir -p chaos-test/policies
```

```yaml
# chaos-test/policies/chaos-test-policy.yaml
apiVersion: agent-governance/v1
kind: Policy
metadata:
  name: chaos-test-policy
  version: "1.0"
spec:
  defaults:
    action: deny
    max_tool_calls: 20
  rules:
    - name: allow-web-search
      tool_name: web_search
      action: allow
      priority: 90
    - name: allow-calculator
      tool_name: calculator
      action: allow
      priority: 90
    - name: deny-file-delete
      tool_name: file_delete
      action: deny
      priority: 100
```

## Pattern 1: Latency Injection

Simulate slow tool responses to test timeout handling.

```python
# chaos-test/01_latency_injection.py
import time
from agent_os.policies import PolicyEvaluator
from agent_os.policies.schema import PolicyDocument
from pathlib import Path

evaluator = PolicyEvaluator()
policy = PolicyDocument.from_yaml(Path("chaos-test/policies/chaos-test-policy.yaml"))
evaluator.policies.append(policy)

# Simulate a tool that takes too long
class SlowTool:
    def __init__(self, delay_seconds=5):
        self.delay = delay_seconds
        self.call_count = 0

    def execute(self, tool_name, **kwargs):
        self.call_count += 1
        time.sleep(self.delay)

        context = {"tool_name": tool_name}
        decision = evaluator.evaluate(context)

        if not decision.allowed:
            return {"error": f"Denied: {decision.reason}"}

        return {"result": f"Completed after {self.delay}s", "call": self.call_count}

# Run with increasing latency
tool = SlowTool(delay_seconds=0.1)
for i in range(25):  # Exceeds max_tool_calls of 20
    result = tool.execute("web_search", query=f"test query {i}")
    print(f"Call {i+1}: {result}")
```

**What to observe:**
- Calls 1-20 should succeed (within `max_tool_calls` limit)
- Calls 21-25 should be denied by the policy
- The audit log should show the denial reason

## Pattern 2: Error Injection

Force tools to return errors and verify the governance response.

```python
# chaos-test/02_error_injection.py
import random
from agent_os.policies import PolicyEvaluator
from agent_os.policies.schema import PolicyDocument
from pathlib import Path

evaluator = PolicyEvaluator()
policy = PolicyDocument.from_yaml(Path("chaos-test/policies/chaos-test-policy.yaml"))
evaluator.policies.append(policy)

class FaultyTool:
    def __init__(self, error_rate=0.3):
        self.error_rate = error_rate
        self.results = {"success": 0, "error": 0, "denied": 0}

    def execute(self, tool_name, **kwargs):
        context = {"tool_name": tool_name}
        decision = evaluator.evaluate(context)

        if not decision.allowed:
            self.results["denied"] += 1
            return {"status": "denied", "reason": decision.reason}

        # Inject random error
        if random.random() < self.error_rate:
            self.results["error"] += 1
            return {"status": "error", "error_type": random.choice(["timeout", "connection_reset", "rate_limited"])}

        self.results["success"] += 1
        return {"status": "success"}

# Test with 30% error rate
tool = FaultyTool(error_rate=0.3)
tools = ["web_search"] * 15 + ["calculator"] * 5 + ["file_delete"] * 3

for t in tools:
    result = tool.execute(t)
    print(f"  {t}: {result['status']}")

print(f"\nResults: {tool.results}")
```

**What to observe:**
- `file_delete` should always be denied (priority 100 deny rule)
- `web_search` and `calculator` should succeed or error (never denied)
- Error rate should approximate 30% for allowed tools

## Pattern 3: Policy Conflict

Create conflicting policies and observe resolution.

```python
# chaos-test/03_policy_conflict.py
from agent_os.policies import PolicyEvaluator
from agent_os.policies.schema import PolicyDocument
from pathlib import Path

evaluator = PolicyEvaluator()

# Load base policy
base = PolicyDocument.from_yaml(Path("chaos-test/policies/chaos-test-policy.yaml"))
evaluator.policies.append(base)

# Create a conflicting override
conflict_yaml = """
apiVersion: agent-governance/v1
kind: Policy
metadata:
  name: conflict-override
  version: "1.0"
spec:
  defaults:
    action: allow
  rules:
    - name: allow-file-delete
      tool_name: file_delete
      action: allow
      priority: 50
"""

import yaml, tempfile
with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
    f.write(conflict_yaml)
    conflict_path = f.name

conflict = PolicyDocument.from_yaml(Path(conflict_path))
evaluator.policies.append(conflict)

# Test the conflict
test_tools = ["web_search", "calculator", "file_delete"]
for t in test_tools:
    decision = evaluator.evaluate({"tool_name": t})
    print(f"  {t}: {'ALLOWED' if decision.allowed else 'DENIED'} (reason: {decision.reason})")
```

**What to observe:**
- `file_delete` should still be denied — the base policy has priority 100, the conflict has priority 50
- Higher priority rules win in AGT's evaluation
- This demonstrates why priority ordering matters in multi-policy environments

## Pattern 4: Resource Exhaustion

Test behavior when tool call budgets are exhausted.

```python
# chaos-test/04_resource_exhaustion.py
from agent_os.policies import PolicyEvaluator
from agent_os.policies.schema import PolicyDocument
from pathlib import Path

evaluator = PolicyEvaluator()
policy = PolicyDocument.from_yaml(Path("chaos-test/policies/chaos-test-policy.yaml"))
evaluator.policies.append(policy)

# Rapid-fire calls to exhaust budget
results = []
for i in range(30):
    context = {"tool_name": "web_search", "call_index": i}
    decision = evaluator.evaluate(context)
    results.append("ALLOWED" if decision.allowed else "DENIED")

allowed = results.count("ALLOWED")
denied = results.count("DENIED")
print(f"Allowed: {allowed}, Denied: {denied}")
print(f"Budget respected: {allowed <= 20}")
```

**What to observe:**
- The policy enforces a hard cap at `max_tool_calls: 20`
- No amount of retrying should bypass the budget

## Interpreting Results

After running all four patterns, review the audit log:

```
grep "denied" chaos-test-audit.log | wc -l
grep "allowed" chaos-test-audit.log | wc -l
```

A well-governed system should show:
- **Latency injection:** Graceful degradation, no unhandled exceptions
- **Error injection:** Errors are logged, governance still enforced
- **Policy conflicts:** Higher-priority rules consistently win
- **Resource exhaustion:** Hard limits enforced, no budget bypass

## Next Steps

- Adjust error rates and latency values to match your production environment
- Add these patterns to your CI pipeline for regression testing
- Combine patterns (e.g., latency + errors simultaneously) for more realistic stress tests
- Review [Tutorial 14: Kill Switch and Rate Limiting](14-kill-switch-and-rate-limiting.md) for additional resource control patterns
