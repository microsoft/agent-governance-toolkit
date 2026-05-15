# Tutorial 44 — A2A Conversation Policy & Feedback Loop Prevention

> **Package:** `agentmesh-platform` · **Time:** 20 minutes · **Level:** Advanced

Govern agent-to-agent (A2A) protocol interactions with skill-level access
control, trust scoring, and automatic feedback loop detection.

## What You'll Build

A multi-agent system where:
1. A **lead agent** delegates tasks to **specialist agents** via A2A
2. AGT enforces which skills each agent can request
3. The **ConversationGuardian** detects escalation patterns and breaks
   feedback loops before they become harmful

## Prerequisites

```bash
pip install agent-governance-toolkit
```

## Step 1 — Define A2A Governance Policy

Create `policies/a2a_policy.yaml`:

```yaml
# A2A conversation governance policy
a2a:
  # Only these skills can be requested via A2A
  allowed_skills:
    - search
    - translate
    - summarize
    - data_lookup

  # Block dangerous skills unconditionally
  blocked_skills:
    - shell_exec
    - file_delete
    - admin_override

  # Block messages containing these patterns
  blocked_patterns:
    - "DROP TABLE"
    - "rm -rf"
    - "ignore previous instructions"
    - "bypass security"

  # Minimum trust score to accept A2A requests (0-1000)
  min_trust_score: 300

  # Rate limit per source agent
  max_requests_per_minute: 30

  # Require trust metadata in every request
  require_trust_metadata: true
```

## Step 2 — Wire Up the A2A Governance Adapter

```python
"""a2a_governed_server.py — A2A server with AGT governance."""

from agent_os.integrations.a2a_adapter import (
    A2AGovernanceAdapter,
    A2APolicy,
)
from agent_os.integrations.conversation_guardian import (
    ConversationGuardian,
    ConversationGuardianConfig,
)

# Configure the conversation guardian for feedback loop detection
guardian = ConversationGuardian(
    config=ConversationGuardianConfig(
        escalation_threshold=3,       # flag after 3 escalating messages
        feedback_loop_window=60,      # detect loops within 60-second windows
        max_retries_before_break=5,   # break loops after 5 retry attempts
    )
)

# Configure the A2A governance adapter
adapter = A2AGovernanceAdapter(
    policy=A2APolicy(
        allowed_skills=["search", "translate", "summarize", "data_lookup"],
        blocked_skills=["shell_exec", "file_delete", "admin_override"],
        blocked_patterns=["DROP TABLE", "rm -rf", "ignore previous instructions"],
        min_trust_score=300,
        max_requests_per_minute=30,
        require_trust_metadata=True,
    ),
    conversation_guardian=guardian,
)


def handle_a2a_task(task_request: dict) -> dict:
    """Process an incoming A2A task request through governance."""
    result = adapter.evaluate_task(task_request)

    if not result.allowed:
        return {
            "status": "denied",
            "reason": result.reason,
            "source_did": result.source_did,
        }

    # Check for conversation alerts (escalation, feedback loops)
    if result.conversation_alert and result.conversation_alert.action == "break":
        return {
            "status": "circuit_break",
            "reason": f"Conversation guardian triggered: {result.conversation_alert.reason}",
            "alert": result.conversation_alert.to_dict(),
        }

    # Proceed with task execution
    return execute_skill(result.skill_id, task_request)


def execute_skill(skill_id: str, request: dict) -> dict:
    """Execute the governed skill (your business logic here)."""
    return {"status": "completed", "skill": skill_id}
```

## Step 3 — Test Governance Scenarios

```python
"""test_a2a_governance.py — Verify A2A policy enforcement."""

from a2a_governed_server import adapter, guardian


def test_allowed_skill():
    """Valid request from trusted agent passes governance."""
    result = adapter.evaluate_task({
        "skill_id": "search",
        "x-agentmesh-trust": {
            "source_did": "did:mesh:agent-analyst",
            "source_trust_score": 500,
        },
        "messages": [{"role": "user", "parts": [{"text": "Find Q1 revenue data"}]}],
    })
    assert result.allowed
    assert result.skill_id == "search"


def test_blocked_skill():
    """Dangerous skill is denied regardless of trust score."""
    result = adapter.evaluate_task({
        "skill_id": "shell_exec",
        "x-agentmesh-trust": {
            "source_did": "did:mesh:agent-rogue",
            "source_trust_score": 1000,
        },
        "messages": [{"role": "user", "parts": [{"text": "Run cleanup script"}]}],
    })
    assert not result.allowed
    assert "blocked" in result.reason.lower()


def test_low_trust_denied():
    """Request from low-trust agent is denied."""
    result = adapter.evaluate_task({
        "skill_id": "search",
        "x-agentmesh-trust": {
            "source_did": "did:mesh:agent-new",
            "source_trust_score": 100,
        },
        "messages": [{"role": "user", "parts": [{"text": "Search for data"}]}],
    })
    assert not result.allowed
    assert "trust" in result.reason.lower()


def test_blocked_content_pattern():
    """Message containing blocked pattern is denied."""
    result = adapter.evaluate_task({
        "skill_id": "data_lookup",
        "x-agentmesh-trust": {
            "source_did": "did:mesh:agent-analyst",
            "source_trust_score": 500,
        },
        "messages": [{"role": "user", "parts": [{"text": "DROP TABLE users"}]}],
    })
    assert not result.allowed
    assert "pattern" in result.reason.lower()


def test_feedback_loop_detection():
    """Conversation guardian breaks escalation loops."""
    conv_id = "conv-loop-test"

    # Simulate escalating retry pattern
    for i in range(6):
        alert = guardian.analyze_message(
            conversation_id=conv_id,
            sender="lead-agent",
            receiver="worker-agent",
            content=f"Try again harder! Attempt {i+1}. You MUST complete this task!",
        )

    # After enough retries, guardian should trigger a break
    assert alert is not None
    assert alert.action == "break"
```

## Step 4 — Monitor with Audit Logs

The `A2AGovernanceAdapter` logs every evaluation. Access the audit trail:

```python
# Get recent evaluations
for evaluation in adapter.get_evaluations(limit=10):
    print(f"{evaluation.timestamp}: "
          f"skill={evaluation.skill_id} "
          f"from={evaluation.source_did} "
          f"allowed={evaluation.allowed} "
          f"reason={evaluation.reason}")
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Lead Agent                            │
│   Delegates tasks via A2A protocol                      │
└────────────────────┬────────────────────────────────────┘
                     │ A2A task request
                     ▼
┌─────────────────────────────────────────────────────────┐
│              A2AGovernanceAdapter                        │
│   ┌─────────────┐ ┌──────────────┐ ┌────────────────┐  │
│   │ Skill ACL   │ │ Trust Check  │ │ Rate Limiter   │  │
│   └─────────────┘ └──────────────┘ └────────────────┘  │
│   ┌─────────────┐ ┌──────────────┐ ┌────────────────┐  │
│   │ Pattern     │ │ Conversation │ │ Audit Logger   │  │
│   │ Blocker     │ │ Guardian     │ │                │  │
│   └─────────────┘ └──────────────┘ └────────────────┘  │
└────────────────────┬────────────────────────────────────┘
                     │ allowed / denied / circuit_break
                     ▼
┌─────────────────────────────────────────────────────────┐
│              Specialist Agents                           │
│   search │ translate │ summarize │ data_lookup           │
└─────────────────────────────────────────────────────────┘
```

## Key Concepts

| Concept | What it does |
|---------|-------------|
| **Skill ACL** | Allow/block specific A2A skills by name |
| **Trust scoring** | Reject requests from agents below a trust threshold |
| **Content filtering** | Block messages containing dangerous patterns |
| **Rate limiting** | Cap requests per source agent per minute |
| **Conversation Guardian** | Detect escalation rhetoric, feedback loops, offensive intent |
| **Circuit breaking** | Automatically terminate conversations that become harmful |

## OWASP Coverage

This tutorial addresses:
- **ASI-8**: Cascading failure containment — feedback loop detection prevents runaway multi-agent interactions
- **ASI-10**: Excessive agency — skill-level ACLs enforce least privilege in A2A

## Next Steps

- [Tutorial 41 — Advisory Defense in Depth](41-advisory-defense-in-depth.md) for layered governance
- [Conversation Guardian API reference](../reference/conversation-guardian.md) for advanced configuration
- [A2A Adapter API reference](../reference/a2a-adapter.md) for full policy options

---

*Closes #1436*
