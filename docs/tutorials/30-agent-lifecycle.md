# Tutorial 30 — Agent Lifecycle Management: Birth to Retirement

> **Package:** `agentmesh-platform` · **Time:** 20 minutes · **Prerequisites:** Python 3.11+

---

## What You'll Learn

- How to manage agent identities from provisioning to decommission
- How approval workflows control agent onboarding
- How credential rotation keeps agents secure with short-lived credentials
- How orphan detection finds abandoned agents in your fleet
- How the full audit trail satisfies compliance requirements

---

## Why Lifecycle Management?

Agent identity is more than issuing a DID. Enterprises need to manage the **full lifecycle**:

```
Request → Approve → Provision → Activate → Monitor → Rotate → Decommission
    │                                         │
    │                                    Orphan Detection
    └── Reject                           (heartbeat monitoring)
```

Without lifecycle management:
- **Orphan agents** accumulate — no one knows who owns them
- **Stale credentials** create persistent attack surfaces (Salesloft incident)
- **No accountability** — when an agent misbehaves, there's no ownership trail
- **Compliance gaps** — EU AI Act Art. 14 requires demonstrable human oversight

---

## Step 1: Create a Lifecycle Manager

```python
from agentmesh.lifecycle import LifecycleManager, LifecyclePolicy, CredentialPolicy
from datetime import timedelta

# Configure policy
policy = LifecyclePolicy(
    require_approval=True,           # Human must approve new agents
    require_owner=True,              # Every agent needs an owner
    heartbeat_interval=timedelta(minutes=5),
    orphan_threshold=timedelta(hours=24),
    max_inactive_days=90,
    credential_policy=CredentialPolicy(
        max_credential_ttl=timedelta(hours=24),   # Short-lived credentials
        auto_rotate=True,                          # Rotate before expiry
        revoke_on_decommission=True,               # Clean up on shutdown
    ),
)

manager = LifecycleManager(
    policy=policy,
    storage_path="~/.agentmesh/lifecycle.json",  # Persistent storage
)
```

---

## Step 2: Provision an Agent

```python
# Developer requests a new agent
agent = manager.request_provisioning(
    name="Code Review Agent",
    owner="alice@company.com",
    purpose="Automated PR review for the platform team",
    agent_type="langchain",
    actor="alice@company.com",
    tags={"team": "platform", "env": "production"},
)

print(f"Agent {agent.agent_id}: {agent.state.value}")
# → Agent agent:a1b2c3d4e5f6: pending_approval
```

---

## Step 3: Approval Workflow

```python
# Admin approves the request
agent = manager.approve(agent.agent_id, actor="admin@company.com")
print(f"State: {agent.state.value}")  # → provisioned

# Or reject it:
# manager.reject(agent.agent_id, reason="Duplicate of existing agent")
```

---

## Step 4: Activate with Credentials

```python
# Activate the agent — issues short-lived credentials
agent = manager.activate(agent.agent_id)
print(f"State: {agent.state.value}")          # → active
print(f"Credential: {agent.credential_id}")    # → cred:abc123...
print(f"Expires: {agent.credential_expires_at}")  # → 24h from now
```

---

## Step 5: Heartbeat Monitoring

```python
# Agent sends periodic heartbeats to prove it's alive
agent = manager.heartbeat(agent.agent_id)
print(f"Heartbeats: {agent.heartbeat_count}")  # → 1

# In production, agents call this on a timer:
# while running:
#     manager.heartbeat(my_agent_id)
#     await asyncio.sleep(300)  # every 5 minutes
```

---

## Step 6: Credential Rotation

```python
from agentmesh.lifecycle import CredentialRotator

rotator = CredentialRotator(manager)

# Check fleet and rotate expiring credentials
results = rotator.check_and_rotate()
for r in results:
    print(f"  {r['agent_id']}: {r['action']} — {r['detail']}")

# Manual rotation
agent = manager.rotate_credentials(agent.agent_id)
print(f"New credential: {agent.credential_id}")
```

---

## Step 7: Orphan Detection

```python
from agentmesh.lifecycle import OrphanDetector

detector = OrphanDetector(manager)

# Scan for orphaned agents
candidates = detector.detect()
for c in candidates:
    print(f"  ⚠ {c.agent.name}: {c.reason}")
    if c.days_silent:
        print(f"    Silent for {c.days_silent:.1f} days")

# Mark as orphaned (restricts operations)
detector.mark_orphaned(silent_agent_id)

# Reclaim with new owner
detector.reclaim(orphan_id, new_owner="bob@company.com")
```

---

## Step 8: Decommission

```python
# Clean decommission — revokes credentials, records audit trail
agent = manager.decommission(
    agent.agent_id,
    reason="Feature sunset — migrating to new agent",
    actor="alice@company.com",
)
print(f"State: {agent.state.value}")         # → decommissioned
print(f"Credential: {agent.credential_id}")  # → None (revoked)
print(f"Retired: {agent.decommissioned_at}")
```

---

## Step 9: Audit Trail

Every lifecycle event is immutably recorded:

```python
trail = manager.get_audit_trail(agent.agent_id)
for event in trail:
    print(f"  [{event.timestamp}] {event.event_type.value}")
    print(f"    Actor: {event.actor}")
    print(f"    {event.previous_state} → {event.new_state}")

# Output:
#   [2026-04-11T04:30:00Z] requested
#     Actor: alice@company.com
#     None → pending_approval
#   [2026-04-11T04:31:00Z] approved
#     Actor: admin@company.com
#     pending_approval → provisioned
#   [2026-04-11T04:32:00Z] activated
#     Actor: system
#     provisioned → active
#   ...
```

---

## State Machine Reference

```
                    ┌─────────┐
                    │REQUESTED│
                    └────┬────┘
                   approve│reject
              ┌──────────┴──────────┐
              ▼                     ▼
        ┌───────────┐        ┌──────────────┐
        │PROVISIONED│        │DECOMMISSIONED│
        └─────┬─────┘        └──────────────┘
         activate│                    ▲
              ▼                       │
        ┌──────────┐    decommission  │
   ┌───►│  ACTIVE  ├─────────────────►│
   │    └──┬───┬───┘                  │
   │  suspend│  │orphan               │
   │       ▼  │  ▼                    │
   │ ┌─────────┐ ┌────────┐          │
   │ │SUSPENDED│ │ORPHANED├──────────►│
   │ └────┬────┘ └───┬────┘          │
   │ resume│     reclaim│              │
   └──────┘      └──────┘
```

---

## Next Steps

- **Discover first:** [Tutorial 29 — Agent Discovery](29-agent-discovery.md)
- **Apply policies:** [Tutorial 01 — Policy Engine](01-policy-engine.md)
- **Set up identity:** [Tutorial 02 — Trust & Identity](02-trust-and-identity.md)
- **Monitor health:** [Tutorial 05 — Agent Reliability (SRE)](05-agent-reliability.md)
