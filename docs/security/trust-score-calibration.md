# Trust Score Calibration Guide

> How to interpret, calibrate, and operationalize AgentMesh's 0–1000 trust scoring system.

## Overview

AgentMesh assigns every agent a trust score from 0 to 1000. This guide provides the missing calibration details: what the scores mean, how they change, how to set thresholds, and how to map scores to capabilities.

---

## Trust Tiers

| Score Range | Tier | Meaning | Typical Capabilities |
|-------------|------|---------|---------------------|
| 900–1000 | **Verified Partner** | Long track record, fully audited, cross-org delegation | Full access, can delegate to other agents, production deploys |
| 700–899 | **Trusted** | Established, compliant, no recent violations | Elevated privileges, write access, sensitive data |
| 500–699 | **Standard** | Default for newly registered agents | Read access, non-sensitive writes, standard API calls |
| 300–499 | **Probationary** | New, recently violated, or under observation | Read-only, limited tool access, all actions logged |
| 0–299 | **Untrusted** | Unknown, compromised, or repeatedly non-compliant | Blocked or sandboxed, no external access |

---

## Score Components

The trust score is computed from four weighted dimensions:

```
trust_score = (
    0.35 × compliance_score +    # Policy compliance rate
    0.25 × task_success_score +  # Task completion without errors
    0.25 × behavior_score +      # Anomaly detection (no rogue behavior)
    0.15 × identity_score        # Identity freshness, credential validity
)
```

### Compliance Score (0–1000)
- Based on: ratio of policy-compliant actions to total actions
- `1000` if 100% of actions pass policy checks
- `-50` per policy violation (hard penalty)
- Lookback window: last 1000 actions or 7 days (whichever is larger)

### Task Success Score (0–1000)
- Based on: successful task completions vs failures
- `1000` if all tasks succeed
- `-100` per task failure
- Weighted by task severity (production tasks count 3x)

### Behavior Score (0–1000)
- Based on: absence of anomalous behavior
- `1000` if no anomalies detected
- `-200` per detected anomaly (burst activity, unexpected tool use, etc.)
- `-500` for quarantine trigger
- Resets to 500 after 30 days with no anomalies

### Identity Score (0–1000)
- `1000` if: DID registered, credentials valid, sponsor verified, credential rotated within TTL
- `-200` if credentials expired
- `-300` if no DID registered
- `-100` if sponsor unverified

---

## Score Decay

Trust scores decay over time to prevent stale high scores:

```
daily_decay = max(0, (days_since_last_activity - 7) × 2)
```

- **Active agents** (activity within 7 days): no decay
- **Inactive 7–30 days**: decay 2 points/day (max -46)
- **Inactive 30+ days**: decay 2 points/day (capped at tier floor)
- **Reactivation**: score freezes at current value, begins rebuilding on next action

### Decay Floors
Scores cannot decay below the floor of their current tier:
- Verified Partner agents cannot decay below 700 (trusted floor)
- Trusted agents cannot decay below 500 (standard floor)
- This prevents agents from being locked out due to scheduled downtime

---

## Calibration Guidelines

### Initial Score Assignment

| Agent Origin | Initial Score | Rationale |
|-------------|--------------|-----------|
| Registered with DID + verified sponsor | 600 | Standard tier — must prove itself |
| Registered with DID, no sponsor | 450 | Probationary — needs verification |
| Discovered (shadow agent) | 200 | Untrusted until registered |
| Migrated from legacy system | 500 | Standard — needs baseline period |
| Created by trusted agent (delegation) | parent_score × 0.7 | Inherit trust, with attenuation |

### Threshold Recommendations

Configure capability gates based on your risk tolerance:

```yaml
# Conservative (recommended for regulated industries)
trust_thresholds:
  read_data: 300
  write_data: 600
  send_email: 700
  deploy: 800
  cross_org_delegate: 900
  admin_operations: 950

# Moderate (general enterprise)
trust_thresholds:
  read_data: 200
  write_data: 500
  send_email: 600
  deploy: 700
  cross_org_delegate: 800
  admin_operations: 900

# Permissive (internal tools, experimentation)
trust_thresholds:
  read_data: 100
  write_data: 300
  send_email: 400
  deploy: 500
  cross_org_delegate: 700
  admin_operations: 800
```

---

## Score-to-Capability Mapping

```python
from agentmesh import TrustBridge

bridge = TrustBridge()

# Check if agent has sufficient trust for an action
can_deploy = bridge.check_trust(
    agent_did="did:agent:deploy-bot",
    required_score=700,
    action="deploy",
)

# Get current score breakdown
report = bridge.get_trust_report("did:agent:deploy-bot")
# report.total_score = 750
# report.compliance = 900
# report.task_success = 700
# report.behavior = 650
# report.identity = 800
```

---

## Operational Playbook

### When score drops below tier threshold

1. **Standard → Probationary (below 500)**
   - Auto-restrict to read-only operations
   - Alert agent owner
   - Require manual review within 24h

2. **Probationary → Untrusted (below 300)**
   - Suspend all operations
   - Alert security team
   - Require investigation and re-registration

3. **Any tier → quarantine (anomaly detected)**
   - Immediate suspension via kill switch
   - Full audit trail export
   - Require manual reinstatement

### Score recovery

- After policy violation: score rebuilds at +10/day with clean compliance
- After quarantine: manual reinstatement sets score to 300 (probationary)
- After re-registration: starts at initial score for origin type

---

## Anti-Gaming Measures

- **Rate limiting on score changes**: max +50 points per day
- **Minimum observation period**: 7 days before tier promotion
- **Hard penalties**: violations cause immediate score drops, not gradual
- **Audit requirement**: all score changes are logged with reasons
- **No self-modification**: agents cannot modify their own trust scores
