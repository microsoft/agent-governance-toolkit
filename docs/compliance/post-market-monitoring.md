<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Post-Market Monitoring and Incident Reporting

> **Purpose**: Define post-deployment monitoring capabilities for AI agent systems
> and incident reporting procedures as required by EU AI Act Articles 72 and 62.
>
> **Deadline**: EU AI Act provisions apply from **August 2, 2026**.

---

## 1. Post-Market Monitoring Plan

### 1.1 Overview

EU AI Act Article 72 requires providers of high-risk AI systems to establish a
post-market monitoring system that actively and systematically collects, documents,
and analyzes relevant data throughout the lifetime of the AI system.

AGT provides the technical infrastructure for this through:

| Requirement | AGT Capability | Module |
|------------|---------------|--------|
| **Performance monitoring** | OTel spans + metrics | `enable_otel()`, `trace_policy_evaluation()` |
| **Decision logging** | Tamper-evident audit trail | `AuditLog`, `AuditChain` |
| **Anomaly detection** | Policy denial rate monitoring | `agt.policy.denials` metric |
| **Bias monitoring** | Advisory classifiers | `CallbackAdvisory` with fairness model |
| **Incident detection** | Kill switch, circuit breaker | `agent_os.circuit_breaker` |
| **Trend analysis** | OTel metric aggregation | Grafana/Azure Monitor dashboards |

### 1.2 Monitoring Dimensions

| Dimension | What to Monitor | AGT Data Source | Alert Threshold |
|-----------|----------------|-----------------|-----------------|
| **Policy effectiveness** | Denial rate per rule | `agt.policy.denials` counter | Sudden spike (> 2x baseline) |
| **Trust degradation** | Agent trust scores over time | `agt.trust.score` gauge | Score drops below tier threshold |
| **Approval patterns** | Approval/rejection ratios | `agt.approval.requests` counter | Rejection rate > 50% |
| **Latency** | Policy evaluation latency | `agt.policy.latency_ms` histogram | P99 > 5ms |
| **Error rate** | Governance errors/exceptions | OTel error spans | Any non-zero count |
| **Data sensitivity** | Session attribute ratchets | `SessionState` values | Restricted-level reached |
| **Advisory triggers** | Classifier block/flag count | `advisory_check` audit entries | Increasing trend |

### 1.3 Recommended Dashboard

```
┌──────────────────────────────────────────────────────────┐
│ AGT Post-Market Monitoring Dashboard                      │
├──────────────────┬──────────────────┬────────────────────┤
│ Policy Denials   │ Trust Scores     │ Approval Rate      │
│ (last 24h)       │ (distribution)   │ (last 7d)          │
│ ▃▅▇▅▃▂▁▂▃▄      │ ░░▓▓▓▓▓░░░       │ 78% approved       │
├──────────────────┼──────────────────┼────────────────────┤
│ Eval Latency P99 │ Advisory Blocks  │ Active Agents      │
│ 0.08ms           │ 3 (last 24h)     │ 147                │
├──────────────────┴──────────────────┴────────────────────┤
│ Recent Incidents: 0 P0, 0 P1, 2 P2, 5 P3 (last 30d)    │
└──────────────────────────────────────────────────────────┘
```

### 1.4 PromQL Queries for Monitoring

```promql
# Denial rate by rule (anomaly detection)
sum(rate(agt_policy_denials_total[1h])) by (agt_policy_rule)

# Trust score distribution
histogram_quantile(0.5, agt_trust_score_bucket)

# Approval rejection rate
sum(rate(agt_approval_requests_total{agt_approval_outcome="rejected"}[24h]))
/ sum(rate(agt_approval_requests_total[24h]))

# Policy evaluation latency P99
histogram_quantile(0.99, rate(agt_policy_latency_ms_bucket[5m]))

# Advisory classifier trigger rate
sum(rate(advisory_check_total{outcome!="allow"}[24h]))
```

## 2. Serious Incident Reporting (Article 62)

### 2.1 What Constitutes a Serious Incident

Per EU AI Act Article 3(49), a serious incident is an incident or malfunctioning
of a high-risk AI system that directly or indirectly leads to:

- **Death** of a person or serious damage to health
- **Serious and irreversible disruption** of critical infrastructure management
- **Breach of obligations** under EU law intended to protect fundamental rights
- **Serious damage** to property or the environment

### 2.2 Reporting Timeline

| Event | Deadline |
|-------|----------|
| Serious incident discovered | Document immediately |
| Initial report to market surveillance authority | **Within 15 days** of becoming aware |
| Updated report (if investigation ongoing) | As new information becomes available |
| Final report | When investigation concludes |

### 2.3 Report Content (Article 62(2))

| Field | Description | AGT Source |
|-------|------------|-----------|
| AI system identification | Name, version, DID | `AgentIdentity`, deployment records |
| Provider/deployer information | Contact details | Organizational records |
| Date and circumstances | When and how the incident occurred | `AuditLog.query(start_time=..., end_time=...)` |
| Description of non-compliance | What went wrong | `PolicyDecision` chain, incident investigation |
| Corrective actions taken | What was done to remediate | Post-mortem actions |
| Impact assessment | Who was affected and how | FRIA update |

### 2.4 AGT Evidence for Incident Reports

```python
from agentmesh.governance import AuditLog
from datetime import datetime, timezone, timedelta

audit = AuditLog()  # existing audit log

# Pull all events around the incident window
incident_start = datetime(2026, 7, 15, 10, 0, tzinfo=timezone.utc)
incident_end = incident_start + timedelta(hours=2)

events = audit.query(
    agent_did="did:agentmesh:affected-agent",
    start_time=incident_start,
    end_time=incident_end,
)

# Export for regulatory report
for event in events:
    print(f"{event.timestamp} | {event.event_type} | {event.action} | {event.outcome}")
    print(f"  Data: {event.data}")
```

## 3. Implementation Checklist

### Before Deployment
- [ ] Post-market monitoring plan documented
- [ ] OTel observability enabled (`enable_otel()`)
- [ ] Alert thresholds configured
- [ ] Incident response workflow linked ([incident-response-workflow.md](incident-response-workflow.md))
- [ ] FRIA completed ([fria-template.md](fria-template.md))

### During Operation
- [ ] Dashboard reviewed weekly (or per monitoring plan)
- [ ] Denial rate trends analyzed monthly
- [ ] Trust score distributions reviewed quarterly
- [ ] Advisory classifier effectiveness assessed quarterly

### On Incident
- [ ] Follow [incident response workflow](incident-response-workflow.md)
- [ ] Preserve audit logs (hash-chained, tamper-evident)
- [ ] Assess if serious incident per Article 62 criteria
- [ ] Report to market surveillance authority within 15 days if applicable
- [ ] Update FRIA if risks have changed

---

> **Related**: [FRIA Template](fria-template.md) · [Incident Response Workflow](incident-response-workflow.md) · [Record Retention Policy](record-retention-policy.md) · [EU AI Act Checklist](eu-ai-act-checklist.md) · [Tutorial 40 — OTel Observability](../tutorials/40-otel-observability.md)
