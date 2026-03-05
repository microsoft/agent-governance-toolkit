# Security Model

## Overview

Agent-SRE is a monitoring and reliability library — it observes agent behavior,
it does not control execution. This document describes the security boundaries,
threat model, and best practices.

---

## Threat Model

### What Agent-SRE Protects Against

| Threat | Protection | Component |
|---|---|---|
| **Cost explosion** | Per-task/daily/monthly budget limits with auto-throttle | Cost Guard |
| **Silent degradation** | SLO breach detection with error budgets | SLO Engine |
| **Cascade failure** | Circuit breakers on failure thresholds | Incident Manager |
| **Tool drift** | Schema fingerprinting detects MCP server changes | MCP Drift Detection |
| **Unsafe outputs** | LLM-as-Judge safety evaluation | Evaluation Engine |
| **Hallucination** | Rules-based + LLM-as-Judge hallucination detection | Evaluation Engine |
| **Uncontrolled deployment** | Staged rollouts with manual rollback | Progressive Delivery |

### What Agent-SRE Does NOT Protect Against

| Threat | Why | Mitigation |
|---|---|---|
| **Prompt injection** | Not an input filter | Use Agent OS policy enforcement |
| **Data exfiltration** | Observes, doesn't intercept | Use Agent OS kernel-level controls |
| **Identity spoofing** | No identity layer | Use AgentMesh for identity & trust |
| **Network attacks** | Library, not a service | Standard network security practices |
| **LLM model vulnerabilities** | Monitors outputs, not model internals | Model-level security tools |

---

## Security Boundaries

### Data Handling

- **No PII storage**: Agent-SRE stores metrics (floats, counts, timestamps), not user data
- **No network calls by default**: All processing is in-memory unless you configure:
  - Webhook alerting (outbound HTTPS to configured URLs)
  - OTEL export (outbound to configured collector)
  - Langfuse export (outbound to configured endpoint)
- **No external dependencies for core**: SLOs, cost guard, incidents work with zero network access

### Credential Management

- **Webhook URLs**: Store in environment variables, never in code
- **API tokens**: Use environment variables or secret managers
- **No credential storage**: Agent-SRE does not persist credentials

```python
import os
from agent_sre.alerts import AlertManager, ChannelConfig, AlertChannel

manager = AlertManager()
manager.add_channel(ChannelConfig(
    channel_type=AlertChannel.SLACK,
    name="ops",
    url=os.environ["SLACK_WEBHOOK_URL"],  # From environment
))
```

---

## Integration Security

### Agent OS Integration

When used with [Agent OS](https://github.com/microsoft/agent-governance-toolkit), policy violations are reported as SLI signals. Agent OS provides the enforcement; Agent-SRE provides the monitoring.

### AgentMesh Integration

When used with [AgentMesh](https://github.com/microsoft/agent-governance-toolkit), trust scores flow into SLIs. AgentMesh handles identity and authentication; Agent-SRE monitors reliability of the trust infrastructure.

### MCP Drift Detection

MCP drift detection works by comparing tool schema snapshots. It does NOT:
- Connect to MCP servers (you provide snapshots)
- Modify tool schemas
- Intercept tool calls

It DOES:
- Detect when schemas change between baseline and current
- Classify changes by severity (info/warning/critical)
- Alert when breaking changes are detected

---

## Attack Vectors & Mitigations

### 1. Metric Poisoning

**Threat**: An attacker records false SLI values to hide degradation.

**Mitigation**:
- Use immutable audit trails (Agent OS integration)
- Cross-validate with external observability (OTEL, Langfuse)
- Set up anomaly detection on SLI patterns

### 2. Alert Suppression

**Threat**: Disabling webhook alerting to hide SLO breaches.

**Mitigation**:
- Monitor alert channel health separately
- Use multiple independent channels
- Set up heartbeat checks for alert delivery

### 3. Budget Bypass

**Threat**: Circumventing cost guard limits.

**Mitigation**:
- Cost Guard auto-throttle is in-process; cannot be bypassed from outside
- Use `kill_switch_threshold` for hard stops
- Monitor `org_monthly_budget` independently

### 4. Evaluation Evasion

**Threat**: Crafting outputs that pass evaluation but are wrong.

**Mitigation**:
- Use multiple evaluation criteria (correctness + hallucination + safety)
- Implement LLM-as-Judge with stronger models than the agent
- Cross-validate with human evaluation on a sample

---

## Best Practices

1. **Defense in depth**: Use Agent-SRE (monitoring) + Agent OS (enforcement) + AgentMesh (identity) together
2. **Multiple alert channels**: Configure at least two independent channels
3. **Regular chaos testing**: Run chaos experiments to verify resilience
4. **Budget limits from day one**: Set cost guardrails before deploying any agent
5. **MCP drift monitoring**: Baseline all MCP servers and check on every deployment
6. **Evaluation on every task**: Run at least safety + hallucination checks on all agent outputs
