# Deployment Guide

## Installation

### From PyPI

```bash
pip install agent-sre
```

### From Source

```bash
git clone https://github.com/microsoft/agent-governance-toolkit.git
cd agent-sre
pip install -e .
```

### With Optional Dependencies

```bash
# OpenTelemetry support
pip install agent-sre[otel]

# All integrations
pip install agent-sre[all]
```

---

## Docker

### Quick Demo

```bash
docker compose up quickstart
```

### All Examples

```bash
docker compose up
```

### Custom Dockerfile

```dockerfile
FROM python:3.12-slim
RUN pip install agent-sre
COPY your_agent.py .
CMD ["python", "your_agent.py"]
```

---

## Integration Patterns

### 1. Library Embedding (Recommended)

Agent-SRE is a Python library, not a separate service. Embed it directly in your agent code:

```python
from agent_sre import SLO, ErrorBudget
from agent_sre.slo.indicators import TaskSuccessRate, CostPerTask

# Create SLO alongside your agent
slo = SLO(
    name="my-agent",
    indicators=[TaskSuccessRate(target=0.95), CostPerTask(target_usd=0.50)],
    error_budget=ErrorBudget(total=0.05),
)

# After each task
slo.indicators[0].record_task(success=True)
slo.record_event(good=True)
```

### 2. LangChain Integration

```python
from agent_sre.integrations.langchain.callback import AgentSRECallback

callback = AgentSRECallback()

# Pass to LangChain
chain.invoke({"query": "..."}, config={"callbacks": [callback]})

# Get SLI snapshot
snapshot = callback.get_sli_snapshot()
```

### 3. OpenTelemetry Export

```python
from agent_sre.integrations.otel import OTELExporter

exporter = OTELExporter(service_name="my-agent")
exporter.export_slo(slo)  # Sends spans to your OTEL collector
```

### 4. Webhook Alerting

```python
from agent_sre.alerts import AlertManager, ChannelConfig, AlertChannel, Alert, AlertSeverity

manager = AlertManager()
manager.add_channel(ChannelConfig(
    channel_type=AlertChannel.SLACK,
    name="ops",
    url="https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
))

# Send alert on SLO breach
if slo.error_budget.is_exhausted:
    manager.send(Alert(
        title="SLO Breach",
        message=f"Error budget exhausted for {slo.name}",
        severity=AlertSeverity.CRITICAL,
    ))
```

### 5. MCP Drift Monitoring

```python
from agent_sre.integrations.mcp import DriftDetector, ToolSnapshot, ToolSchema

detector = DriftDetector()

# Record baseline from your MCP server
detector.set_baseline(ToolSnapshot(
    server_id="my-mcp-server",
    tools=[ToolSchema(name="search", parameters={"q": {"type": "string"}})],
))

# Periodically check for drift
report = detector.compare(current_snapshot)
if report.has_drift:
    for alert in report.alerts:
        print(f"[{alert.severity.value}] {alert.message}")
```

---

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `AGENT_SRE_LOG_LEVEL` | Logging level | `INFO` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTEL collector endpoint | `http://localhost:4317` |
| `OTEL_SERVICE_NAME` | Service name for traces | `agent-sre` |

---

## Production Checklist

- [ ] Define SLOs for each agent with domain-appropriate targets
- [ ] Set cost guardrails with per-task and daily limits
- [ ] Configure webhook alerting for SLO breaches
- [ ] Enable MCP drift detection for all MCP servers
- [ ] Set up LLM-as-Judge evaluation for correctness/hallucination
- [ ] Run chaos experiments before deploying new agent versions
- [ ] Use staged rollouts for agent version updates
- [ ] Export metrics to your observability platform (OTEL, Langfuse, Arize)

---

## Architecture

```
Your Agent Code
    │
    ├── agent_sre.SLO          → Define reliability targets
    ├── agent_sre.CostGuard    → Prevent cost explosions  
    ├── agent_sre.evals        → LLM-as-Judge evaluation
    ├── agent_sre.alerts       → Webhook alerting
    │
    ├── Integrations
    │   ├── LangChain callback → Automatic SLI collection
    │   ├── OTEL exporter      → Send to Grafana/Datadog/etc.
    │   ├── Langfuse exporter  → LLM observability platform
    │   ├── Arize/Phoenix      → Evaluation import/export
    │   └── MCP drift          → Tool schema monitoring
    │
    └── Ecosystem
        ├── Agent OS           → Policy enforcement
        └── AgentMesh          → Identity & trust
```
