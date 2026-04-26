# Agent-SRE — Coding Agent Instructions

## Project Overview

Agent-SRE is an **SRE toolkit for AI agent reliability** — providing SLO management, error budgets, chaos engineering, progressive delivery, cost guardrails, incident management, and observability for autonomous AI agents.

**Key engines:**

- **SLO Engine:** Define and track Service Level Objectives for agent operations
- **Error Budget Engine:** SRE-style reliability tracking with burn rate alerts
- **Chaos Engine:** Fault injection and resilience testing for agents
- **Cost Guard:** Token/API cost tracking and budget enforcement
- **Progressive Delivery:** Canary deployments, A/B testing for agent versions
- **Incident Manager:** Automated incident detection, classification, and response
- **Replay Engine:** Capture and replay agent execution traces
- **Tracing:** OpenTelemetry semantic conventions for AI agents

## Build & Test Commands

```bash
# Install dependencies (development mode)
pip install -e ".[dev]"

# Run all tests
pytest tests/

# Run tests with coverage
pytest tests/ --cov=src/agent_sre --cov-report=html

# Type checking
mypy src/

# Lint and format
ruff check .
ruff format .
```

## Code Style

- **Linter:** Ruff (line-length: 100, rules: E, F, W, I, N, UP, B, SIM, TCH)
- **Type checker:** MyPy strict mode (Python 3.10)
- **Python:** >=3.10
- **Docstrings:** Google-style

## Key Files

| File | Purpose |
|------|---------|
| `src/agent_sre/slo/` | SLO definitions, tracking, burn rate calculation |
| `src/agent_sre/cost/` | Cost guardrails, token budget tracking |
| `src/agent_sre/chaos/` | Chaos experiments, fault injection |
| `src/agent_sre/delivery/` | Canary/progressive delivery |
| `src/agent_sre/incidents/` | Incident detection and response |
| `src/agent_sre/replay/` | Trace capture and replay |
| `src/agent_sre/tracing/` | OpenTelemetry agent conventions |
| `src/agent_sre/alerts/` | Alert rules and notifications |
| `src/agent_sre/fleet/` | Fleet-wide agent management |
| `src/agent_sre/certification/` | Agent certification framework |
| `deployments/` | Helm charts, Kubernetes manifests |
| `operator/` | Kubernetes operator for agent-sre |

## Coding Conventions

- Error budgets: pure SRE math — availability windows, burn rates, exhaustion forecasting
- SLOs: YAML/TOML definitions, version-controlled
- OTEL conventions: custom attributes like `agent.did`, `agent.trust_score`, `agent.task.success`
- Span kinds: `AGENT_TASK`, `TOOL_CALL`, `LLM_INFERENCE`, `DELEGATION`, `POLICY_CHECK`
- All metrics follow Prometheus naming conventions
- Use `dataclass` or Pydantic `BaseModel` for structured data

## Boundaries

- **Never commit** secrets, API keys, or cloud credentials
- **Never modify** deployment configs without testing locally first
- **Never lower** SLO targets — only raise them
- Keep backward compatibility with existing metric names and OTEL attributes

## Testing Requirements

- All new features must include tests
- Run `pytest tests/` before committing
- Use `pytest-asyncio` for async tests (asyncio_mode = "auto")

## Commit Style

Use conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`
