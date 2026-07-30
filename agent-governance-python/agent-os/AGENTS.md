# Agent-OS — Coding Agent Instructions

## Project Overview

Agent-OS is a **governance-first kernel for AI agents** — a Python framework providing policy enforcement, semantic intent classification, identity management, and execution control for autonomous AI agents.

**Architecture:** 4-layer modular kernel

- **Layer 1 (Primitives):** Core identity (CMVK), credentials (CaaS), execution memory (EMK)
- **Layer 2 (Infrastructure):** Inter-agent trust protocol (IATP), agent message bus (AMB), agent trust registry (ATR)
- **Layer 3 (Framework):** Control plane, observability, nexus orchestration
- **Layer 4 (Intelligence):** MCP kernel server

## Build & Test Commands

```bash
# Install dependencies (development mode)
pip install -e "../../agent-governance-python/agent-primitives[dev]"
pip install -e ".[dev]"

# Run all tests
pytest tests/ modules/*/tests -v --tb=short

# Run tests with coverage
pytest tests/ --cov=src/agent_os --cov-report=html --cov-branch

# Type checking
mypy src/

# Lint
ruff check .

# Format
ruff format .
```

## Code Style

- **Formatter/Linter:** Ruff (line-length: 100, target: Python 3.9+)
- **Rules:** E, W, F, I (isort), B (bugbear), C4, UP (pyupgrade)
- **Type checker:** MyPy strict mode with Pydantic plugin
- **Docstrings:** Google-style
- **Imports:** Sorted by isort via Ruff

## Key Files

| File | Purpose |
|------|---------|
| `src/agent_os/integrations/base.py` | Core governance — AgtRuntime, BaseIntegration, NativeAdapterRuntime, event hooks |
| `src/agent_os/integrations/profiling.py` | @profile_governance decorator |
| `src/agent_os/base_agent.py` | Base agent class with audit logging |
| `src/agent_os/stateless.py` | Stateless agent with optional Redis |
| `tests/test_integrations.py` | Main governance test suite |
| `modules/` | 14+ modular kernel components |

## Coding Conventions

- All public APIs must have type hints (`mypy --strict`)
- Use `dataclass` or Pydantic `BaseModel` for data structures
- Construct `AgtRuntime` from a native ACS manifest or `AgtManifest`.
- Keep per-session counters in `AdapterRuntimeSession`, not `AgtRuntime`.
- Event types: `GovernanceEventType.POLICY_CHECK`, `.POLICY_VIOLATION`, `.TOOL_CALL_BLOCKED`, `.CHECKPOINT_CREATED`
- Tests go in `tests/` (unit) or `modules/*/tests/` (module-specific)

## Native policy evaluation

Framework adapters route intervention points through `AdapterRuntimeSession` and
receive `PolicyEvaluation`. Raise the canonical
`PolicyViolationError.from_evaluation_result(result)` for denied or escalated
results. Hosts should surface `str(error)` and use
`error.evaluation_result.reason_code` for structured handling.

```python
from agent_os.exceptions import PolicyViolationError

result = session.evaluate_input(body=input_data)
if not result.is_allowed():
    raise PolicyViolationError.from_evaluation_result(result)
```

## Boundaries

- **Never modify** `tests/test_mcp_server.py` (known pre-existing failure, excluded from CI)
- **Never commit** secrets, API keys, or credentials
- **Never bypass** native ACS intervention points or weaken fail-closed behavior
- Keep host lifecycle controls separate from native policy evaluation

## Testing Requirements

- All new features must include tests
- Run `pytest tests/ -v --tb=short` before committing
- Minimum: test happy path + at least one edge case per feature
- Use `pytest-asyncio` for async tests (asyncio_mode = "auto")

## Commit Style

Use conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`
