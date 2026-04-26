# AgentMesh — Coding Agent Instructions

## Project Overview

AgentMesh is a **trust-first communication layer for AI agents** — providing cryptographic identity, multi-dimensional trust scoring, scope chains, and governance enforcement for multi-agent systems.

**Architecture:** 4-layer trust stack

- **Layer 1 (Identity):** Ed25519 agent identity, DID (did:mesh:xxx), AI Card integration
- **Layer 2 (Trust):** 5-dimension trust scoring, trust decay, handshake protocol, bridges
- **Layer 3 (Governance):** Policy enforcement, compliance, hash chain audit chains
- **Layer 4 (Reward):** Reputation tracking, reward distribution

## Build & Test Commands

```bash
# Install dependencies (development mode)
pip install -e ".[dev]"

# Run all tests
pytest tests/ -v

# Run tests with coverage
pytest tests/ --cov=src/agentmesh --cov-report=html

# Type checking
mypy src/

# Lint and format
ruff check .
ruff format .

# Or use Black (also configured)
black --check .
```

## Code Style

- **Formatter:** Black (line-length: 100, target: py311)
- **Linter:** Ruff (line-length: 100, rules: E, F, I, N, W, UP)
- **Type checker:** MyPy strict mode
- **Python:** >=3.11
- **Docstrings:** Google-style

## Key Files

| File | Purpose |
|------|---------|
| `src/agentmesh/identity/` | AgentIdentity, AgentDID, Ed25519 key management |
| `src/agentmesh/trust/` | TrustScore (5 dimensions), TrustHandshake, TrustBridge |
| `src/agentmesh/governance/` | Policy enforcement, compliance checking |
| `src/agentmesh/integrations/ai_card/` | AI Card standard adapter (schema, discovery) |
| `src/agentmesh/integrations/a2a/` | A2A protocol integration (wraps AICard) |
| `src/agentmesh/services/` | Backend services |
| `src/agentmesh/cli/` | CLI commands |
| `packages/` | External packages (langchain-agentmesh, mcp-proxy) |

## Coding Conventions

- All data models use Pydantic `BaseModel`
- Identity: `AgentIdentity` with `.sign(data: bytes) -> str` (base64 Ed25519 signatures)
- Trust scores: 5 dimensions — competence, integrity, availability, predictability, transparency
- DID format: `did:mesh:{hex}` — derived from public key
- Private keys stored as `_private_key` (never serialized)
- AICard: `from_identity()` creates signed cards; `from_trusted_agent_card()` bridges existing formats
- Tests in `tests/` directory

## Boundaries

- **Never serialize** private keys in JSON/YAML output
- **Never commit** secrets, API keys, or credentials
- **Never weaken** trust thresholds — only tighten
- Keep backward compatibility with existing protocol messages
- `packages/` are standalone — changes there need their own test suite

## Testing Requirements

- All new features must include tests
- Run `pytest tests/ -v` before committing
- Use `pytest-asyncio` for async tests (asyncio_mode = "auto")

## Commit Style

Use conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`
