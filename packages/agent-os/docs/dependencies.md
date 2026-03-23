# Dependency Rationale

Agent OS follows "Scale by Subtraction" - minimal dependencies for a lean kernel.

## Core Dependencies (1 dependency)

| Package | Version | Why Needed | Alternatives Considered |
|---------|---------|------------|------------------------|
| **pydantic** | >=2.0.0 | Type validation, schema enforcement, JSON serialization | dataclasses (lacks validation), attrs (less ecosystem) |

**Total core deps: 1** (matches our "kernel should be lean" philosophy)

## Optional Dependencies by Layer

### Layer 1: Primitives
- No additional dependencies (zero external deps)

### Layer 2: CMVK
| Package | Why Needed |
|---------|------------|
| numpy | Drift calculation, semantic similarity metrics |

### Layer 3: CaaS (Context-as-a-Service)
| Package | Why Needed |
|---------|------------|
| fastapi | REST API endpoints |
| uvicorn | ASGI server |
| pypdf | Document parsing |
| numpy | Vector operations |
| scikit-learn | ML-based context ranking |

### Layer 4: IATP (Inter-Agent Trust Protocol)
| Package | Why Needed |
|---------|------------|
| fastapi | Trust gateway API |
| uvicorn | ASGI server |
| httpx | Async HTTP for agent-to-agent comms |

### Layer 5: AMB (Agent Message Bus)
| Package | Why Needed |
|---------|------------|
| anyio | Async runtime abstraction |
| aiofiles | Async file I/O for durability |

### Layer 6: ATR (Agent Tool Registry)
| Package | Why Needed |
|---------|------------|
| docker | Container isolation for untrusted tools |

### Layer 7: Control Plane
- **Zero external dependencies** (by design)
- All kernel-space code uses only stdlib

### Layer 8: SCAK (Self-Correcting Agent Kernel)
| Package | Why Needed |
|---------|------------|
| pyyaml | Configuration parsing |

## Development Dependencies

| Package | Why Needed |
|---------|------------|
| pytest | Test framework |
| pytest-asyncio | Async test support |
| pytest-cov | Coverage reporting |
| mypy | Static type checking |
| ruff | Fast linting |
| black | Code formatting |

## Security Posture

### Known Vulnerabilities (as of 2026-01)
Run `pip-audit` to check current status:
```bash
pip-audit
```

### License Compatibility
All dependencies use MIT, BSD, or Apache 2.0 licenses (enterprise-friendly).

| Package | License |
|---------|---------|
| pydantic | MIT |
| numpy | BSD |
| fastapi | MIT |
| uvicorn | BSD |
| httpx | BSD |
| anyio | MIT |

### Dependency Minimization Strategy

1. **Kernel Space (0 deps)**: Control plane uses only Python stdlib
2. **User Space (optional)**: Features that need deps are optional extras
3. **No Transitive Bloat**: We pin major versions, not micro-deps
4. **Regular Audits**: Dependabot + pip-audit in CI

## Installing

```bash
# Minimal (just pydantic)
pip install agent-os-kernel

# With specific features
pip install agent-os-kernel[cmvk]      # + numpy
pip install agent-os-kernel[iatp]      # + fastapi, httpx
pip install agent-os-kernel[full]      # Everything

# Development
pip install agent-os-kernel[dev]       # + pytest, mypy, ruff
```

## Updating Dependencies

```bash
# Check for outdated packages
pip list --outdated

# Check for vulnerabilities
pip-audit

# Update all (dev environment)
pip install --upgrade -e ".[dev]"
```
