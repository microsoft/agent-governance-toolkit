# Contributing to Agent Governance Toolkit

This project welcomes contributions and suggestions. Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide a
CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## How to Contribute

### Reporting Issues

- Search [existing issues](https://github.com/microsoft/agent-governance-toolkit/issues) before creating a new one
- Use the provided issue templates when available
- Include reproduction steps, expected behavior, and actual behavior

### Pull Requests

1. Fork the repository and create a feature branch from `main`
2. Make your changes in the appropriate package directory under `packages/`
3. Add or update tests as needed
4. Ensure all tests pass: `pytest`
5. Update documentation if your change affects public APIs
6. Submit a pull request with a clear description of the changes

### Attribution & Prior Art

**All contributions must properly attribute prior work.** This is a hard requirement, not a suggestion.

- If your contribution implements functionality similar to an existing open-source project, you **must** credit that project in your PR description and in code comments or documentation where the pattern is used.
- Copying or closely adapting architecture, API design, CLI conventions, or documentation from another project without attribution is not acceptable, even if the code is rewritten.
- When in doubt, cite the prior art. Over-attribution is always better than under-attribution.
- PRs found to contain uncredited derivatives of other open-source work will be closed.

**Examples of what requires attribution:**
- Adapting a sandboxing approach from another security tool
- Using an algorithm or protocol design described in another project's docs
- Mirroring CLI flags, config schema, or architectural patterns from a known project

**How to attribute:**
- In your PR description: list related projects under "Prior art / related projects"
- In code: add a comment like `# Approach adapted from <project> (<license>)`
- In documentation: include a "Prior art" or "Acknowledgments" section

### Development Setup

```bash
# Clone the repository
git clone https://github.com/microsoft/agent-governance-toolkit.git
cd agent-governance-toolkit

# Install in development mode
pip install -e "packages/agent-os[dev]"
pip install -e "packages/agent-mesh[dev]"
pip install -e "packages/agent-runtime[dev]"
pip install -e "packages/agent-sre[dev]"
pip install -e "packages/agent-compliance[dev]"
pip install -e "packages/agent-marketplace[dev]"  # installs agentmesh-marketplace
pip install -e "packages/agent-lightning[dev]"
pip install -e "packages/agent-hypervisor[dev]"
pip install -e "packages/agent-governance-dotnet[dev]"
pip install -e "packages/agentmesh-integrations[dev]"

# Run tests
pytest
```

### Docker Quickstart

If you prefer a containerized development environment, use the root Docker
configuration. The image includes Python 3.11, Node.js 22, the core editable
Python packages in this monorepo, and the TypeScript SDK dependencies.

```bash
# Build and start the development container
docker compose up --build dev

# Open a shell in the running container
docker compose exec dev bash

# Run the full test suite
docker compose run --rm test
```

The repository is bind-mounted into `/workspace`, so Python source changes are
available immediately without rebuilding the image. If you update package
metadata or dependency definitions, rebuild with `docker compose build`.

To launch the optional Agent Hypervisor dashboard:

```bash
docker compose --profile dashboard up --build dashboard
```

### Package Structure

This is a mono-repo with ten packages:

| Package | Directory | Description |
|---------|-----------|-------------|
| `agent-os-kernel` | `packages/agent-os/` | Kernel architecture for policy enforcement |
| `agentmesh` | `packages/agent-mesh/` | Inter-agent trust and identity mesh |
| `agentmesh-runtime` | `packages/agent-runtime/` | Runtime sandboxing and capability isolation |
| `agent-sre` | `packages/agent-sre/` | Observability, alerting, and reliability |
| `agent-governance` | `packages/agent-compliance/` | Unified installer and runtime policy enforcement |
| `agentmesh-marketplace` | `packages/agent-marketplace/` | Plugin lifecycle management for governed agent ecosystems |
| `agentmesh-lightning` | `packages/agent-lightning/` | RL training governance with governed runners and policy rewards |
| `agent-hypervisor` | `packages/agent-hypervisor/` | Runtime infrastructure and capability management |
| `agent-governance-dotnet` | `packages/agent-governance-dotnet/` | .NET framework integration for agent governance |
| `agentmesh-integrations` | `packages/agentmesh-integrations/` | Framework integrations and extension library |

### Coding Guidelines

- Follow [PEP 8](https://peps.python.org/pep-0008/) for Python code
- Use type hints for all public APIs
- Write docstrings for all public functions and classes
- Keep commits focused and use [conventional commit](https://www.conventionalcommits.org/) messages

### Testing Policy

All contributions that add or change functionality **must** include corresponding tests:

- **New features** — Add unit tests covering the primary use case and at least one edge case.
- **Bug fixes** — Add a regression test that reproduces the bug before the fix.
- **Security patches** — Add tests verifying the vulnerability is mitigated.

Tests are run automatically via CI on every pull request. The test matrix covers
Python 3.10–3.12 across all four core packages. PRs will not be merged until
all required CI checks pass.

Run tests locally with:

```bash
cd packages/<package-name>
pytest tests/ -x -q
```

### Security

- Review the [SECURITY.md](SECURITY.md) file for vulnerability reporting procedures.
- **Security scanning runs automatically** on all PRs — see [docs/security-scanning.md](docs/security-scanning.md) for details
- Use `.security-exemptions.json` to suppress false positives (requires justification)
- Never commit secrets, credentials, or tokens.
- Use `--no-cache-dir` for pip installs in Dockerfiles.
- Pin dependencies to specific versions in `pyproject.toml`.

### Merge Policy

> **All PRs from external contributors MUST be approved by a maintainer before merge.**
> AI-only approvals and bot approvals do NOT satisfy this requirement.

This policy is enforced by:
1. **CODEOWNERS** — every file requires review from `@microsoft/agent-governance-toolkit`
2. **`require-maintainer-approval.yml`** — CI check that blocks merge without human maintainer approval
3. **Branch protection** — CODEOWNERS review required on `main`

**Why this policy exists:** PRs #357 and #362 were auto-merged without maintainer review and reintroduced a command injection vulnerability (`subprocess.run(shell=True)`) that had been fixed for MSRC Case 111178 just days earlier. AI code review agents did not catch the security regression.

**What counts as maintainer approval:**
- ✅ A GitHub "Approve" review from a listed CODEOWNER
- ❌ AI/bot approval (Copilot, Sourcery, etc.) — does not count
- ❌ Author self-approval — does not count
- ❌ Admin bypass — should not be used for external PRs

**Security-sensitive paths** (extra scrutiny required):
- `.github/workflows/` and `.github/actions/` — CI/CD configuration
- Any file containing `subprocess`, `eval`, `exec`, `pickle`, `shell=True`
- Trust, identity, and cryptography modules

## Licensing

By contributing to this project, you agree that your contributions will be licensed under the [MIT License](LICENSE).

## Integration Author Guide

This guide walks you through creating a new framework integration for Agent Governance Toolkit — from scaffolding to testing to publishing.

### Integration Package Structure

Each integration is a standalone package under `packages/agentmesh-integrations/`:

```
packages/agentmesh-integrations/your-integration/
├── pyproject.toml          # Package metadata and dependencies
├── README.md               # Documentation with quick start
├── LICENSE                 # MIT License
├── your_integration/       # Source code
│   ├── __init__.py
│   └── ...
└── tests/                  # Test suite
    ├── __init__.py
    └── test_your_integration.py
```

### Key Interfaces to Implement

1. **VerificationIdentity**: Cryptographic identity for agents
2. **TrustGatedTool**: Wrap tools with trust requirements
3. **TrustedToolExecutor**: Execute tools with verification
4. **TrustCallbackHandler**: Monitor trust events

See `packages/agentmesh-integrations/langchain-agentmesh/` for the best reference implementation.

### Writing Tests

- Mock external API calls and I/O operations
- Use existing fixtures from `conftest.py` if available
- Cover primary use cases and edge cases
- Include integration tests for trust verification flows

Example test pattern:

```python
def test_trust_gated_tool():
    identity = VerificationIdentity.generate('test-agent')
    tool = TrustGatedTool(mock_tool, required_capabilities=['test'])
    executor = TrustedToolExecutor(identity=identity)
    result = executor.invoke(tool, 'input')
    assert result is not None
```

### Optional Dependency Pattern

Implement graceful fallback when dependencies are not installed:

```python
try:
    import langchain_core
except ImportError:
    raise ImportError(
        "langchain-core is required. Install with: "
        "pip install your-integration[langchain]"
    )
```

### PR Readiness Checklist

Before submitting your integration PR:

- [ ] Package follows the structure outlined above
- [ ] `pyproject.toml` includes proper metadata (name, version, description, author)
- [ ] README.md includes installation instructions and quick start
- [ ] All public APIs have docstrings
- [ ] Tests pass: `pytest packages/your-integration/tests/`
- [ ] Code follows PEP 8 and uses type hints
- [ ] No secrets or credentials committed
- [ ] Dependencies are pinned to specific versions

### Questions?

- Review existing integrations in `packages/agentmesh-integrations/`
- Open a [discussion](https://github.com/microsoft/agent-governance-toolkit/discussions) for design questions
- Tag `@microsoft/agent-governance-team` for integration review

## Data Model Conventions

- **`@dataclass`** — Use for internal value objects that don't cross serialization boundaries (policy rules, evaluation results, internal state).
- **`pydantic.BaseModel`** — Use for models that cross serialization boundaries (API request/response models, configs loaded from YAML/JSON, manifests).
- **Don't mix** — within a single module, use one pattern consistently.