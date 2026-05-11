# Contributing to Agent Governance Toolkit

This project welcomes contributions and suggestions. Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide a
CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

### Developer Certificate of Origin (DCO)

In addition to the CLA, all commits must include a `Signed-off-by` trailer certifying that you
wrote the code or have the right to submit it under the project's license. This is the
[Developer Certificate of Origin](https://developercertificate.org) (DCO).

To sign off on a commit, use the `-s` flag:

```bash
git commit -s -m "feat: add new policy engine"
```

This adds a line like `Signed-off-by: Your Name <your.email@example.com>` to the commit message.
A CI check will verify that all commits in a pull request include this trailer.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## How to Contribute

### Development Environment Setup

**Prerequisites:** Git, Python 3.10+, and optionally Node.js 18+, .NET 8+, Rust 1.75+, or Go 1.21+ depending on what you are working on.

```bash
# Clone and enter the repo
git clone https://github.com/microsoft/agent-governance-toolkit.git
cd agent-governance-toolkit
```

**Python packages** (most common):

```bash
cd agent-governance-python
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
# .venv\Scripts\activate         # Windows

# Install the package you are working on in editable mode
pip install -e agent-os/[dev]       # Policy engine
pip install -e agent-mesh/[dev]     # Identity/trust layer
pip install -e agent-compliance/[dev]  # Compliance tooling

# Run tests for that package
cd agent-os && pytest
```

**TypeScript/Node.js:**

```bash
cd agent-governance-python/agent-mesh/sdks/typescript
npm install && npm test
```

**.NET:**

```bash
cd agent-governance-dotnet
dotnet build && dotnet test
```

**Rust:**

```bash
cd agent-governance-rust
cargo build && cargo test
```

**Go:**

```bash
cd agent-governance-golang
go build ./... && go test ./...
```

**Linting:** The CI runs `ruff check` for Python. Run it locally before submitting:

```bash
ruff check --fix .
```

### Reporting Issues

- Search [existing issues](https://github.com/microsoft/agent-governance-toolkit/issues) before creating a new one
- Use the provided issue templates when available
- Include reproduction steps, expected behavior, and actual behavior

### Pull Requests

1. Fork the repository and create a feature branch from `main`
2. Read the nearest `AGENTS.md` before changing code in that area
3. Make your changes in the appropriate package or top-level directory for that part of the repo
4. Add or update tests as needed
5. Ensure all tests pass: `pytest`
6. Update documentation if your change affects public APIs
7. Submit a pull request with a clear description of the changes

### Repository Routing

This repo is a monorepo. Choosing the right path up front makes review much faster.
The layout is also evolving: some language implementations now use standalone top-level directories
at the repository root. For contributor routing, treat `agent-governance-dotnet/` as the canonical
.NET home and `agent-governance-golang/` as the matching sibling pattern for Go. Treat the paths
below as contributor-routing guidance rather than a promise that every legacy path remains the long-
term home for that language.

| If your change is about... | Start here |
|----------------------------|------------|
| Published first-party Python packages | `agent-governance-python/` |
| Core governance/runtime behavior and Python apps | the repo root |
| Current shared SDK implementations | `agent-governance-python/agent-mesh/sdks/` and other languages that still live in the shared layout |
| Standalone language implementations | `agent-governance-python/`, `agent-governance-dotnet/`, `agent-governance-golang/`, or other `agent-governance-*` siblings at the repository root |
| Tutorials, architecture, package docs | `docs/` |
| Runnable framework integrations | `examples/` |
| Interactive or live demos | `examples/demos/` |
| Azure DevOps publishing/release automation | `.github/pipelines/` |
| GitHub Actions, PR automation, templates | `.github/` |

If a directory contains an `AGENTS.md` file, read it before you start. It captures local
commands, boundaries, and review expectations for that area.
If a standalone top-level language directory exists for the implementation you are changing, prefer
that directory over an older shared path unless maintainers tell you to keep work in the legacy
location. For published Python package work, contributor guidance should point to
`agent-governance-python/` as the canonical path. For the standalone .NET SDK, use
`agent-governance-dotnet/`.

### Choose the Smallest Correct Surface

- Prefer a docs update when the request is informational.
- Prefer an `examples/` contribution when proving a new external integration.
- Prefer `agent-governance-python/agentmesh-integrations/` when the integration is reusable and maintained.
- Propose a core package change only when the functionality clearly belongs in AGT long-term.

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

### AI-Assisted Contributions

We welcome contributions that use AI development tools (copilots, agents, editors, code generators)
as part of the development process. AI tool usage is treated as part of a contributor's workflow,
comparable to editors, linters, or language servers. However, AI assistance does not reduce
contributor responsibility.

**Core principles:**

1. **Take responsibility.** You own every contribution you submit. "The AI wrote it" is not a
   defense for bugs, security issues, or attribution violations.
2. **Demonstrate understanding.** You must be able to explain every meaningful change: what it does,
   why it is designed that way, and what tradeoffs were considered. If you cannot walk through the
   change, it is not ready for review.
3. **Respect maintainer time.** AI has lowered the cost of producing contributions but not the cost
   of reviewing them. Ensure your submission is appropriately scoped, tested, and worth the review
   effort.

**Requirements for all AI-assisted contributions:**

- Run tests and verification appropriate for the change.
- Write commit messages that explain what the change does and why. AI-drafted commit messages are
  acceptable when the contributor has reviewed them and can stand by what they say.
- Keep PRs appropriately scoped. Avoid large automated refactors unless coordinated with maintainers.
- Verify that generated code and docs match the current repository state.
- Do not use AI to launder unattributed derivative work from other projects.
- Do not use AI to respond to review comments. Reviewers expect to engage with the human author.

**Disclosure:**

Disclosure of AI tool usage is not required by default. Disclosure **is** required in two cases:

1. **Autonomous contributions**: the contribution was produced and submitted by an AI agent acting
   independently without meaningful human direction or review of the specific output.
2. **Unreviewed AI-produced content**: the contributor is submitting AI-produced content they have
   not meaningfully reviewed and cannot fully explain.

In both cases, identify which parts of the submission fall into these categories so reviewers can
adjust their review accordingly.

**Autonomous contributions are not accepted by default.** All contributions must have a responsible
human who directed the work and can explain and defend it. The following autonomous agent behaviors
are not acceptable:

- Agents opening pull requests without a human reviewing the specific changes before submission
- Agents filing bug reports or feature requests without a human verifying the issue is genuine
- Agents claiming issues (especially "good first issue") without a human intending to follow through
- Agents posting unsolicited code review feedback on others' pull requests
- Agents responding in issue or discussion threads without human oversight of the response

A human using an AI tool to *draft* any of the above, then reviewing, editing, and submitting
the output themselves, is an AI-assisted contribution and is acceptable.

Authorized bots (Dependabot, Scorecard, CI bots) that predate this policy are governed by their
own approval processes and are not subject to these restrictions. For the full list of authorized
bots and how to request authorization for new ones, see
[docs/policies/autonomous-contributions.md](docs/policies/autonomous-contributions.md).

**Do not use AI tools to generate synthetic community activity**: filing coordinated issues across
repos, creating competing projects from existing issue descriptions, or manufacturing the appearance
of community adoption. This violates the trust that open-source collaboration depends on.

**Security considerations:**

Contributions that touch security-sensitive areas (cryptographic implementations, authentication
logic, input validation, policy enforcement, supply chain tooling) receive heightened review
regardless of how they were produced. For AI-assisted changes to security-critical code:

- Verify that AI-generated tests are not merely testing the AI-generated implementation against
  itself. Independent validation is required.
- Do not include secrets, credentials, or sensitive data in AI tool prompts.
- Review AI output for hallucinated package names, deprecated crypto algorithms, or insecure
  defaults.

For detailed checklists and additional requirements, see
[docs/policies/ai-security-guidance.md](docs/policies/ai-security-guidance.md).

**Legal obligations:**

Contributors using AI development tools must ensure that the tool's terms of service do not conflict
with the MIT License, and that AI-generated output does not contain copyrighted third-party code
incompatible with the project's license. When in doubt, review AI output for copied or closely
adapted snippets and note the source in the PR description.

### IP, Patents, and Licensing

- All contributions must be made under the **MIT License** via our standard CLA process.
- **No patent-encumbered code.** If your contribution implements techniques covered by a pending or granted patent, disclose this in the PR description. We cannot accept code that would encumber AGT users.
- **No NDA-gated contributions.** If understanding your contribution requires signing an NDA, it is not suitable for this open-source project.
- **No side agreements.** Licensing arrangements, partnership proposals, or "formal engagement" discussions should be directed to agentgovtoolkit@microsoft.com, not embedded in code contributions.

### External Integrations and Related Projects

We welcome integrations, but we review them as product decisions, not just code submissions.

- If you are proposing support for your own project, explain why AGT users benefit from it.
- Start with the smallest useful contribution shape: docs mention, example, integration package,
  then core-package change.
- Include adoption context when requesting a large integration surface. Small or brand-new projects
  are usually better introduced through examples than through core dependencies.
- New dependencies must be justified, pinned correctly, and appropriate for the part of the repo
  they are entering.
- "Related project" PRs may be closed if they read primarily as promotion rather than user value.

When in doubt, open an issue or discussion first and describe:

1. the user problem
2. the external project involved
3. why the change belongs in AGT
4. whether the first version can live in docs or examples

### Development Setup

```bash
# Clone the repository
git clone https://github.com/microsoft/agent-governance-toolkit.git
cd agent-governance-toolkit

# Install in development mode
pip install -e "agent-governance-python/agent-primitives[dev]"
pip install -e "agent-governance-python/agent-mcp-governance[dev]"
pip install -e "agent-os[dev]"
pip install -e "agent-mesh[dev]"
pip install -e "agent-runtime[dev]"
pip install -e "agent-sre[dev]"
pip install -e "agent-compliance[dev]"
pip install -e "agent-marketplace[dev]"  # installs agentmesh-marketplace
pip install -e "agent-lightning[dev]"
pip install -e "agent-hypervisor[dev]"
pip install -e "agentmesh-integrations[dev]"

# Restore the standalone .NET SDK when working in that path
dotnet restore agent-governance-dotnet/AgentGovernance.sln

# Run tests
pytest
```

### Docker Quickstart

If you prefer a containerized development environment, use the root Docker
configuration. The image includes Python 3.11, Node.js 22, the core editable
Python packages in this monorepo, and the TypeScript SDK dependencies.

```bash
# Build and start the development container
docker compose up --build dev -d

# Run the full test suite
docker compose run --rm test
```

To access the container and run commands interactively, use the following command:

```bash
# Open a shell in the running container
docker compose exec dev bash
```

The repository is bind-mounted into `/workspace`, so Python source changes are
available immediately without rebuilding the image. If you update package
metadata or dependency definitions, rebuild with `docker compose build`.

To launch the optional Agent Hypervisor dashboard:

```bash
docker compose --profile dashboard up --build dashboard
```

### Pre-push checklist (recommended)

Run these before pushing a PR. Each step catches a different class of bug
and has a different cycle-time cost.

**Local prerequisites:**

- **Python 3.10+** (CI tests on 3.10, 3.11, 3.12, and 3.13)
- **pytest** — `pip install pytest` (or install the package's dev extras)
- **ruff** — `pip install ruff==0.12.4` (matches `agent-governance-python/requirements/ci-lint.txt`)
- **Docker** with Compose v2 — required for step 3
- For a given package, run `pip install -e .` from inside the package
  directory before its first `pytest`. Sibling packages (e.g.
  `agent-mesh`) may also need to be installed when their canonical
  modules are imported by the package under test. Step 3's Docker flow
  handles this automatically.

1. **Inner loop — test the package you changed:**

   ```bash
   cd agent-governance-python/<package>
   pytest tests/ -q
   ```

   *Cycle time: seconds. Catches: the bug you just wrote.*

2. **Inner loop — lint the package you changed:**

   ```bash
   ruff check agent-governance-python/<package>/src --select E,F,W --ignore E501
   ```

   *Cycle time: seconds. Catches: lint failures CI would flag.*

3. **Pre-push integration — run the full Docker test suite:**

   ```bash
   docker compose up --build dev -d
   docker compose run --rm test
   ```

   *Cycle time: ~3 min cold, ~30 s warm. **This catches integration bugs
   that per-package tests cannot see**, including shim/canonical drift,
   sibling-package conflicts, Dockerfile drift, and line-ending issues.
   This is the same flow CI gates on (`docker-compose-test` job).*

4. **Push and let CI handle the rest** — multi-version Python, .NET,
   TypeScript, Rust, Go, lint, build, security scanners, supply-chain
   audits. Don't try to replicate all of CI locally.

### Package Structure

This repo includes these core packages and standalone SDKs today:

| Package | Directory | Description |
|---------|-----------|-------------|
| `agent-os-kernel` | `agent-governance-python/agent-os/` | Kernel architecture for policy enforcement |
| `agentmesh` | `agent-governance-python/agent-mesh/` | Inter-agent trust and identity mesh |
| `agentmesh-runtime` | `agent-governance-python/agent-runtime/` | Runtime sandboxing and capability isolation |
| `agent-sre` | `agent-governance-python/agent-sre/` | Observability, alerting, and reliability |
| `agent-governance` | `agent-governance-python/agent-compliance/` | Unified installer and runtime policy enforcement |
| `agentmesh-marketplace` | `agent-governance-python/agent-marketplace/` | Plugin lifecycle management for governed agent ecosystems |
| `agentmesh-lightning` | `agent-governance-python/agent-lightning/` | RL training governance with governed runners and policy rewards |
| `agent-hypervisor` | `agent-governance-python/agent-hypervisor/` | Runtime infrastructure and capability management |
| `agent-primitives` | `agent-governance-python/agent-primitives/` | Shared foundational Python primitives package |
| `agent-mcp-governance` | `agent-governance-python/agent-mcp-governance/` | Published MCP governance facade for Python consumers |
| `agent-governance-dotnet` | `agent-governance-dotnet/` | Standalone .NET SDK for agent governance |
| `agentmesh-integrations` | `agent-governance-python/agentmesh-integrations/` | Framework integrations and extension library |

Contributor routing for first-party published Python packages should use `agent-governance-python/`
at the repository root as the canonical path. The standalone .NET SDK should use
`agent-governance-dotnet/`.

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
cd <package-name>
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

Each integration is a standalone package under `agent-governance-python/agentmesh-integrations/`:

```
agent-governance-python/agentmesh-integrations/your-integration/
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

See `agent-governance-python/agentmesh-integrations/langchain-agentmesh/` for the best reference implementation.

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
- [ ] Tests pass: `pytest your-integration/tests/`
- [ ] Code follows PEP 8 and uses type hints
- [ ] No secrets or credentials committed
- [ ] Dependencies are pinned to specific versions
- [ ] Prior art and related projects are credited in the PR description
- [ ] The contribution shape is appropriate (example vs integration package vs core package)

### Questions?

- Review existing integrations in `agent-governance-python/agentmesh-integrations/`
- Open a [discussion](https://github.com/microsoft/agent-governance-toolkit/discussions) for design questions
- Tag `@microsoft/agent-governance-team` for integration review

## Data Model Conventions

- **`@dataclass`** — Use for internal value objects that don't cross serialization boundaries (policy rules, evaluation results, internal state).
- **`pydantic.BaseModel`** — Use for models that cross serialization boundaries (API request/response models, configs loaded from YAML/JSON, manifests).
- **Don't mix** — within a single module, use one pattern consistently.
