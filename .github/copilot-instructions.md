# Copilot Instructions for agent-governance-toolkit

## PR Merge Workflow

When merging PRs, follow this sequence for EACH PR (do not batch):

1. **Review** — run all mandatory checks below
2. **Update branch** — merge latest main into the PR branch (`update-branch` API or UI button)
3. **Approve pending workflows** — fork PRs may have `pull_request_target` workflows waiting for maintainer approval; approve them in the Actions tab
4. **Approve the PR** — submit an approving review
5. **Enable auto-merge** — set squash auto-merge so it merges once CI passes
6. **Move to next PR** — don't wait; auto-merge handles the rest

This prevents PRs from stacking in the merge queue behind stale branches.

## PR Review — Mandatory Before Merge

NEVER merge a PR without thorough code review. CI passing is NOT sufficient.

Before approving or merging ANY PR, verify ALL of the following:

1. **Read the actual diff** — don't rely on PR description alone
2. **Dependency confusion scan** — check every `pip install`, `npm install`, `cargo add` command in docs/code for unregistered package names. The registered names are:
   - **PyPI:** `agent-os-kernel`, `agentmesh-platform`, `agent-hypervisor`, `agentmesh-runtime`, `agent-sre`, `agent-governance-toolkit`, `agentmesh-lightning`, `agentmesh-marketplace`
   - **PyPI (local-only, not published):** `agent-governance-dotnet`, `agentmesh-integrations`, `agent-primitives`, `emk`
   - **PyPI (common deps):** `streamlit`, `plotly`, `pandas`, `networkx`, `aioredis`, `pypdf`, `spacy`, `slack-sdk`, `docker`, `langchain-openai`
   - **npm:** `@microsoft/agent-os-kernel`
   - **crates.io:** `agentmesh`
3. **New Python modules** — verify `__init__.py` exists in any new package directory
4. **Dependencies declared** — any new `import` must have the package in `pyproject.toml` dependencies (not just transitive)
5. **No hardcoded secrets** — no API keys, tokens, passwords, connection strings in code or docs
6. **No plaintext config in pipelines** — ESRP Client IDs, Key Vault names, cert names go in secrets, not YAML
7. **Verify PR has actual changes** — check `additions > 0` before merging (empty PRs have happened)
8. **MIT license headers** — every new source file (`.py`, `.ts`, `.js`, `.rs`, `.go`, `.cs`, `.sh`) must have the license header. This is the #1 most common review finding.

## Security Rules

- All `pip install` commands must reference registered PyPI packages
- All security patterns must be in YAML config, not hardcoded
- All GitHub Actions must be SHA-pinned (use `action@<sha> # vX.Y.Z` format, never bare tags like `@v46`)
- All workflows must define `permissions:`
- Use `yaml.safe_load()`, never `yaml.load()`
- No `pickle.loads`, `eval()`, `exec()`, `shell=True` in production code
- No `innerHTML` — use safe DOM APIs
- No `unwrap()` in non-test Rust code paths (use `?` or explicit error handling)
- Docker images must use pinned version tags or SHA digests (never `:latest`)

## Supply Chain Security (Anti-Poisoning)

### Version Selection
- **7-Day Rule:** Never install a package version released less than 7 days ago. Prefer versions with at least one week of stability and consistent download metrics.
- **Fallback:** If the latest version is < 7 days old, pin to the previous stable release.
- **Verification:** Check release timestamps via `npm view <package> time` or `pip index versions <package>`.

### Version Locking
- **Exact versions only:** Use exact versioning in `package.json` (e.g., `"axios": "1.14.0"`). Prohibit `^` or `~` ranges.
- **Python pinning:** Use `==` in `requirements.txt` and pin in `pyproject.toml` with `>=x.y.z,<x.y+1.0`.
- **Rust pinning:** Use exact versions in `Cargo.toml` (e.g., `serde = "=1.0.228"`).
- **Lockfile integrity:** Ensure `package-lock.json`, `Cargo.lock`, or equivalent is committed to the repository.

### Anomaly Detection
- **Pre-install audit:** Before adding any new dependency, check for red flags: unusual release spikes, sudden maintainer changes, new suspicious transitive dependencies.
- **Alert:** If any anomaly is detected, halt the installation and flag for human review.
- **Dependabot PRs:** Review Dependabot version bumps for major version jumps, new transitive deps, or maintainer changes before merging.

## Code Style

- Use conventional commits (feat:, fix:, docs:, etc.)
- Run tests before committing
- MIT license headers on all source files:
  - Python/Shell: `# Copyright (c) Microsoft Corporation.\n# Licensed under the MIT License.`
  - TypeScript/JavaScript/Rust/C#/Go: `// Copyright (c) Microsoft Corporation.\n// Licensed under the MIT License.`
- Author: Microsoft Corporation, email: agentgovtoolkit@microsoft.com
- All packages prefixed with "Public Preview" in descriptions

## CI Optimization

CI workflows use path filters so only relevant checks run per PR:
- **Python changes** (`packages/agent-mesh/`, `packages/agent-os/`, etc.) → lint + test for that package only
- **TypeScript changes** (`sdks/typescript/`, `extensions/copilot/`) → TS lint + test only
- **Rust changes** (`sdks/rust/`) → cargo test only
- **.NET changes** (`agent-governance-dotnet/`) → dotnet test only
- **Go changes** (`sdks/go/`) → go test only
- **Docs-only changes** (`.md`, `notebooks/`) → link check only, skip all builds/tests
- **Workflow changes** (`.github/workflows/`) → workflow-security audit only

## Publishing

- PyPI/npm/NuGet/crates.io publishing goes through ESRP Release (ADO pipelines), NOT GitHub Actions
- All ESRP config values must be in pipeline secrets, never plaintext in YAML
- Package names must NOT start with `microsoft` or `windows` (reserved by Python team)
- npm packages use `@microsoft` scope only
