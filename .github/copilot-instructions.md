# Copilot Instructions for agent-governance-toolkit

## PR Review — Mandatory Before Merge

NEVER merge a PR without thorough code review. CI passing is NOT sufficient.

Before approving or merging ANY PR, verify ALL of the following:

1. **Read the actual diff** — don't rely on PR description alone
2. **Dependency confusion scan** — check every `pip install`, `npm install`, `cargo add` command in docs/code for unregistered package names. The registered names are:
   - **PyPI:** `agent-os-kernel`, `agentmesh-platform`, `agent-hypervisor`, `agentmesh-runtime`, `agent-sre`, `agent-governance-toolkit`, `agentmesh-lightning`, `agentmesh-marketplace`
   - **PyPI (local-only, not published):** `agent-governance-dotnet`, `agentmesh-integrations`
   - **npm:** `@microsoft/agent-os-kernel`
   - **crates.io:** `agentmesh`
3. **New Python modules** — verify `__init__.py` exists in any new package directory
4. **Dependencies declared** — any new `import` must have the package in `pyproject.toml` dependencies (not just transitive)
5. **No hardcoded secrets** — no API keys, tokens, passwords, connection strings in code or docs
6. **No plaintext config in pipelines** — ESRP Client IDs, Key Vault names, cert names go in secrets, not YAML
7. **Verify PR has actual changes** — check `additions > 0` before merging (empty PRs have happened)
8. **MIT license headers** — every new source file (`.py`, `.ts`, `.js`, `.rs`, `.go`) must have the license header. This is the #1 most common review finding.

## Security Rules

- All `pip install` commands must reference registered PyPI packages
- All security patterns must be in YAML config, not hardcoded
- All GitHub Actions must be SHA-pinned (use `action@<sha> # vX.Y.Z` format, never bare tags like `@v46`)
- All workflows must define `permissions:`
- Use `yaml.safe_load()`, never `yaml.load()`
- No `pickle.loads`, `eval()`, `exec()`, `shell=True` in production code
- No `innerHTML` — use safe DOM APIs
- No `unwrap()` in non-test Rust code paths (use `?` or explicit error handling)

## Code Style

- Use conventional commits (feat:, fix:, docs:, etc.)
- Run tests before committing
- MIT license headers on all source files:
  - Python/Go: `# Copyright (c) Microsoft Corporation.\n# Licensed under the MIT License.`
  - TypeScript/JavaScript: `// Copyright (c) Microsoft Corporation.\n// Licensed under the MIT License.`
  - Rust: `// Copyright (c) Microsoft Corporation.\n// Licensed under the MIT License.`
- Author: Microsoft Corporation, email: agentgovtoolkit@microsoft.com
- All packages prefixed with "Public Preview" in descriptions

## Publishing

- PyPI/npm/NuGet/crates.io publishing goes through ESRP Release (ADO pipelines), NOT GitHub Actions
- All ESRP config values must be in pipeline secrets, never plaintext in YAML
- Package names must NOT start with `microsoft` or `windows` (reserved by Python team)
- npm packages use `@microsoft` scope only
