# Copilot Instructions for agent-governance-toolkit

## Decision Escalation

For major design changes, always ask the maintainer (@imran-siddique) before proceeding:
- New packages or modules that change the repo structure
- Cross-cutting changes spanning 3+ packages
- Security model changes (identity, trust, policy engine)
- Breaking API changes to public interfaces
- New framework integrations or SDK additions
- Changes to CI/CD pipeline architecture

Do NOT auto-merge large feature PRs without maintainer review.

## External Contribution Quality Gate

When external contributors open issues or PRs proposing integration with their own project/tool/library, apply these quality checks before investing review time:

- **Attribution & prior art check**: If the PR implements functionality similar to an existing open-source project, verify it credits that project explicitly. Check the "Prior art" section in the PR template. If the PR mirrors patterns from a known project (architecture, CLI conventions, config schema, API design) without attribution, **request changes immediately** and do not merge until attribution is added. Uncredited derivatives of community work will be closed.
- **Timeline verification**: For PRs that arrive shortly after a community member proposes similar functionality in an issue, verify the PR author isn't racing to submit an uncredited copy of the proposed approach. Check issue discussion history for prior art.
- **Repo creation date check**: If a contributor references their own project, check when that project's repository was created. If it was created within 7 days of the contributor's first issue or PR on this repo, treat this as a high-risk signal requiring additional scrutiny. Same-day creation is a strong indicator of reactive/derivative work.
- **Cross-repo pattern detection**: Before merging contributions from new external contributors, search their GitHub handle across adjacent repos in the ecosystem. If the same contributor is filing similar issues or PRs on multiple related projects within a short window, this is a coordination signal — it may indicate legitimate cross-project work, or it may indicate automated/synthetic activity. Evaluate in context.
- **Velocity as a signal**: A new contributor submitting multiple substantial PRs (code, docs, examples, CI workflows) within days of their first interaction is unusual. High velocity from an unknown contributor is not proof of bad faith, but it warrants deeper review — check for AI-generated content patterns (overly comprehensive specs, hallucinated technical details, projects that claim features without evidence).
- **AI-generated contribution detection**: Watch for signs of AI-generated contributions: internally consistent but externally unverifiable claims (IETF drafts, NIST submissions, patent filings), projects with elaborate documentation but no real users, landing pages with "design partner" CTAs for projects created days ago, and technically plausible but occasionally hallucinated details (e.g., referencing specific hardware chips in implausible contexts).
- **Minimum credibility threshold**: The referenced project should have meaningful community adoption (e.g., 50+ GitHub stars, multiple contributors, evidence of production usage). One-person repos with <10 stars and no community traction do not warrant integration effort.
- **Self-promotion filter**: Issues or PRs that primarily serve to promote the contributor's own low-profile project — rather than adding genuine value to AGT — should be deprioritized. Politely acknowledge but do not fast-track.
- **Verify claims**: If the PR cites benchmarks, adoption numbers, or production deployments, spot-check them. Unverifiable claims are a red flag.
- **Scope proportionality**: A small or unknown project requesting a large integration surface (new package, new dependency, new CI pipeline) is disproportionate. Suggest they contribute as an example or community link instead.
- **Dependency risk**: Adding a dependency on an obscure package creates supply chain risk. Prefer vendored examples or optional integrations that don't add to the core dependency tree.
- **IP / patent / NDA red flags**: If a contributor mentions patents, NDAs, licensing arrangements, or "the full scope goes beyond what we've discussed," **stop technical engagement immediately**. AGT is MIT-licensed. All contributions must be made under MIT via the standard CLA. No side agreements, no patent-encumbered code, no NDA-gated architectures.
- **Spam/scam PR filter**: Close immediately with a polite note if the PR/issue is:
  - Marketing content disguised as a contribution (e.g., adding the contributor's company to COMMUNITY.md or README.md as a "Related Project" when there's no genuine technical integration)
  - From an account with <5 repos, <5 followers, created <3 months ago that submits promotional content to core docs
  - Name-dropping awards, magazine features, publications, or rankings instead of providing technical value
  - Repetitive submissions from the same contributor after previous PR was closed for the same reason (e.g., kevinkaylie/AgentNexus pattern)

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
2. **Attribution & prior art** — check if the PR implements patterns similar to known open-source projects. If it does, verify proper attribution exists in the PR description and code. Check whether the PR arrived shortly after a community member proposed similar work in an issue — if so, verify the contributor isn't submitting an uncredited derivative. **PRs without proper attribution will not be merged.**
3. **Dependency confusion scan** — check every `pip install`, `npm install`, `cargo add` command in docs/code for unregistered package names. The registered names are:
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

### Code Scanning Prevention (Scorecard + CodeQL)

These rules prevent the exact alert categories that code scanning flags. Every PR
and commit MUST comply — CI will catch violations, but catching them before push
saves time.

**Pinned Dependencies (Scorecard PinnedDependenciesID):**
- All GitHub Actions MUST be pinned by full SHA hash, never bare tags:
  - ✅ `uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4`
  - ❌ `uses: actions/checkout@v4`
- All Docker FROM images MUST include `@sha256:` digest:
  - ✅ `FROM python:3.12-slim@sha256:804ddf3251a60bbf9c92e73b7566c40428d54d0e79d3428194edf40da6521286`
  - ❌ `FROM python:3.12-slim`
- All `pip install` in workflows, Dockerfiles, and shell scripts MUST pin versions:
  - ✅ `pip install mkdocs-material==9.7.6`
  - ❌ `pip install mkdocs-material`
- To look up a GitHub Action SHA: `gh api repos/{owner}/{repo}/git/ref/tags/{tag} --jq '.object.sha'`
- To look up a Docker image digest: `docker pull python:3.12-slim && docker inspect --format='{{index .RepoDigests 0}}' python:3.12-slim`

**Token Permissions (Scorecard TokenPermissionsID):**
- All workflow files MUST have explicit `permissions:` at the top level
- Top-level permissions MUST be `contents: read` only (least privilege)
- Write permissions (`packages: write`, `pull-requests: write`, `id-token: write`, etc.)
  MUST be scoped to the specific job that needs them, not the workflow level:
  ```yaml
  # ✅ CORRECT — write scoped to job
  permissions:
    contents: read
  jobs:
    publish:
      permissions:
        packages: write
  
  # ❌ WRONG — write at top level
  permissions:
    contents: read
    packages: write
  ```

**Python Code Quality (CodeQL):**
- Never use `timedelta(days=365)` to represent "one year" — use `timedelta(days=366)`
  or `dateutil.relativedelta(years=1)` for leap-year safety
- Never use `is True` / `is False` for boolean comparison — use `== True` / `== False`
  (or just `if value:` / `if not value:`)
- Never use mutable default arguments (`def f(x=[])`) — use `None` with body initialization:
  ```python
  # ✅ def f(x=None): x = x or []
  # ❌ def f(x=[]):
  ```
- Remove unnecessary `pass` statements in non-empty function/class bodies

**TypeScript/JavaScript Code Quality (CodeQL):**
- URL validation MUST use `new URL()` constructor or protocol-aware checks, never
  plain substring matching:
  - ✅ `new URL(href).hostname === 'cdn.jsdelivr.net'`
  - ❌ `href.includes('cdn.jsdelivr.net')`

### General Security Rules

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
- **TypeScript changes** (`agent-governance-typescript/`, `extensions/copilot/`) → TS lint + test only`n- **Rust changes** (`agent-governance-rust/`) → cargo test only
- **.NET changes** (`agent-governance-dotnet/`) → dotnet test only
- **Go changes** (`agent-governance-golang/`) → go test only
- **Docs-only changes** (`.md`, `notebooks/`) → link check only, skip all builds/tests
- **Workflow changes** (`.github/workflows/`) → workflow-security audit only

## Publishing

- PyPI/npm/NuGet/crates.io publishing goes through ESRP Release (ADO pipelines), NOT GitHub Actions
- All ESRP config values must be in pipeline secrets, never plaintext in YAML
- Package names must NOT start with `microsoft` or `windows` (reserved by Python team)
- npm packages use `@microsoft` scope only

## Post-Merge Review — Mandatory Follow-Up

After merging ANY external contributor PR, perform these follow-up checks and fix issues immediately in a separate PR:

### Security Sweep
1. **Secrets scan** — grep new files for `sk-`, `ghp_`, `password=`, `api_key=` patterns. Placeholder keys in README instructions (e.g., `sk-...`) are OK; real-looking keys are not.
2. **Unsafe patterns** — check for `eval()`, `exec()`, `yaml.load()` (not safe_load), `shell=True`, `pickle.load` in new non-test code. Function names containing "exec" (e.g., `tool_exec()`) are fine — only actual `exec(` calls matter.
3. **innerHTML/XSS** — check new `.ts`/`.tsx` files for `innerHTML` without escaping. Must use `escapeHtml()` or `textContent`.
4. **Network exposure** — check for `0.0.0.0` bindings in new code (must be `127.0.0.1` for dev servers).
5. **Wildcard CORS** — check for `allow_origins=["*"]` in new code (must use env-driven origins).
6. **Credential leaks in scanners** — if new security scanning code stores matched patterns, ensure values are redacted (not raw secrets in audit logs).

### Build & Compatibility
7. **License headers** — verify all new `.py`, `.ts`, `.cs`, `.rs`, `.go`, `.sh` files have the MIT copyright header.
8. **File encoding** — all `open()` calls reading YAML/JSON/text must use `encoding="utf-8"` (prevents Windows failures).
9. **Trailing newlines** — all new source files must end with a newline (ruff W292).
10. **Relative links** — translated/i18n docs must adjust relative paths (e.g., `../../` prefix for files in `docs/i18n/`).

### Structural Integrity
11. **Scope verification** — confirm PR only touches files matching its description. Flag "trojan PRs" that bundle unrelated code changes in docs-only PRs.
12. **.github/ modifications** — ANY change to `.github/workflows/` from an external contributor requires line-by-line security review. Never merge a delete-all/re-add-all workflow diff.
13. **Mutable data structures** — if a PR adds validation (e.g., `__post_init__`), ensure the validated fields cannot be mutated post-construction (convert `list` → `tuple`). Update tests to match.
14. **Dependency format** — `pyproject.toml` uses `license = {text = "MIT"}` (table format); `Cargo.toml` uses `license = "MIT"` (SPDX string). Do NOT mix these.
15. **Package names** — `pyproject.toml` names must use underscores (PEP 625): `agent_governance_toolkit`, not `agent-governance-toolkit`.

### CI Verification
16. **Run CI** — confirm the CI run on the merge commit passes. If it fails, fix immediately.
17. **Lint compliance** — new Python files must pass `ruff check --select E,F,W --ignore E501`.
18. **Test compatibility** — if our fixes changed data types (e.g., list → tuple), update any tests that assert on the old type.

## Implementation Quality

- **No mocks or stubs in production code.** Always provide real, working implementations. If a dependency is unavailable, build the real integration or defer the feature — never ship a mock.
- **No TODO/FIXME/HACK comments as placeholders.** If something needs to be done, do it now or track it as a GitHub issue. Code with TODO comments will not be merged.
- **No placeholder or skeleton implementations.** Every function, class, and module must be fully implemented and tested. Empty methods, `pass` bodies, `raise NotImplementedError`, or `// TODO` stubs are not acceptable.
