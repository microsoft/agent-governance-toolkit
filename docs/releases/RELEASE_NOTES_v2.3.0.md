# Agent Governance Toolkit v2.3.0

> [!IMPORTANT]
> **Community Preview Release** — All packages published from this repository (PyPI, npm, NuGet)
> are **community preview releases** for testing and evaluation purposes only. They are **not**
> official Microsoft-signed releases. Official Microsoft-signed packages published via ESRP
> Release will be available in a future release.

**Plugin governance, developer tooling, and hardened security — 97 commits since v2.2.0.**

This release introduces a full plugin governance layer (MCP server allowlist/blocklist, schema
adapters, trust tiers), developer-facing tooling (policy linter CLI, pre-commit hooks, GitHub
Actions action), runtime reliability primitives (event bus, task outcomes, graceful degradation,
budget policies), and 14 new tutorials. It also includes significant security hardening across the
entire codebase and two PyPI package renames to avoid namespace collisions.

## 🚀 What's New

### Plugin Governance & MCP Server Controls

- **MCP server allowlist/blocklist** — Enforces marketplace-level policies on which MCP servers
  plugins can use through `MCPServerPolicy` with allowlist/blocklist modes. Validates plugin
  manifests and rejects non-compliant plugins during registration (#425, #426, #434)
- **Plugin trust tiers** — Classify plugins into trust levels (e.g., verified, community,
  untrusted) with tier-based policy enforcement (#434)
- **Plugin schema adapters** — Auto-detects and adapts Copilot-style and Claude-style plugin
  manifest formats to the canonical `PluginManifest` schema, enabling multi-format plugin
  support with capability extraction (#424, #429, #433)
- **Batch plugin evaluation** — Evaluate multiple plugins against governance policies in a single
  call for marketplace-scale validation (#429, #433)
- **Reference integration example** — Complete example showing plugin marketplace governance
  integration end-to-end (#427, #435)

### Developer Tooling

- **Governance policy linter CLI** — New `agent-compliance lint-policy <path>` command validates
  YAML policy files for required fields, unknown operators/actions, deprecated names, and
  conflicting rules with JSON/text output options (#404, #432)
- **Pre-commit hooks** — Two new hooks for local development: `validate-plugin-manifest` (checks
  plugin.json schema compliance) and `evaluate-plugin-policy` (evaluates manifests against
  governance policies before commit) (#428, #431)
- **GitHub Actions action** — Composite action at `action/action.yml` wrapping governance
  verification commands (`governance-verify`, `marketplace-verify`, `policy-evaluate`, `all`)
  with configurable inputs, structured outputs, and support for plugin marketplace PR
  workflows (#423, #430)
- **JSON schema validation** — Governance policy files are now validated against a formal JSON
  schema, catching structural errors before runtime (#305, #367)

### Runtime Reliability & Observability

- **Event bus** — Cross-gate publish/subscribe system (`GovernanceEventBus`) enabling loose
  coupling between governance gates (PolicyEvaluator, TrustGate, CircuitBreaker) with standard
  event types for policy violations, trust changes, circuit state, and budget overages
  (#398, #415)
- **Task outcomes** — `TaskOutcomeRecorder` tracks agent task successes/failures with
  severity-based scoring, diminishing returns on success boosts, time-based score recovery,
  and per-agent trust state management (#396, #415)
- **Diff policy** — Evaluate only the delta between previous and current policy state to reduce
  overhead on incremental policy updates (#395, #415)
- **Sandbox provider** — Pluggable sandbox provider abstraction for swapping isolation backends
  (#394, #415)
- **Graceful degradation** — `agent_os.compat` module provides no-op fallbacks
  (`NoOpPolicyEvaluator`, `NoOpGovernanceMiddleware`) allowing consumers to optionally depend
  on the toolkit without try/except boilerplate (#410, #414)
- **Budget policies** — `BudgetPolicy` dataclass defines resource consumption limits (max tokens,
  tool calls, cost, duration) with `BudgetTracker` for monitoring usage and detecting overages
  with detailed violation reasons (#409, #414)
- **Audit logger** — Structured audit logging for governance decisions with pluggable backends
  (#400, #414)
- **Policy evaluation heatmap** — Visual heatmap added to the SRE dashboard showing policy
  evaluation patterns and hotspots (#309, #326)
- **Compliance grading** — `compliance_grade()` method added to `GovernanceAttestation` for
  calculating compliance scores (#346)

### Tutorials & Learning Paths

- **14 new tutorials (07–20)** — Launch-ready tutorials covering all toolkit features including
  plugin governance, budget policies, event bus, graceful degradation, MCP server controls,
  and more
- **Tutorials landing page** — New README with structured learning paths guiding users from
  beginner to advanced topics (#422)

### CI/CD & ESRP

- **PR review orchestrator** — Collapses multiple agent review comments into a single unified
  summary on pull requests (#345)
- **Dependency confusion pre-commit hook** — Detects unregistered package names before commit,
  plus weekly CI audit job (#350)
- **Markdown link checker** — CI workflow to catch broken links in documentation (#323)
- **ESRP NuGet signing** — Updated NuGet signing config with Client ID and Key Vault
  integration (#359, #361, #363, #365)

## ⚠️ Breaking Changes

### PyPI Package Renames

Two PyPI packages have been renamed to avoid namespace collisions:

| Old Name | New Name | Reason |
|----------|----------|--------|
| `agent-runtime` | `agentmesh-runtime` | Name collision with AutoGen team's `agent-runtime` package (#444) |
| `agent-marketplace` | `agentmesh-marketplace` | Consistent `agentmesh` namespace alignment (#439) |

**Migration:** Update your `requirements.txt` or `pyproject.toml`:

```diff
- agent-runtime
+ agentmesh-runtime

- agent-marketplace
+ agentmesh-marketplace
```

## 🔒 Security

- **Fork RCE hardening** — Hardened `pull_request_target` workflows against fork-based remote
  code execution [MSRC-111178] (#353)
- **Dependency confusion** — Comprehensive remediation across the entire codebase: replaced all
  unregistered PyPI package names, added weekly audit CI, added pre-commit detection hook
  (#325, #328, #349, #350, #351, #352)
- **MD5 → SHA-256 migration** — All cryptographic hash usage migrated from MD5 to SHA-256
  (#349, #351)
- **ESRP secrets** — Moved all ESRP configuration values to pipeline secrets (#370)
- **Maintainer approval enforcement** — All external PRs now require maintainer approval (#392)
- **SECURITY.md** — Added security policy files to all packages (#354)
- **LangChain crypto hardening** — Hardened cryptographic fallback in LangChain integration (#354)
- **24 security findings addressed** — Comprehensive sweep across codebase (#303)
- **Agent sandbox escape hardening** — Strengthened isolation boundaries against escape
  vectors (#297)
- **OWASP Agentic AI hardening** — Proactive hardening against OWASP Agentic AI Top 10
  themes
- **47 negative security tests** — Adversarial scenario test suite added
- **101 additional tests** — CA security, MCP integration, and audit stub coverage
- **OpenSSF Scorecard fixes** — Dangerous-workflow, signed-releases, and pinned-deps
  improvements (#356)

## 🐛 Bug Fixes

- Corrected license reference in AgentMesh README from Apache 2.0 to MIT (#436)
- Hardcoded service connection name in ESRP pipelines (ADO compile-time requirement) (#421)
- ESRP pipeline fixes for `each` directive syntax in Verify stages and `ESRP_CERT_IDENTIFIER`
  secret usage
- Fixed .NET `GovernanceMetrics` test isolation — flush listener before baseline assertion (#417)
- Fixed dependency confusion + pydantic dependency issues (#411, #412)
- Followup cleanup for recently merged community PRs (#393)
- Bumped `cryptography` package, migrated `PyPDF2` → `pypdf`, scoped workflow permissions (#355)
- Filled community PR gaps — replaced bare excepts, `print` → `logging`, added `py.typed`
  markers, LICENSE fixes (#344)
- Improved CLI error messages in `register` and `policy` commands (#314)
- `SagaStep.MaxRetries` rename + behavioral fault injection + lint fix (#295)
- Pre-announcement security hardening and demo improvements (#296)
- Restored `read-all` at workflow level for Scorecard verification (#327)
- Reverted unsafe merged PRs #357 and #362 (#391)

## 📚 Documentation

- Added copilot-instructions.md with PR review checklist (#413)
- Standardized package README badges across all packages (#373)
- Added README files to example directories and skill integrations (#371, #372, #390)
- Added requirements files for example directories (#372)
- Refreshed all design proposals — updated status, added 5 new proposals (#348)
- Added inline comments to Helm chart `values.yaml` (#341)
- Updated framework integration star counts to current values (#329)
- Added comprehensive docstrings to `mcp_adapter.py` classes (#324)
- Added testing guide for external testers and customers (#313)
- Added integration author guide for contributors (#311)

## 📦 Dependencies

### GitHub Actions

| Package | From | To |
|---------|------|----|
| `actions/attest-sbom` | 2.2.0 | 4.1.0 |
| `actions/attest-build-provenance` | 2.4.0 | 4.1.0 |
| `actions/github-script` | 7.0.1 | 8.0.0 |
| `actions/setup-node` | 4.4.0 | 6.3.0 |
| `actions/stale` | 9.1.0 | 10.2.0 |
| `actions/upload-artifact` | 4.6.2 | 7.0.0 |
| `anchore/sbom-action` | 0.23.1 | 0.24.0 |
| `ossf/scorecard-action` | 2.4.0 | 2.4.3 |
| `sigstore/gh-action-sigstore-python` | 3.0.0 | 3.2.0 |

### npm Dev Dependencies

- Bumped `eslint` (#387)
- Bumped `typescript` (#385, #386)
- Bumped `yaml` (#384)
- Bumped `@typescript-eslint/eslint-plugin` (#381, #292)
- Bumped `@typescript-eslint/parser` (#286, #288)
- Bumped `@vitest/coverage-v8` (#289, #380)
- Bumped `@types/node` (#283, #291)

### Python

- Bumped `cryptography` (#355)
- Migrated `PyPDF2` → `pypdf` (#355)

## 🧹 Internal

- Removed unused imports with autoflake in a2a-protocol (#340)
- Added pytest markers for slow and integration tests (#375)
- Added 10 AI-powered GitHub Actions workflows (#294)

## Packages

### Python (PyPI)

| Package | Version | Status |
|---------|---------|--------|
| `agent-os-kernel` | 2.3.0 | Community Preview |
| `agentmesh-platform` | 2.3.0 | Community Preview |
| `agent-hypervisor` | 2.3.0 | Community Preview |
| `agentmesh-runtime` | 2.3.0 | Community Preview _(renamed from `agent-runtime`)_ |
| `agentmesh-marketplace` | 2.3.0 | Community Preview _(renamed from `agent-marketplace`)_ |
| `agent-sre` | 2.3.0 | Community Preview |
| `agent-governance-toolkit` | 2.3.0 | Community Preview |
| `agentmesh-lightning` | 2.3.0 | Community Preview |

### npm

| Package | Version | Status |
|---------|---------|--------|
| `@microsoft/agentmesh-sdk` | 1.0.0 | Community Preview |
| `@microsoft/agentmesh-mcp-proxy` | 1.0.0 | Community Preview |
| `@microsoft/agentos-mcp-server` | 1.0.1 | Community Preview |
| `@microsoft/agentmesh-copilot-governance` | 0.1.0 | Community Preview |
| `@microsoft/agentmesh-mastra` | 0.1.0 | Community Preview |
| `@microsoft/agentmesh-api` | 0.1.0 | Community Preview |
| `@microsoft/agent-os-copilot-extension` | 1.0.0 | Community Preview |

### NuGet

| Package | Version | Status |
|---------|---------|--------|
| `Microsoft.AgentGovernance` | 2.3.0 | Community Preview |

## Contributors

- @imran-siddique
- @dependabot
- @matt-van-horn
- @jhawpetoss6-collab
- @Bob
- @AuthorPrime
- @Copilot
- @parsa-faraji-alamouti
- @umesh-pal
- @xavier-garceau-aranda
- @zeel-desai
- @aryan
- @sharath-k
- @yuchengpersonal

## What's Coming

- Official Microsoft-signed releases via ESRP Release (pending onboarding approval)
- PyPI package ownership transfer to `microsoft` account
- npm `@microsoft` scope activation via ESRP
- NuGet Authenticode + NuGet package signing

## Full Changelog

See [CHANGELOG.md](CHANGELOG.md) for the complete list of changes.

**Full Changelog:** https://github.com/microsoft/agent-governance-toolkit/compare/v2.2.0...v2.3.0

## License

[MIT](LICENSE) — © Microsoft Corporation
