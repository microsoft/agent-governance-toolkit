# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> [!IMPORTANT]
> All releases are currently **public preview releases**. They are Microsoft-signed
> and production-quality but may have breaking changes before GA.

## [Unreleased]


## [3.1.1] - 2026-04-21

### Added
- **E2E Encrypted Agent Messaging** — Signal protocol (X3DH + Double Ratchet) for agent-to-agent channels with per-message forward secrecy (#1222, #1223, #1224, #1226)
  - `agentmesh.encryption.x3dh` — X3DH key agreement using Ed25519 identity keys
  - `agentmesh.encryption.ratchet` — Double Ratchet with ChaCha20-Poly1305 encryption
  - `agentmesh.encryption.channel` — SecureChannel high-level send/receive API
  - `agentmesh.encryption.bridge` — EncryptedTrustBridge gates channels on trust verification
  - 61 tests across all encryption modules
- **GitHub Pages documentation site** — MkDocs Material at microsoft.github.io/agent-governance-toolkit (#1186)
- **BinSkim binary security analysis** for .NET SDK in CI (#1245)
- **Customer FAQ** — 13 technical Q&As for customers, partners, and evaluators (#1171, #1185)
- **Tutorial 32** — E2E Encrypted Agent Messaging (#1227)
- **Tutorial 33** — Offline-Verifiable Decision Receipts (#1197)
- **Entra Agent ID bridge tutorial** — DID ↔ Entra identity integration (#1166)
- **Chaos testing tutorial** for AI agents with Agent SRE (#1184)
- **ISO 42001 alignment assessment** (#1183)
- **sb-runtime governance skill** — signed decision receipts with Veritas Acta format (#1203)
- **Physical attestation example** — cold chain sensor governance receipts (#1168)
- **protect-mcp governed example** — Cedar policies + signed receipts (#1159)
- **Container images** — GHCR publishing for AgentMesh components (#1192)
- **.NET SDK**: MCP security namespace, kill switch, lifecycle management (#1021, #1065)
- **Go SDK**: MCP security, execution rings, lifecycle management (#1066)
- **Rust SDK**: Execution rings and lifecycle management (#1067)
- **Graph API group membership sync** for Entra Agent ID bridge (#1191)
- **Workshop materials** — 2-hour AI agent governance session (#1195)

### Security
- Address all 106 open code scanning alerts (#1211)
- Address 14 code scanning alerts (#1211)
- Remove hardcoded credentials flagged by generic secret scanning (#1217)
- Upgrade axios to 1.15.0 for CVE-2026-40175, CVE-2025-62718 (#966)
- Address 6 Dependabot security vulnerabilities (#1212)
- Resolve CodeQL syntax errors (#1213)
- Harden new packages against audit findings (#944)
- XSS, curl|bash, CORS, PII leak, path traversal fixes (#945)

### Fixed
- **ESRP NuGet signing** — add AuthCertName for cert-based auth, fix Windows agent requirement (#1022, #1207, #1208, #1210, #1214, #1232, #1233)
- **CI path filters** — docs-only PRs drop from ~14 checks to ~4 (#1019)
- **CI concurrency groups** — cancel stale duplicate runs on branch updates (#1019)
- Remove pi-mono integration breaking dependency scan (#1190)
- Fix lint errors in encryption modules (#1248)
- Add mkdocs-minify-plugin to dep scan allowlist (#1247)
- Align lotl_prevention_policy.yaml with PolicyDocument schema
- Standardize DID method to did:agentmesh across all SDKs (#1170)
- Downgrade rand 0.9.3 to 0.8.5 for ed25519-dalek compatibility (#1178)
- Fix container publish workflow matrix issues (#1239, #1240, #1241, #1243)
- Rewrite production policy examples to valid PolicyDocument schema (#1011)

### Documentation
- **OpenClaw sidecar** — comprehensive rewrite with verified API examples and working demo (#1163, #1164, #1167)
- v3.1.0 release announcement in README with PyPI badge (#1019)
- OWASP ASI-07 updated with Signal protocol E2E encryption (#1242)
- Governance Maturity Model blog post (#1182)
- Blog post comparing AI agent governance approaches (#1193)
- GOVERNANCE.md, MAINTAINERS.md, ROADMAP.md for foundation submission (#1215)
- Attribution & prior art policy (#1219)
- Sync audit redaction wording with current code (#1014)
- Address external critic gaps in limitations and threat model (#1017, #1025)

### Dependencies
- Bump 25+ dependencies across Python, TypeScript, .NET, and Rust packages


## [3.1.0] - 2026-04-11

### Added
- **Unified `agt` CLI** with plugin discovery, doctor command, and 79 tests (#924)
- **Governance Dashboard** — real-time agent fleet visibility (#925)
- **Agent Lifecycle Management** — provisioning to decommission (#923)
- **Agent Discovery Package** — shadow AI discovery & inventory (#921)
- **Quantum-Safe Signing** — ML-DSA-65 alongside Ed25519 (#927)
- **Vendor Independence Enforcement** across all core packages
- **OWASP ASI 2026 Taxonomy Migration** with reference architecture
- **PromptDefenseEvaluator** — 12-vector prompt audit (#854)
- **EU AI Act Risk Classifier** (`agentmesh.governance.EUAIActRiskClassifier`) — structured risk classification per Article 6 and Annex III, with Art. 6(1) Annex I safety-component path, Art. 6(3) exemptions, GDPR Art. 4(4) profiling override, and configurable YAML categories for regulatory updates (#756)

### Security
- Patched dependency verification bypass and trust handshake DID forgery (#920)
- **Hardened CLI Error Handling** — standardized sanitized JSON error output across all 7 ecosystem tools to prevent internal information disclosure (CWE-209)
- **Audit Log Whitelisting** — implemented strict key-whitelisting in `agentmesh audit` JSON output to prevent accidental leakage of sensitive agent internal state
- **CLI Input Validation** — added regex-based validation for agent identifiers (DIDs/names) in registration and verification commands to prevent injection attacks

### Fixed
- Repo hygiene: MIT headers, compliance disclaimers, dependency confusion, network bindings (#926)
- CI: pyyaml added to agent-compliance direct dependencies
- Code samples updated to v3 API
- Various dependency bumps (cryptography, path-to-regexp, etc.)

### Documentation
- Modern Agent Architecture overview for enterprise sharing
- NIST AI RMF 1.0 alignment assessment
- MCP governance consolidated into docs/compliance/
- Policy-as-code tutorial chapter 4
- Added `EUAIActRiskClassifier` usage example and API docs to `packages/agent-mesh/README.md`
- Updated `QUICKSTART.md` and `Tutorial 04 — Audit & Compliance` with secure JSON error handling examples and schema details
- Added "Secure Error Handling" sections to primary documentation to guide users on interpreting sanitized machine-readable outputs

### Added
- Added optional runtime evidence mode for `agt verify` with `--evidence` and `--strict`.


## [3.0.2] - 2026-04-02

### Security
- Comprehensive security audit remediation (29 findings fixed)
- CI injection prevention: moved all github.event expressions to env blocks
- Supply chain hardening: dependency confusion fixes, npm lockfiles, Dockerfile pinning
- Docker/infra: removed hardcoded passwords, wildcard CORS, added .dockerignore exclusions
- Code quality: XSS prevention in VS Code webviews, Rust panic safety
- Version pinning compliance across all pyproject.toml and Cargo.toml files
- Extended dependency confusion detection script coverage

## [3.0.1] - 2026-04-01

### Added
- Rust SDK (`agentmesh` crate) for native governance integration
- Go SDK module for policy, trust, audit, and identity
- Trust report CLI command (`agentmesh trust report`)
- Secret scanning workflow (Gitleaks)
- 4 new fuzz targets (prompt injection, MCP scanner, sandbox, trust scoring)
- Dependabot coverage expanded to 13 ecosystems (+ cargo, gomod, nuget, docker)
- 7 new tutorials (Rust SDK, Go SDK, delegation chains, budgets, security, SBOM, MCP scan)
- ESRP Release publishing for Rust crates (crates.io)
- Entra Agent ID adapter for managed identity integration
- Secure code generation templates with AST validation
- SBOM generation (SPDX/CycloneDX) with Ed25519 artifact signing
- Tenant isolation checklist and private endpoint deployment examples

### Fixed
- ADO build failures: shebang position (TS18026), Express 5 type narrowing (TS2345)
- NuGetCommand@2 → DotNetCoreCLI@2 for Ubuntu 24.04 compatibility
- path-to-regexp ReDoS vulnerability (8.3.0 → 8.4.0)
- Python 3.10 CI matrix exclusions for packages requiring >=3.11
- TypeScript eslint peer dependency conflicts resolved
- Rust crate dependency pins (rand 0.8, sha2 0.10, thiserror 1)
- Ruff lint errors in agent-sre (E741, F401, E401)
- Policy provider test mock contract alignment
- Dify integration removed from CI (archived package)
- Notebook dependency scanner regex hardened

### Changed
- PUBLISHING.md rewritten with full Microsoft compliance policies (MCR, ESRP, Conda, PMC)
- Branch protection: 13 required status checks, dismiss stale reviews, squash-only merges
- README updated with 5 SDK languages, 20+ framework integrations, security tooling table


## [3.0.0] - 2026-03-26

### Changed
- **Official Microsoft-Signed Public Preview** — all packages are now published
  via ESRP Release with Microsoft signing
- All package descriptions updated from "Community Edition" to "Public Preview"
- All Development Status classifiers standardized to "4 - Beta"
- Package `agent-lightning` renamed to `agentmesh-lightning` on PyPI
- All personal author references replaced with Microsoft Corporation
- Contact email updated to agentgovtoolkit@microsoft.com

### Fixed
- Removed all merge conflict markers from docs
- Updated all old PyPI package name references (agent-runtime → agentmesh-runtime,
  agent-lightning → agentmesh-lightning) across README, QUICKSTART, tutorials,
  workflows, and scripts
- ESRP pipeline service connection hardcoded for ADO compile-time requirement
- ESRP pipeline `each` directive syntax fixed in Verify stages
- License format updated to SPDX string (setuptools deprecation fix)

## [2.3.0] - 2026-03-26

### Added
- MCP server allowlist/blocklist and plugin trust tiers (#425, #426)
- Plugin schema adapters and batch evaluation (#424, #429)
- Governance policy linter CLI command (#404)
- Pre-commit hooks for plugin manifest validation (#428)
- GitHub Actions action for governance verification (#423)
- Event bus, task outcomes, diff policy, and sandbox provider (#398, #396, #395, #394)
- Graceful degradation, budget policies, and audit logger (#410, #409, #400)
- JSON schema validation for governance policies (#305, #367)
- 14 launch-ready tutorials (07–20) covering all toolkit features
- Tutorials landing page README with learning paths (#422)
- Copilot instructions with PR review checklist (#413)
- Pytest markers for slow and integration tests (#375)
- Reference integration example for plugin marketplace governance (#427)

### Changed
- Renamed PyPI package `agent-runtime` → `agentmesh-runtime` (name collision with AutoGen) (#444)
- Renamed PyPI package `agent-marketplace` → `agentmesh-marketplace` (#439)
- Renamed PyPI package `agent-lightning` → `agentmesh-lightning` (name collision on PyPI)

### Fixed
- ESRP pipeline `each` directive syntax in Verify stages
- ESRP pipelines updated to use `ESRP_CERT_IDENTIFIER` secret
- Hardcoded service connection name (ADO compile-time requirement) (#421)
- License format updated to SPDX string (setuptools deprecation) in agent-compliance and agent-lightning
- Corrected license reference in AgentMesh README from Apache 2.0 to MIT (#436)
- .NET GovernanceMetrics test isolation — flush listener before baseline (#417)
- Dependency confusion + pydantic dependency fix (#412)
- Enforced maintainer approval for all external PRs (#392)

### Security
- Moved all ESRP config to pipeline secrets (#370)

### Documentation
- Standardized package README badges (#373)
- Added README files to example and skill integration directories (#371, #372, #390)
- Added requirements for example directories (#372)

## [2.2.0] - 2026-03-17

### Added
- ESRP Release ADO pipeline for PyPI publishing (`pipelines/pypi-publish.yml`)
- ESRP Release ADO pipeline for npm publishing (`pipelines/npm-publish.yml`)
- npm build + pack job in GitHub Actions publish workflow
- Community preview disclaimers across all READMEs, release notes, and package descriptions
- `PUBLISHING.md` guide covering PyPI, npm, and NuGet publishing requirements
- `agent-runtime` re-export wrapper package (`src/agent_runtime/__init__.py`)
- `RELEASE_NOTES_v2.2.0.md`
- `create_policies_from_config()` API — load security policies from YAML config files
- `SQLPolicyConfig` dataclass and `load_sql_policy_config()` for structured policy loading
- 10 sample policy configs in `examples/policies/` (sql-safety, sql-strict, sql-readonly, sandbox-safety, prompt-injection-safety, mcp-security, semantic-policy, pii-detection, conversation-guardian, cli-security-rules)
- Configurable security rules across 7 modules: sandbox, prompt injection, MCP security, semantic policy, PII detection, conversation guardian, CLI checker

### Changed
- GitHub Actions `publish.yml` no longer publishes to PyPI (build + attest only)
- Python package author updated to `Microsoft Corporation` with team DL (all 7 packages)
- npm packages renamed to `@microsoft` scope (from `@agentmesh`, `@agent-os`, unscoped)
- npm package author set to `Microsoft Corporation` (all 9 packages)
- All package descriptions prefixed with `Community Edition`
- License corrected to MIT where mismatched (agent-mesh classifier, 2 npm packages)

### Deprecated
- `create_default_policies()` — emits runtime warning directing users to `create_policies_from_config()` with explicit YAML configs

### Security
- Expanded SQL policy deny-list to block GRANT, REVOKE, CREATE USER, EXEC xp_cmdshell, UPDATE without WHERE, MERGE INTO
- Externalized all hardcoded security rules to YAML configuration across 7 modules

### Fixed
- `agent-runtime` build failure (invalid parent-directory hatch reference)
- Missing `License :: OSI Approved :: MIT License` classifier in 3 Python packages
- Incorrect repository URLs in 2 npm packages

## [2.1.0] - 2026-03-15

### 🚀 Highlights

**Multi-language SDK readiness, TypeScript full parity, .NET NuGet hardening, 70+ commits since v1.1.0.** This release makes the toolkit a true polyglot governance layer — Python, TypeScript, and .NET are all first-class citizens with install instructions, quickstarts, and package metadata ready for registry publishing.

### Added

- **TypeScript SDK full parity** (— PolicyEngine + AgentIdentity) — rich policy evaluation with 4 conflict resolution strategies, expression evaluator, rate limiting, YAML/JSON policy documents, Ed25519 identity with lifecycle/delegation/JWK/JWKS/DID export, IdentityRegistry with cascade revocation. 136 tests passing. (#269)
- **@microsoft/agentmesh-sdk 1.0.0** — TypeScript package now publish-ready with `exports` field, `prepublishOnly` build hook, correct `repository.directory`, MIT license.
- **Multi-language README** — root README now surfaces Python (PyPI), TypeScript (npm), and .NET (NuGet) install sections, badges, quickstart code, and a multi-SDK packages table.
- **Multi-language QUICKSTART** — getting started guide now covers all three SDKs with code examples.
- **Semantic Kernel + Azure AI Foundry** added to framework integration table.
- **5 standalone framework quickstarts** — one-file runnable examples for LangChain, CrewAI, AutoGen, OpenAI Agents, Google ADK.
- **Competitive comparison page** — vs NeMo Guardrails, Guardrails AI, LiteLLM, Portkey (`docs/COMPARISON.md`).
- **GitHub Copilot Extension** — agent governance code review extension for Copilot.
- **Observability integrations** — Prometheus, OpenTelemetry, PagerDuty, Grafana (#49).
- **NIST RFI mapping** — question-by-question mapping to NIST AI Agent Security RFI 2026-00206 (#29).
- **Performance benchmarks** — published BENCHMARKS.md with p50/p99 latency, throughput at 50 concurrent agents (#231).
- **6 comprehensive governance tutorials** — policy engine, trust & identity, framework integrations, audit & compliance, agent reliability, execution sandboxing (#187).
- **Azure deployment guides** — AKS, Azure AI Foundry, Container Apps, OpenClaw sidecar.

### Changed

- **agent-governance** (formerly `ai-agent-compliance`): Renamed PyPI package for better discoverability.
- **README architecture disclaimer** reframed from apology to confidence — leads with enforcement model, composes with container isolation (#240).
- **README tagline** updated for OWASP 10/10 discoverability.
- **.NET NuGet metadata** enhanced — Authors, License, RepositoryUrl, Tags, ReadmeFile in csproj.
- All example install strings updated from `ai-agent-compliance[full]` to `agent-governance[full]`.
- Demo fixed: legacy `agent-hypervisor` path → `agent-runtime`.
- BENCHMARKS.md: fixed stale "VADP version" reference.

### Fixed

- Demo fixed: legacy `agent-hypervisor` path → `agent-runtime`.
- BENCHMARKS.md: fixed stale "VADP version" reference.
- **.NET bug sweep** — thread safety, error surfacing, caching, disposal fixes (#252).
- **Behavioral anomaly detection** implemented in RingBreachDetector.
- **CLI edge case tests** and input validation for agent-compliance (#234).
- **Cross-package import errors** breaking CI resolved (#222).
- **OWASP-COMPLIANCE.md** broken link fix + Copilot extension server hardening (#270).

### Security

- **CostGuard org kill switch bypass** — crafted IEEE 754 inputs (NaN/Inf/negative) could bypass organization-level kill switch. Fixed with input validation + persistent `_org_killed` flag (#272).
- **CostGuard thread safety** — bound breach history + Lock for concurrent access (#253).
- **ErrorBudget._events** bounded with `deque(maxlen=N)` to prevent unbounded growth (#172).
- **VectorClock thread safety** + integrity type hints (#243).
- Block `importlib` dynamic imports in sandbox (#189).
- Centralize hardcoded ring thresholds and constants (#188).

### Infrastructure

- Phase 3 architecture rename propagated across 52 files (#221).
- Deferred architecture extractions — slim OS init, marketplace, lightning (#207).
- Architecture naming review and layer consolidation (#206).
- agentmesh-integrations migrated into monorepo (#138).
- CI test matrix updated with agentmesh-integrations packages (#226).
- OpenSSF Scorecard improved from 5.3 to ~7.7 (#113, #137).

### Install

```bash
# Python
pip install agent-governance-toolkit[full]

# TypeScript
npm install @microsoft/agentmesh-sdk

# .NET
dotnet add package Microsoft.AgentGovernance
```

## [2.0.2] - 2026-03-12

### Changed

- **agent-runtime**: Version bump to align with mono-repo versioning

### Security

- Block `importlib` dynamic imports in sandbox (#189)

## [2.0.1] - 2026-03-11

### Changed

- **agent-runtime**: Centralize hardcoded ring thresholds and constants (#188)

## [1.1.0] - 2026-03-08

### 🚀 Highlights

**15 issues closed, 339+ tests added, 12 architectural features shipped** — in 72 hours from first analysis to merged code. This release transforms the toolkit from a well-structured v1.0 into an enterprise-hardened governance layer with real adversarial durability.

### Added — Security & Adversarial Durability

- **Policy conflict resolution engine** — 4 declared strategies (`DENY_OVERRIDES`, `ALLOW_OVERRIDES`, `PRIORITY_FIRST_MATCH`, `MOST_SPECIFIC_WINS`) with 3-tier policy scope model (global → tenant → agent) and auditable resolution trace. Answers the question every security architect will ask: "if two policies conflict, which wins?" (#91)
- **Session policy pinning** — `create_context()` now deep-copies policy so running sessions get immutable snapshots. Mid-flight policy mutations no longer leak into active sessions. (#92)
- **Tool alias registry** — Canonical capability mapping for 7 tool families (30+ aliases) prevents policy bypass via tool renaming. `bing_search` can no longer dodge a `web_search` block. (#94)
- **Human-in-the-loop escalation** — `EscalationPolicy` with `ESCALATE` tier, `InMemoryApprovalQueue`, and `WebhookApprovalBackend`. Adds the suspend-and-route-to-human path required by regulated industries (healthcare, finance, legal). (#81)

### Added — Reliability & Operations

- **Inter-package version compatibility matrix** — `doctor()` function with runtime compatibility checking across all 5 packages. Detects silent version skew before it causes trust handshake failures. (#83)
- **Credential lifecycle management** — Wired `RevocationList` into `CardRegistry.is_verified()` so revoked credentials are actually rejected. Key rotation now has a kill path. (#82)
- **File-backed trust persistence** — `FileTrustStore` with JSON persistence, atomic writes, and thread safety. Trust scores survive agent restarts — misbehaving agents can no longer reset reputation by crashing. (#86)
- **Policy schema versioning** — `apiVersion` field with validation, migration tooling, and deprecation warnings. Schema evolution in v1.2+ won't silently break existing policy files. (#87)

### Added — Supply Chain & Certification (PR #99)

- **Bootstrap integrity verification** — `IntegrityVerifier` hashes 15 governance module source files and 4 critical function bytecodes (SHA-256) against a published `integrity.json` manifest. Detects supply chain tampering before any policy evaluation occurs. (#95)
- **Governance certification CLI** — `agent-governance verify` checks all 10 OWASP ASI 2026 controls, generates signed attestations, and outputs shields.io badges for README embedding. `agent-governance integrity --generate` creates baseline manifests for release signing.

### Added — Governance Enhancements (PR #90)

- **SIGKILL-analog process isolation** — Real `os.kill(SIGKILL)` for Linux, `TerminateProcess` for Windows, with PID tracking and cgroup integration. Not a simulated kill — actual process-level termination. (#77)
- **OpenTelemetry observability** — `GovernanceTracer` with distributed traces, span events for policy checks, custom metrics (policy evaluations, violations, latency histograms), and OTLP exporter integration. (#76)
- **Async concurrency safety** — `asyncio.Lock` guards on shared state, `ConcurrencyStats` tracking, deadlock detection with configurable timeouts. Concurrent agent evaluations no longer corrupt trust scores. (#75)
- **Policy-as-code CI pipeline** — `PolicyCI` class with YAML linting, schema validation, conflict detection, and dry-run simulation. Integrates with GitHub Actions for PR-time policy validation. (#74)
- **Deep framework integrations** — `LangChainGovernanceCallback`, `CrewAIGovernanceMiddleware`, `AutoGenGovernanceHook` with framework-specific lifecycle hooks, not just wrapper-level interception. (#73)
- **External audit trail integrity** — `SignedAuditEntry` with Ed25519 signatures, `HashChainVerifier` for tamper detection, `FileAuditSink` for append-only external storage. Cryptographic proof that audit logs haven't been modified. (#72)
- **Behavioral anomaly detection** — Statistical anomaly detection for agent behavior patterns (tool call frequency, response time, error rate) with configurable sensitivity. Catches rogue agents before they violate explicit rules. (#71)

### Added — Infrastructure

- **Copilot auto-review workflow** — Automated PR review on every pull request. (#70)
- **7 production module ports** — Episodic Memory Kernel, CMVK, Self-Correcting Agent Kernel, Context-as-a-Service, Agent Control Plane, Trust Engine, Mute Agent infrastructure — ported from internal production with full test coverage. (#63–#69)

### Fixed

- **44 code scanning alerts resolved** — CodeQL SAST findings across the entire repository including CWE-209 (error information exposure), CWE-116 (improper encoding), and CWE-20 (improper input validation). (#79)

### Security

- All cryptographic operations use real Ed25519 primitives (not placeholder/XOR).
- Prompt injection defense verified: `prompt_injection.py` + LlamaFirewall + `OutputValidationMiddleware`.
- SLO alerting verified: `AlertManager` with Slack, PagerDuty, Teams, and OpsGenie channels.

### Test Coverage

- **339+ new tests** across all features with full assertion coverage.
- All 5 packages pass CI independently.

### Install

```bash
pip install agent-governance-toolkit[full]
```

## [1.0.1] - 2026-03-06

### Added

- **CODEOWNERS** — Default and per-package code ownership for review routing.
- **SBOM workflow** — Generates SPDX-JSON and CycloneDX-JSON on every release
  with GitHub attestation via `actions/attest-sbom`.

### Changed

- **Microsoft org release** — First publish from `microsoft/agent-governance-toolkit`
- Added MIT license headers to 1,159 source files across all packages.
- Migrated all 215 documentation URLs from personal repos to Microsoft org.
- Replaced personal email references with team alias (`agentgovtoolkit@microsoft.com`).
- Enhanced README with hero section, CI badge, navigation links, CLA/Code of Conduct sections.
- Bumped all 5 package versions from 1.0.0 to 1.0.1.

### Fixed

- Fixed `agentmesh` PyPI link to `agentmesh-platform` (correct package name).
- Removed internal feed reference from providers.py.

### Security

- Secret scan verified clean — no keys, tokens, or credentials in repository.
- `pip-audit` verified 0 known vulnerabilities across all packages.
- All 43 OSV vulnerabilities from v1.0.0 confirmed resolved.

### Repository

- Archived 6 personal repos with deprecation banners and migration notices.
- Closed 83 open issues and annotated 596 closed items with migration links.
- Posted migration announcements to 89 stargazers.
- Enabled GitHub Discussions, 12 topic tags, OpenSSF Scorecard.
## [1.0.0] - 2026-03-04

### Added

- **Agent OS Kernel** (`agent-os-kernel`) — Policy-as-code enforcement engine with
  syscall-style interception, OWASP ASI 2026 compliance, and Microsoft Agent Framework
  (MAF) native middleware adapter.
- **AgentMesh** (`agentmesh`) — Zero-trust inter-agent identity mesh with SPIFFE-based
  identity, DID-linked credentials, Microsoft Entra Agent ID adapter, and AI-BOM v2.0
  supply-chain provenance.
- **Agent Runtime** (`agent-runtime`) — Runtime sandboxing with capability-based
  isolation, resource quotas, and Docker/Firecracker execution environments.
- **Agent SRE** (`agent-sre`) — Observability toolkit with chaos-engineering probes,
  canary deployment framework, and automated incident response.
- **Agent Compliance** (`agent-governance`, formerly `ai-agent-compliance`) — Unified compliance installer mapping
  OWASP ASI 2026 (10/10), NIST AI RMF, EU AI Act, and CSA Agentic Trust Framework.
- Mono-repo CI/CD: lint (ruff) × 5 packages, test matrix (3 Python versions × 4 packages),
  security scanning (safety), CodeQL SAST (Python + JavaScript).
- Dependabot configuration for 8 ecosystems.
- OpenSSF Best Practices badge and Scorecard integration.
- Comprehensive governance proposal documents for standards bodies (OWASP, CoSAI, LF AI & Data).

### Security

- **CVE-2025-27520** — Bumped `python-multipart` to ≥0.0.20 (arbitrary file write).
- **CVE-2024-53981** — Bumped `python-multipart` to ≥0.0.20 (DoS via malformed boundary).
- **CVE-2024-47874** — Bumped `python-multipart` to ≥0.0.20 (Content-Type ReDoS).
- **CVE-2024-5206** — Bumped `scikit-learn` to ≥1.6.1 (sensitive data leakage).
- **CVE-2023-36464** — Replaced deprecated `PyPDF2` with `pypdf` ≥4.0.0 (infinite loop).
- Removed exception details from HTTP error responses (CWE-209).
- Redacted PII (patient IDs, SSNs) from example log output (CWE-532).
- Fixed ReDoS patterns in policy library regex (CWE-1333).
- Fixed incomplete URL validation in Chrome extension (CWE-20).
- Pinned all GitHub Actions by SHA hash.
- Pinned all Docker base images by SHA256 digest.
- Removed `gradle-wrapper.jar` binary artifact.

[2.1.0]: https://github.com/microsoft/agent-governance-toolkit/releases/tag/v2.1.0
[1.1.0]: https://github.com/microsoft/agent-governance-toolkit/releases/tag/v1.1.0
[1.0.1]: https://github.com/microsoft/agent-governance-toolkit/releases/tag/v1.0.1
[1.0.0]: https://github.com/microsoft/agent-governance-toolkit/releases/tag/v1.0.0
