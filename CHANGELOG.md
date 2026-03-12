# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.2] - 2026-03-12

### Changed

- **agent-hypervisor**: Version bump to align with mono-repo versioning

### Security

- Block `importlib` dynamic imports in sandbox (#189)

## [2.0.1] - 2026-03-11

### Changed

- **agent-hypervisor**: Centralize hardcoded ring thresholds and constants (#188)

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
- **Governance certification CLI** — `agent-compliance verify` checks all 10 OWASP ASI 2026 controls, generates signed attestations, and outputs shields.io badges for README embedding. `agent-compliance integrity --generate` creates baseline manifests for release signing.

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
pip install ai-agent-compliance[full]
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
- Replaced personal email references with team alias (`agt@microsoft.com`).
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
- **Agent Hypervisor** (`agent-hypervisor`) — Runtime sandboxing with capability-based
  isolation, resource quotas, and Docker/Firecracker execution environments.
- **Agent SRE** (`agent-sre`) — Observability toolkit with chaos-engineering probes,
  canary deployment framework, and automated incident response.
- **Agent Compliance** (`ai-agent-compliance`) — Unified compliance installer mapping
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

[1.1.0]: https://github.com/microsoft/agent-governance-toolkit/releases/tag/v1.1.0
[1.0.1]: https://github.com/microsoft/agent-governance-toolkit/releases/tag/v1.0.1
[1.0.0]: https://github.com/microsoft/agent-governance-toolkit/releases/tag/v1.0.0
