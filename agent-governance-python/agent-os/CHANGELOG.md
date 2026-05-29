# Changelog

All notable changes to Agent OS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- **Broadened SSN PII regex across integration adapters** ([#2635](https://github.com/microsoft/agent-governance-toolkit/issues/2635), [#2636](https://github.com/microsoft/agent-governance-toolkit/pull/2636)) — the dashed-only `\b\d{3}-\d{2}-\d{4}\b` regex used by the LangChain, AutoGen, CrewAI, and Bedrock adapters to detect SSNs in memory writes and outbound messages was trivially bypassed by space-, dot-, or no-separator variants such as `123 45 6789`, `123.45.6789`, and `123456789`. The pattern is now `\b\d{3}[\s.-]?\d{2}[\s.-]?\d{4}\b`, matching the YAML policy pack fix from [#2594](https://github.com/microsoft/agent-governance-toolkit/pull/2594) / [#2469](https://github.com/microsoft/agent-governance-toolkit/issues/2469).
- `POST /api/v1/execute` now fails closed by default and no longer trusts
  caller-asserted `agent_id` values before policy, audit, and rate-limit
  enforcement.

### Changed
- **Consolidated PII detection patterns into a single shared constant** in `agent_os.integrations.base` ([#2635](https://github.com/microsoft/agent-governance-toolkit/issues/2635)). The four per-adapter copies (`langchain_adapter`, `autogen_adapter`, `crewai_adapter`, `bedrock_adapter`) now import the shared `PII_PATTERNS` tuple so future adapters cannot silently drift out of sync. The shared constant is the union of patterns previously used across all four adapters, which means LangChain, AutoGen, and CrewAI now also block credit-card PII (previously a Bedrock-only check). `bedrock_adapter._PII_RE` remains as a back-compat alias to the shared constant.
- Execute requests must now present `Authorization: Bearer <token>` bound to an
  agent identity through `MCPSessionAuthenticator`, unless you explicitly opt
  into local-only unsafe mode.
- `ExecuteRequest.agent_id` is now optional; when present, it must match the
  authenticated agent identity derived from the bearer token.
- If execute auth is not configured, unauthenticated requests now return `503`
  instead of running with a caller-supplied identity.

### Added
- **`BackendDecision` assurance fields**: optional `proof_artefact: str | None`
  (content-address of an underlying proof, e.g. `sha256:…`) and
  `verification_pointers: dict[str, str]` (named URLs for offline re-verification)
  on `agent_os.policies.backends.BackendDecision`. High-assurance external
  backends (SMT-verified gates, mechanised-proof PDPs, TEE-attested PDPs) can
  populate them; `PolicyEvaluator._evaluate_flat` propagates non-empty values
  into `PolicyDecision.audit_entry`. Fully additive — existing `OPABackend` and
  `CedarBackend` are unaffected and audit consumers see no new keys until a
  backend supplies them.
- `AGENT_OS_EXECUTION_TOKENS="agent-id=token"` for packaged-server bootstrap
  credentials. These tokens remain valid for the life of the process unless
  revoked explicitly.
- **Google ADK `GovernancePlugin`**: Runner-scoped governance via ADK's
  `BasePlugin` with all 12 lifecycle hooks (before/after run, model, tool,
  agent, plus event and user-message callbacks).
- **`ADKExecutionContext`**: Per-run state tracking dataclass with invocation
  ID, agent names, token usage (`prompt_tokens`, `completion_tokens`),
  model call count, and cancellation flag.
- **SIGKILL / cancellation**: `GoogleADKKernel.cancel_run()` and
  `is_cancelled()` for immediate run termination with audit trail.
- **`GoogleADKKernel.as_plugin()`**: Factory method for one-line `Runner`
  plugin registration.
- **Enhanced `health_check()`**: Now includes `model_calls`, `token_usage`,
  `cancelled_runs`, and `context_count` metrics.

### Migration Notes
- Configure `GovServer(execute_authenticator=...)` or set
  `AGENT_OS_EXECUTION_TOKENS` before exposing `/api/v1/execute`.
- `AGENT_OS_ALLOW_UNAUTHENTICATED_EXECUTE=true` is available only as an unsafe
  local-development escape hatch. It restores caller-asserted identity behavior
  and should not be used in shared or production environments.

## [1.0.0] - 2026-01-26

### Added - Monorepo Creation
- Unified 10 packages into single `agent-os` monorepo
- Preserved full git history from all original repositories (742 commits)
- Created unified `pyproject.toml` with optional dependencies for each layer

### Packages Included

#### Layer 1: Primitives
- **primitives** (v0.1.0) - Base failure types and models
- **cmvk** (v0.2.0) - CMVK — Verification Kernel
- **caas** (v0.2.0) - Context-as-a-Service RAG pipeline
- **emk** (v0.1.0) - Episodic Memory Kernel

#### Layer 2: Infrastructure
- **iatp** (v0.4.0) - Inter-Agent Trust Protocol with IPC Pipes
- **amb** (v0.2.0) - Agent Message Bus
- **atr** (v0.2.0) - Agent Tool Registry

#### Layer 3: Framework
- **control-plane** (v0.3.0) - Agent Control Plane with kernel architecture

#### Layer 4: Intelligence
- **scak** (v2.0.0) - Self-Correcting Agent Kernel
- **mute-agent** (v0.2.0) - Reasoning/Execution decoupling

### New Features (v0.3.0 Control Plane)
- **Signal Handling**: POSIX-style signals (SIGSTOP, SIGKILL, SIGPOLICY, SIGTRUST)
- **Agent VFS**: Virtual File System with mount points (/mem/working, /mem/episodic, /state)
- **Kernel/User Space**: Protection rings, syscall interface, crash isolation
- **Typed IPC Pipes**: Policy-enforced inter-agent communication

### Documentation
- Unified architecture documentation in `/docs`
- AIOS comparison document
- Package-specific docs consolidated under `/docs/packages`

### Examples
- carbon-auditor: Reference implementation for Voluntary Carbon Market
- sdlc-agents: SDLC automation agents
- self-evaluating: Research POC for self-evolving agents

## Package Version History

### control-plane
- v0.3.0 - Kernel architecture (signals, VFS, kernel space)
- v0.2.0 - Lifecycle management (health, recovery, circuit breaker)
- v0.1.0 - Initial release

### iatp
- v0.4.0 - Typed IPC Pipes
- v0.3.1 - agent-primitives integration
- v0.3.0 - Policy engine, recovery

### scak
- v2.0.0 - Layer 4 architecture, agent-primitives integration
- v1.0.0 - Initial release

### primitives
- v0.1.0 - Initial release (FailureType, FailureSeverity, AgentFailure)

---

## Original Repository Archives

The following repositories have been archived (renamed with `-archived` suffix):
- agent-primitives-archived
- cmvk-archived
- caas-archived
- emk-archived
- iatp-archived
- amb-archived
- atr-archived
- agent-control-plane-archived
- scak-archived
- mute-agent-archived
- carbon-auditor-swarm-archived
- sdlc-agents-archived
- self-evaluating-agent-archived
