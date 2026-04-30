# Changelog

All notable changes to Agent OS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- `POST /api/v1/execute` now fails closed by default and no longer trusts
  caller-asserted `agent_id` values before policy, audit, and rate-limit
  enforcement.

### Changed
- Execute requests must now present `Authorization: Bearer <token>` bound to an
  agent identity through `MCPSessionAuthenticator`, unless you explicitly opt
  into local-only unsafe mode.
- `ExecuteRequest.agent_id` is now optional; when present, it must match the
  authenticated agent identity derived from the bearer token.
- If execute auth is not configured, unauthenticated requests now return `503`
  instead of running with a caller-supplied identity.

### Added
- **Native hooks for Anthropic, Semantic Kernel, smolagents, PydanticAI**:
  All four adapters now expose a non-invasive factory method that returns a
  native framework hook instead of a proxy wrapper:
  - `AnthropicKernel.as_message_hook()` → `GovernanceMessageHook`
  - `SemanticKernelWrapper.as_filter()` → `GovernanceFunctionFilter`
  - `SmolagentsKernel.as_step_callback()` → `GovernanceStepCallback`
  - `PydanticAIKernel.as_capability()` → `GovernanceCapability`
- All new hook classes exported from `agent_os.integrations`.
- UUID-based session identifiers prevent collision on rapid instantiation.

### Deprecated
- `AnthropicKernel.wrap()` / `wrap_client()` → use `as_message_hook()`
- `SemanticKernelWrapper.wrap()` / `wrap_kernel()` → use `as_filter()`
- `SmolagentsKernel.wrap()` → use `as_step_callback()`
- `PydanticAIKernel.wrap()` / module-level `wrap()` → use `as_capability()`

  All deprecated methods emit a `DeprecationWarning` with a migration hint and
  will be removed in the next major release.

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
