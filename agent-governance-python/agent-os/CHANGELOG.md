# Changelog

All notable changes to Agent OS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
