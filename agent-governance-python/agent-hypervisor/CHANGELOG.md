# Changelog

All notable changes to Agent Hypervisor will be documented in this file.

## [2.0.0] — 2026-02-20

### Added — Observability
- **Structured Event Bus** (`observability/event_bus.py`) — append-only event store with typed events, pub/sub, and multi-index queries (by type, agent, session, time range)
- **Causal Trace IDs** (`observability/causal_trace.py`) — distributed tracing with full spawn/delegation tree encoding (not just correlation IDs)

### Added — Ring Improvements
- **Dynamic Ring Elevation** (`rings/elevation.py`) — time-bounded privilege escalation (like `sudo` with TTL), auto-expiry, manual revocation
- **Ring Inheritance** — child agents inherit parent ring - 1 (prevents privilege escalation via spawning)
- **Ring Breach Detector** (`rings/breach_detector.py`) — sliding window anomaly scoring for ring call patterns, circuit breaker on HIGH/CRITICAL severity

### Added — Liability Improvements
- **Fault Logging** (`liability/attribution.py`) — Shapley-value inspired proportional fault scoring (replaces binary guilty/not-guilty)
- **Quarantine Manager** (`liability/quarantine.py`) — read-only isolation before termination, forensic data preservation, auto-release with timeout
- **Persistent Liability Ledger** (`liability/ledger.py`) — per-agent historical risk scoring, admission decisions (admit/probation/deny)

### Added — Saga Improvements
- **Parallel Fan-Out** (`saga/fan_out.py`) — concurrent branch execution with `ALL_MUST_SUCCEED`, `MAJORITY_MUST_SUCCEED`, `ANY_MUST_SUCCEED` policies
- **Execution Checkpoints** (`saga/checkpoint.py`) — capture what goal was achieved (not just state), enabling partial replay without re-running completed effects
- **Declarative Saga DSL** (`saga/dsl.py`) — define saga topology via dict/YAML with validation, fan-out support, and SagaStep conversion

### Added — Session Improvements
- **Version Counters** (`session/vector_clock.py`) — causal consistency enforcement, stale-write rejection, automatic merge on read
- **Resource Locks** (`session/intent_locks.py`) — READ/WRITE/EXCLUSIVE lock declarations with contention detection and lock timeout prevention (wait-for graph)
- **Isolation Levels** (`session/isolation.py`) — SNAPSHOT, READ_COMMITTED, SERIALIZABLE per saga (low-stakes sagas skip coordination cost)

### Added — Security
- **Agent Rate Limiter** (`security/rate_limiter.py`) — token bucket per agent per ring, configurable limits, automatic refill
- **Kill Switch** (`security/kill_switch.py`) — graceful agent termination with in-flight saga step handoff to substitute agents

### Changed
- Package version bumped to 2.0.0
- 58 public exports (up from 28)
- **326 tests** (up from 184)

## [1.0.0] — 2026-02-20

### Added
- **Core Hypervisor** orchestrator with session lifecycle management
- **Shared Session Object (SSO)** with VFS, snapshots, and consistency modes
- **4-Ring Execution Model** (Ring 0 Root → Ring 3 Sandbox) based on eff_score trust scores
- **Joint Liability Engine** with sponsorship, bonding, and proportional penalty
- **Saga Orchestrator** with step timeouts, retries, and reverse-order compensation
- **Audit-Logged Trail** with delta capture, commitment engine, and ephemeral GC
- **Reversibility Registry** for execute/undo API mapping with 4 reversibility levels
- **Transaction History Verifier** for DID-based trust verification
- **Integration Adapters** (Protocol-based, zero hard dependencies):
  - Nexus adapter — trust score resolution and caching
  - Verification adapter — behavioral drift detection with severity thresholds
  - IATP adapter — capability manifest parsing and trust hints
- **184 tests** (unit, integration, and scenario tests)
- **Performance benchmarks** (268μs full pipeline)
- **Interactive demo** (`examples/demo.py`) showcasing all 5 subsystems
- Extracted from [Agent OS](https://github.com/microsoft/agent-governance-toolkit) as standalone package
