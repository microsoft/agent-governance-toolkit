# Changelog

All notable changes to Agent SRE will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `MeasurementStore` ABC with `InMemoryMeasurementStore` (thread-safe, default) and
  `SQLiteMeasurementStore` (durable, survives agent restarts) backends for SLI
  measurement persistence — closes #645.
- `CalibrationDeltaSLI`: new built-in SLI that tracks the running gap between an
  agent's stated confidence and its empirical success rate (calibration drift).
  Registered in `SLIRegistry` by default.  Reference: PDR DOI 10.5281/zenodo.19339987.
- `SLI.__init__` and all built-in SLI subclasses now accept an optional `store`
  keyword argument.  Omitting it preserves identical backward-compatible behaviour.
- `_validate_db_path()` utility function rejects non-file URI schemes (e.g. `http://`)
  passed to `SQLiteMeasurementStore`.
- 26 new tests in `tests/unit/test_sli_persistence.py` covering both stores,
  thread-safety, SQLite durability, input validation, and `CalibrationDeltaSLI`.

### Changed
- `InMemoryMeasurementStore` is now thread-safe (uses `threading.Lock`).
- `SLI._measurements` is preserved as a backward-compatible alias pointing into
  the in-memory store's row list when the default backend is used.

### Fixed
- Burn alerts now evaluate errors over each alert's declared window instead of
  the default one-hour window, allowing errors from one to 24 hours ago to
  correctly raise SLO status to WARNING or CRITICAL.
- **Provider fallbacks on the default install.** Without an advanced provider,
  `get_slo_detector()` and `get_chaos_engine()` raise a `NotImplementedError` naming
  the missing class and the entry point group a provider package must register,
  instead of an `ImportError` for classes that never existed (#4152).
- `list_providers()` reports `"unavailable"` instead of `"community"` for the
  `slo_detection` and `chaos_engine` slots when no advanced provider is installed,
  since they have no community implementation.

## [0.3.0] - 2026-02-19

### Added
- ARCHITECTURE.md documenting 7-engine architecture
- OpenTelemetry integration for distributed tracing
- SLO-as-Code YAML definitions with error budgets
- Incident runbook templates for common agent failures
- Golden signal traces for agent observability
- Chaos scheduling engine with 9 fault templates
- Blue-green deployment support for agent rollouts
- Cost optimization engine with budget guardrails
- Prometheus/Grafana dashboards for SLO monitoring
- GitHub Actions canary deployment action

### Changed
- Improved burn rate alert thresholds
- Enhanced error budget calculation precision

## [0.2.0] - 2026-02-01

### Added
- Core SLO Engine with 7 SLI types
- Replay Engine for deterministic capture/replay
- Progressive Delivery engine (shadow, canary, rollback)
- Chaos Engineering engine with fault injection
- Cost Guard engine with anomaly detection
- Incident Manager with auto-detection and postmortem
- Full test suite

## [0.1.0] - 2026-01-26

### Added
- Initial release
- Basic SLO definitions and evaluation
- Error budget tracking
- Agent OS and AgentMesh integration
