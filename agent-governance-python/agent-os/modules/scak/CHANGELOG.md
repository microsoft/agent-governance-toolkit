# Changelog

All notable changes to the Self-Correcting Agent Kernel (SCAK) project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-01-18

### Added
- Real LLM integrations (OpenAI GPT-4o, o1-preview, Anthropic Claude 3.5 Sonnet)
- Multi-agent orchestration framework with supervisor, analyst, and verifier roles
- Dynamic tool registry with multi-modal support (text, vision, audio, code)
- Streamlit dashboard for real-time monitoring and visualization
- CLI tool (`scak`) for agent management and benchmarks
- Docker Compose setup for production deployment

### Enhanced
- Telemetry system with structured JSON logging
- Test suite expanded to 183+ tests

### Fixed
- Async/await patterns for non-blocking I/O throughout
- Type safety with Pydantic v2 models
- Error handling with structured telemetry (no silent failures)

## [1.0.0] - 2026-01-15

### Added
- Core self-correction loop with failure detection
- Configurable retry strategies
- Three-tier memory hierarchy
- Basic triage for failure routing

### Documentation
- Contributing guidelines

## [0.1.0] - 2025-12-01

### Added
- Initial release of Self-Correcting Agent Kernel
- Basic failure detection and correction
- Simple prompt patching mechanism
- Core data models with Pydantic
- Basic telemetry and logging
- Initial test suite (50+ tests)
- Example scripts and demos

---

## Version History Summary

- **v1.1.0** (2026-01-18): Production-ready with LLM integrations, multi-agent orchestration
- **v1.0.0** (2026-01-15): Complete self-correction architecture
- **v0.1.0** (2025-12-01): Initial prototype release

---

**Maintained by:** Self-Correcting Agent Team
**License:** MIT
