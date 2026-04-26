# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-01-23

### Added

#### Layer 3: Dependency Injection Architecture
- **KernelInterface**: Abstract interface for custom kernel implementations
- **Plugin Interfaces**: Extensible component architecture for validators, executors, routers
- **Protocol Interfaces**: Integration points for Layer 2 protocols
- **PluginRegistry**: Central dependency injection system with runtime registration

### Changed

- **AgentControlPlane**: Now supports dependency injection
  - New `use_plugin_registry` parameter for plugin-based architecture
  - New parameters for injecting custom implementations

### Documentation

- Added architecture guides for Layer 3

### Dependency Policy

- **Allowed Dependencies**: iatp, cmvk, caas (optional protocol integrations)
- **Forbidden Dependencies**: scak, mute-agent (must implement interfaces instead)

## [1.1.0] - 2026-01-18

### Added

#### Safety & Anomaly Detection
- Pattern-based jailbreak detection with 60+ attack vectors
- Behavioral anomaly detection for agent actions

#### Compliance & Regulatory Frameworks
- Multi-framework compliance checking (EU AI Act, SOC 2, GDPR, HIPAA)
- Value alignment framework

#### Multimodal Capabilities
- Image and audio analysis support
- Vector store integration (in-memory, Pinecone, Weaviate, ChromaDB, Qdrant, Milvus)
- RAG pipeline

#### Production Observability
- Prometheus metrics export
- Rule-based alerting system
- Distributed tracing (OpenTelemetry-compatible)

### Enhanced
- Comprehensive test coverage: 196 tests

### Documentation
- Example scripts for all new features

## [0.1.0] - 2025-01-11

### Added
- Initial release of Agent Control Plane
- Core agent kernel functionality
- Policy engine with rate limiting and quotas
- Execution engine with sandboxing
- Comprehensive test suite (31 tests)
- Example scripts and documentation
- CI/CD with GitHub Actions
- MIT License
