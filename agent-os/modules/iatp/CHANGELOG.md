# Changelog

All notable changes to the Inter-Agent Trust Protocol (IATP) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - 2026-01-23

### Changed
- **BREAKING**: Removed `agent-control-plane` dependency
  - IATP is Layer 2 (Infrastructure/Protocol) - it defines the protocol, not the control plane
  - Higher layers (agent-control-plane) USE IATP; IATP does not depend on them
  - Policy Engine now uses built-in `PolicyRule` class and Python `Protocol` for extensibility
- Refactored `IATPPolicyEngine` to be self-contained with duck typing
- Updated all documentation to reflect architectural changes

### Removed
- Dependency on `agent-control-plane>=1.1.0`
- External `PolicyEngine` wrapper - now uses built-in implementation

## [0.3.0] - 2026-01-22

### Added
- **Standalone Sidecar Application** (`iatp/main.py`): Production-ready FastAPI application
  - Direct uvicorn entry point: `uvicorn iatp.main:app --port 8081`
  - Environment-based configuration (IATP_AGENT_URL, IATP_TRUST_LEVEL, etc.)
  - Health check, metrics, and distributed tracing endpoints
  - Full integration with Policy Engine and Recovery Engine
- **Root Dockerfile**: Simplified Docker image for one-line deployment
  - `docker build -t iatp-sidecar .`
  - `docker run -p 8081:8081 -e IATP_AGENT_URL=http://agent:8000 iatp-sidecar`
- **Demo Client** (`examples/demo_client.py`): Interactive demonstration script
  - Shows trust negotiation, security blocks, and user override flows
  - ASCII art banner and color-coded output
- **Updated docker-compose.yml**: Complete demo environment
  - Bank Agent + Sidecar (trusted) on ports 8000/8081
  - Honeypot Agent + Sidecar (untrusted) on ports 9000/9001
  - Redis for state management
  - Legacy sidecar support via profiles

### Changed
- Renamed PyPI package from `iatp` to `inter-agent-trust-protocol` (name conflict)
- Updated QUICKSTART.md with one-line deploy instructions
- Improved documentation with access points and test commands

### Fixed
- Model field compatibility across all components
- Sidecar module import chain

## [0.2.0] - 2026-01-23

### Added
- **Go Sidecar**: Production-ready high-performance sidecar implementation in Go
  - 10k+ concurrent connection support
  - Zero-copy proxying for efficient data transfer
  - Single static binary with no runtime dependencies
  - ~10MB memory footprint
  - Dockerfile and comprehensive documentation
- **Cascading Hallucination Experiment**: Complete experimental setup to demonstrate IATP's prevention of cascading failures
  - Agent A (User), Agent B (Summarizer with poisoning), Agent C (Database)
  - Control group (no IATP) and test group (with IATP) implementations
  - Automated experiment runner with result visualization
  - Documentation for reproducing the "money slide" results
- **Docker Compose Deployment**: One-line deployment configuration
  - Complete docker-compose.yml with secure bank agent and honeypot
  - Dockerfiles for agents and Python sidecar
  - Network configuration for sidecar pattern
  - Comprehensive deployment documentation
- **PyPI Distribution Preparation**: Package ready for distribution
  - MANIFEST.in for proper file inclusion
  - Updated setup.py with proper metadata
  - CHANGELOG.md for version tracking
  - Blog post draft for community launch

### Changed
- Enhanced README with Docker deployment instructions
- Improved documentation structure across all components
- Updated examples to work with Docker deployment

### Documentation
- Added Go sidecar README with performance benchmarks
- Added experiment README with detailed instructions
- Added Docker deployment guide
- Added blog post draft for community launch

## [0.1.0] - 2026-01-15

### Added
- Initial release of IATP protocol and Python SDK
- Capability manifest schema and protocol specification
- Trust score calculation algorithm (0-10 scale)
- Security validation with credit card (Luhn) and SSN detection
- Privacy policy enforcement (block/warn/allow)
- Flight recorder for distributed tracing
- User override mechanism for risky operations
- Python sidecar implementation with FastAPI
- Integration with agent-control-plane (policy engine)
- Integration with scak (recovery engine)
- Comprehensive test suite (32 tests)
- Example agents: secure bank, untrusted/honeypot, generic backend
- Complete documentation and implementation guide

### Features
- **Trust Levels**: verified_partner, trusted, standard, unknown, untrusted
- **Reversibility**: full, partial, none
- **Retention Policies**: ephemeral, temporary, permanent
- **Policy Enforcement**:
  - Trust score >= 7: Allow immediately
  - Trust score 3-6: Warn (requires override)
  - Trust score < 3: Warn (requires override)
  - Credit card + permanent retention: Block (403)
  - SSN + non-ephemeral retention: Block (403)
- **Flight Recorder**: JSONL logging with request/response/error/blocked events
- **Distributed Tracing**: Unique trace IDs for all requests
- **Sensitive Data Scrubbing**: Automatic redaction in logs

[0.3.0]: https://github.com/microsoft/agent-governance-toolkit/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/microsoft/agent-governance-toolkit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/microsoft/agent-governance-toolkit/releases/tag/v0.1.0
