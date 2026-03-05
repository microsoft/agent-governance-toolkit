# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Modern Python packaging with `pyproject.toml` and hatchling build backend
- Docker support with `Dockerfile` and `docker-compose.yml`
- GitHub Actions CI/CD workflows for automated testing and linting
- Pre-commit hooks configuration for code quality enforcement
- MIT License
- Comprehensive test infrastructure with pytest and coverage reporting
- Documentation for threat model, ethics, and limitations
- Multi-agent collaboration examples
- Benchmarking and evaluation framework
- Architecture documentation and diagrams

### Changed
- Updated `setup.py` to include README as long description
- Enhanced package metadata and classifiers

### Fixed
- Package distribution and PyPI publishing support

## [0.1.0] - 2026-01-21

**🎉 First Public Release!**

- **PyPI**: https://pypi.org/project/context-as-a-service/
- **Hugging Face Dataset**: https://huggingface.co/datasets/microsoft/context-as-a-service
- **GitHub**: https://github.com/microsoft/agent-governance-toolkit

### Added
- Initial release of Context-as-a-Service
- Core features:
  - Auto-ingestion of PDF, HTML, and source code
  - Auto-detection of document types and structures
  - Auto-tuning of content weights
  - Structure-aware indexing (High/Medium/Low value tiers)
  - Metadata injection for contextual enrichment
  - Time-based decay for recency prioritization
  - Tiered context (Hot/Warm/Cold) system
  - Context scoring tracking with source citations
  - Heuristic Router for fast query routing
  - Sliding Window conversation management
  - Trust Gateway for enterprise security
- FastAPI-based REST API
- CLI tool for document management and analysis
- Comprehensive test suite
- Example scripts and demo agents
- Documentation for all major features

[Unreleased]: https://github.com/microsoft/agent-governance-toolkit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/microsoft/agent-governance-toolkit/releases/tag/v0.1.0
