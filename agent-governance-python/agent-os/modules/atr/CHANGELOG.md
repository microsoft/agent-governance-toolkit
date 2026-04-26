# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Hugging Face Hub integration (`atr.hf_utils`)
- Comprehensive experiment suite (`experiments/`)
- Research paper structure (`paper/`)
- GitHub Actions CI/CD workflows
- Type stubs (`py.typed` marker)

### Changed
- Enhanced `pyproject.toml` with full metadata and tool configurations
- Improved `__init__.py` with Google-style docstrings and complete exports

## [0.1.0] - 2026-01-23

### Added
- Initial release of Agent Tool Registry (ATR)
- Core `ToolSpec` schema with Pydantic validation
- `@atr.register()` decorator for tool registration
- `Registry` class for tool storage and discovery
- OpenAI Function Calling schema conversion
- Parameter type inference from Python type hints
- Cost level and side effect declarations
- Tag-based tool filtering and search

### Features
- Strict type hint enforcement (no magic arguments)
- Separation of tool discovery from execution
- Compatible with OpenAI, Anthropic, and other LLM function calling formats

[Unreleased]: https://github.com/microsoft/agent-governance-toolkit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/microsoft/agent-governance-toolkit/releases/tag/v0.1.0
