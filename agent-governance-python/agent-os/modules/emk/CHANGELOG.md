# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Hugging Face Hub integration (`emk.hf_utils`) for dataset sharing
- Reproducible experiment runner (`experiments/reproduce_results.py`)
- Research paper structure (`paper/whitepaper.md`, `paper/structure.tex`)
- GitHub Actions CI/CD workflows for testing and PyPI publishing
- CONTRIBUTING.md with development guidelines
- PEP 561 `py.typed` marker for typed package support
- `get_version_info()` function for runtime feature detection

### Changed
- Enhanced `__init__.py` with better exports and metadata
- Updated `pyproject.toml` with additional classifiers and keywords
- Added Python 3.12 support

## [0.1.0] - 2026-01-23

### Added
- Initial release of EMK (Episodic Memory Kernel)
- `Episode` schema with immutable, content-addressed storage
- `VectorStoreAdapter` abstract interface
- `FileAdapter` for JSONL-based local storage
- `ChromaDBAdapter` for vector similarity search (optional)
- `Indexer` utilities for tag generation and search text creation
- Comprehensive test suite with 71% coverage
- Basic usage examples

### Security
- Fixed tempfile.mktemp() usage (CodeQL)
- Fixed potential metadata mutation issues

[Unreleased]: https://github.com/microsoft/agent-governance-toolkit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/microsoft/agent-governance-toolkit/releases/tag/v0.1.0
