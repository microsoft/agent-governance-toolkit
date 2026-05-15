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

### Fixed
- `02-episodic-memory-demo.ipynb`: aligned all code cells with emk 3.2.2 / agent-os 3.2.2 API
  - `episode.id` → `episode.episode_id` (correct field name)
  - `store.list_all()` → `store.retrieve()` (method removed)
  - `store.retrieve(query=str, k=n)` → `store.retrieve(limit=n)` (FileAdapter uses filter-based retrieval; use ChromaDBAdapter for semantic search)
  - `len(store)` → `len(store.retrieve())` (FileAdapter has no `__len__`)
  - `fail.failure_reason` → `fail.metadata.get('failure_reason')` (nested in metadata)
  - `compressor` result keys aligned: `compressed_count`, `rules_created` (not `episodes_processed`, `rules_generated`)
  - `result['rules']` → `compressor.retrieve_rules()` (method on compressor instance, returns `List[SemanticRule]`)
  - `SemanticRule` attribute access: `.rule`, `.context`, `.confidence` (not `['pattern']`, `['insight']`)
  - `from agent_os import KernelSpace` → conditional import with `ImportError` guard (requires `agent-control-plane`)
  - Summary markdown Quick Reference updated to match actual API
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
