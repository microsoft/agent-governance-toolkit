# Changelog

All notable changes to the CMVK — Verification Kernel will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-01-21

### Changed
- **BREAKING**: Renamed package from `src` to `verification_kernel`
  - All imports must now use `from verification_kernel import ...`
  - CLI entry point updated to `verification_kernel.cli:app`
- Reorganized documentation into `docs/` directory
- Reorganized tests into `tests/unit/` and `tests/integration/`
- Moved example scripts to `examples/` directory
- Updated `.pre-commit-config.yaml` to v5.0.0 hooks
- Modernized `.gitignore` with comprehensive patterns

### Added
- `src/verification_kernel/__main__.py` for `python -m` support
- `CONTRIBUTING.md` with development guidelines
- `requirements-dev.txt` for contributors
- `tests/conftest.py` with shared pytest fixtures
- Merged `docs/getting_started.md`
- Professional README.md with badges and quick start guide

### Removed
- Redundant files: `IMPLEMENTATION_COMPLETE.md`, `IMPLEMENTATION_SUMMARY.md`,
  `PROJECT_COMPLETE.md`, `NEXT_STEPS.md`, `LAUNCH_CHECKLIST.md`, `hf_readme.md`
- Old `sys.path` hacks in example files

## [Unreleased]

### Added
- Anthropic Claude verifier support
- CLI interface with `cmvk` command
- Reproducibility controls with seed configuration
- `pyproject.toml` for modern Python packaging
- GitHub Actions CI/CD pipeline
- Docker multi-stage build
- Pre-commit configuration
- **LICENSE** file (MIT)

### Changed
- Pinned all dependency versions in `requirements.txt`
- Updated README with installation via pip, CLI usage, and Docker instructions
- Improved configuration handling with seed support

## [1.0.0] - 2024-01-21

### Added
- Initial release of CMVK — Verification Kernel
- Drift detection and comparison utilities
- Trace logging and visualization system
- Configuration via YAML files
- Basic test suite

### Security
- Basic sandbox isolation for code execution
- API key handling via environment variables

---

## Version History

- **1.0.0**: Initial release with drift detection
- **1.1.0**: Package restructure, Anthropic support, CLI
