# Contributing to Agent Governance Toolkit

AGT welcomes code, documentation, examples, tests, bug reports, and design
proposals.

AGT is proposed for AAIF hosting in `aaif/project-proposals#19`. Until the
contribution agreement is executed, existing Microsoft CLA automation may still
run on pull requests. After transfer, the LF/AAIF contribution process supersedes
the Microsoft CLA. DCO sign-off remains required unless the foundation process
explicitly replaces it.

## How to contribute

1. Fork the repository and create a feature branch from `main`.
2. Read the nearest `AGENTS.md` before changing code in that area.
3. Make the change in the smallest correct surface.
4. Add or update tests for behavior changes.
5. Run relevant validation.
6. Submit a pull request with a clear description.

## Repository routing

| If your change is about... | Start here |
|---|---|
| Published first-party Python packages | `agent-governance-python/` |
| Core governance/runtime behavior | package-local source and tests |
| Standalone language SDKs | `agent-governance-dotnet/`, `agent-governance-golang/`, `agent-governance-rust/`, `agent-governance-typescript/` |
| Tutorials, architecture, package docs | `docs/` |
| Runnable framework integrations | `examples/` |
| GitHub Actions, release automation, templates | `.github/` |

## Specification changes

Normative behavior changes must follow the
[Specification Change Process](../specs/PROCESS.md). Use that process when a
change affects policy decisions, trust, audit, receipts, SDK conformance, wire
formats, security boundaries, or compatibility.

## AI-assisted contributions

AI-assisted contributions are allowed, but contributors remain responsible for
the final work. Generated code must be reviewed, understood, tested, and
attributed where required by the tool output or third-party licenses.

## Code of Conduct

This project follows the [Code of Conduct](../../CODE_OF_CONDUCT.md). During
AAIF contribution finalization, reporting paths are being aligned with LF/AAIF
project policy.
