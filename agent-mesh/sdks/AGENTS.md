# AgentMesh SDKs - Coding Agent Instructions

## Project Overview

This directory contains cross-language AgentMesh SDKs:

- `typescript/`
- `rust/`
- `go/`

These SDKs should stay conceptually aligned with the trust, identity, governance, and MCP
security surfaces provided elsewhere in the repo.

## Transition Note

This directory reflects the repo layout **at this point in time**. Some language implementations
may eventually move into standalone top-level directories such as `agent-governance-golang/`,
`agent-governance-rust/`, or `agent-governance-python/`.

If that happens, treat the standalone top-level directory as the primary home for new work. This
directory should then be treated as legacy/shared-layout guidance for the code that still lives
here.

## SDK Conventions

- Preserve API parity where practical; call out intentional gaps instead of creating silent drift.
- Keep package metadata, examples, and docs aligned with the shipped API surface.
- Favor small, language-idiomatic wrappers over clever abstractions that hide security behavior.
- Update shared docs such as `docs/SDK-FEATURE-MATRIX.md` when parity materially changes.

## Boundaries

- Do not introduce breaking API changes casually.
- Do not weaken validation, trust checks, or security defaults to match another language.
- Avoid language-specific one-offs unless there is a strong ecosystem reason.

## Validation

- Run the language-specific tests for the SDK you changed.
- Confirm package names, versions, and build outputs still match publishing expectations.
