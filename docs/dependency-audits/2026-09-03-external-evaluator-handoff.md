---
title: External Evaluator Handoff Example Dependencies
last_reviewed: 2026-09-03
owner: agt-maintainers
---

# External Evaluator Handoff Example Dependencies

## Which Dependencies Changed And Why

The new `examples/external-evaluator-handoff/requirements.txt` declares two
bounded dependencies for the standalone example:

- `agent-governance-toolkit-core>=5.0.0,<6.0` supplies the existing
  `DecisionBOM` model and the public `sha256_jcs` digest helper. The v5 floor is
  required so the example does not teach direct use of a raw cryptographic
  primitive outside the SDK boundary.
- `pytest>=8.0.0,<10.0` is used only to run the example's local regression
  tests. It is not imported by the runnable example.

These dependencies are isolated to the example and do not change any AGT
package or repository-wide runtime dependency.

## Security Advisory Relevance

This change is not a security-advisory remediation and does not add a new
cryptographic implementation. Content digests are delegated to AGT's existing
public SDK helper. `pytest` is test-only, and the repository's dependency
review and vulnerability checks remain authoritative for the resolved graph.

## Breaking Change Risk Assessment

**Risk: low and example-local.** The example requires AGT core v5 because the
public digest helper is part of that supported surface. Users pinned to AGT
core v4 cannot run this example without upgrading, but no existing package,
API, policy, or runtime behavior is changed. The upper bounds keep resolution
within the currently supported major versions.

## Validation And Rollback

Validation covers the example test suite, formatting and lint checks, strict
JSON output, documentation links, and the repository dependency and
unauthorized-crypto gates. Rollback consists of removing the standalone
example and this audit record; no production data or migration is involved.
