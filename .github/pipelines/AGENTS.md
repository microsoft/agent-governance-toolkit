# Pipelines - Coding Agent Instructions

## Project Overview

The `pipelines/` directory contains Azure DevOps release automation, especially ESRP-backed
publishing flows for Python, npm, NuGet, Rust, and Go artifacts.

## Critical Rules

- Treat every pipeline edit as security-sensitive.
- Keep secrets, client IDs, key vault names, and certificate identifiers in pipeline secrets or
  variables, not inline in YAML.
- Pin package-install commands to explicit versions where applicable.
- Preserve least privilege and existing release gates.
- Prefer comments that explain non-obvious ESRP or platform constraints.

## What To Watch For

- Azure DevOps compile-time vs runtime variable behavior
- Windows-vs-Unix path differences in publishing tasks
- artifact naming consistency across build and publish stages
- package path correctness for monorepo publishing

## Boundaries

- Do not weaken release approvals or bypass ESRP requirements.
- Do not introduce plaintext credentials into YAML.
- Do not mix unrelated publishing changes into the same PR as product code.

## Validation

- Re-check all referenced package paths after edits.
- Verify each changed stage still matches the package name, artifact name, and target registry.
