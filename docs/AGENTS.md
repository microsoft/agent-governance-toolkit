# Documentation - Coding Agent Instructions

## Project Overview

The `docs/` tree powers the published documentation site for Agent Governance Toolkit:
reference material, tutorials, architecture docs, threat modeling, compliance content,
package pages, and integration guides.

## Key Files

| File | Purpose |
|------|---------|
| `docs/index.md` | Docs homepage and top-level navigation |
| `docs/packages/` | Package landing pages and package-specific docs |
| `docs/tutorials/` | Step-by-step guides |
| `docs/integrations/` | External integration guides |
| `docs/security/` | Threat model, OWASP, security guidance |
| `mkdocs.yml` | Site navigation and build configuration |

## Documentation Conventions

- Be precise and honest; do not claim a feature is shipped unless the repo actually contains it.
- Prefer updating an existing page over creating a near-duplicate page.
- Use repo-relative links that work from the current document location.
- Match existing tone: technical, direct, and evidence-based.
- Keep package names, CLI commands, and install snippets aligned with the actual repo.
- When documenting third-party integrations, explain whether they are examples, adapters,
  or maintained first-party surfaces.

## Content Boundaries

- Do not introduce new ecosystem claims, benchmarks, or adoption numbers without a source.
- Do not add translated docs unless explicitly requested; keep the source English page correct first.
- Do not hide limitations. If behavior is partial or experimental, say so clearly.
- Avoid copying large blocks of vendor docs; summarize and attribute instead.

## When Code Changes Need Docs

- Public API changes should update the nearest package page or tutorial.
- New examples should usually update docs discoverability at least once.
- Security-sensitive changes should review `docs/security/` and `docs/THREAT_MODEL.md`.

## Validation

- Check that links, file paths, and fenced code blocks are valid.
- Keep headings and page titles stable unless a rename is intentional.
