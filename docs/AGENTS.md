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
- When documenting repo layout, treat standalone language SDKs at the repository root as a valid
  first-party pattern. Use `agent-governance-python/` as the canonical Python package path,
  `agent-governance-dotnet/` as the canonical .NET path, and `agent-governance-golang/` as the
  matching sibling pattern.
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

## Docs Quality Tooling

The `Docs Quality` workflow (`.github/workflows/docs-quality.yml`) runs on every
PR that touches markdown. It enforces two checks:

| Check | Script | Mode |
|-------|--------|------|
| Relative link validation | [scripts/docs/check_links.py](../scripts/docs/check_links.py) | **strict** — broken links fail CI |
| Frontmatter validation | [scripts/docs/check_frontmatter.py](../scripts/docs/check_frontmatter.py) | **warn-only** for now; flipped to strict in the IA capstone PR |

Run them locally before opening a PR:

```bash
python scripts/docs/check_links.py
python scripts/docs/check_frontmatter.py
```

The link checker uses a baseline allowlist at
[scripts/docs/.linkcheck-baseline.txt](../scripts/docs/.linkcheck-baseline.txt)
recording broken links that pre-date this gate. New findings outside the
baseline fail CI. As docs IA work fixes existing entries, remove the
matching lines from the baseline — never add new entries by hand. To
regenerate after a sanctioned bulk fix:

```bash
python scripts/docs/check_links.py --update-baseline
```

### Required frontmatter (target state)

New and edited docs pages should include:

```yaml
---
title: Page Title
last_reviewed: 2026-05-19   # ISO date, YYYY-MM-DD
owner: docs-team            # team or maintainer handle
---
```

`last_reviewed` is a freshness signal — bump it whenever you meaningfully revise
a page. The link checker resolves relative links, URL-encoded paths, and
heading anchors (GitHub-style slug). Directory targets are accepted if the
directory exists (matching GitHub's folder rendering); pass
`--require-directory-index` for strict MkDocs-style validation. Targets that
resolve outside the repository root are rejected. External URLs (`http`,
`https`, `mailto`) are not network-validated.
