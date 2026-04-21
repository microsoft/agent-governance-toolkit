# Demo - Coding Agent Instructions

## Project Overview

The `demo/` directory contains live demonstrations of AGT capabilities, including real-service
walkthroughs and visual dashboards. Demos should help users see the system working end-to-end
without changing the core product contract.

## What Belongs Here

- interactive dashboards
- live governance walkthroughs
- scenario-driven demo scripts
- demo policies and supporting assets

## Demo Conventions

- Demos must clearly distinguish production behavior from illustrative scaffolding.
- Real credentials belong in environment variables or local secrets only, never in code or docs.
- Document prerequisites, expected cost, and runtime side effects.
- Prefer localhost-safe defaults and explicit opt-in for external services.
- Reuse existing packages instead of duplicating governance logic in demo scripts.

## Boundaries

- Do not add hidden dependencies or services that are not documented in the demo README.
- Do not hardcode API keys, endpoints with secrets, or tenant-specific values.
- Do not present demo-only behavior as a supported product API.
- Keep demos scoped; broad product features belong in packages, not in demo-only code.

## Validation

- Keep the documented run command accurate.
- If you add a new demo directory, add or update its README.
