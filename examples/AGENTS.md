# Examples - Coding Agent Instructions

## Project Overview

The `examples/` directory is the preferred place for runnable, self-contained integrations and
worked examples. For OSS contributors, examples are often the best starting point for proposing
support for a new framework or ecosystem tool.

## Preferred Contribution Shape

Use `examples/` when you want to:

- demonstrate AGT with a third-party framework
- prove an integration pattern before proposing a core package change
- publish a minimal end-to-end scenario with policies and expected output

Prefer an example over a core package change when the external project is new, niche, or still
proving community demand.

## Example Conventions

- Keep examples runnable and self-contained.
- Include a README with setup, run steps, expected output, and cleanup notes.
- Attribute external projects and prior art in the README when the example is integration-driven.
- Keep dependencies minimal and explain why each one is needed.
- Use fake or placeholder secrets only; direct users to environment variables for real credentials.

## Boundaries

- Do not add obscure dependencies to the repo root just for a single example.
- Do not let example code silently become a de facto supported public API.
- Do not overstate maturity; label experimental or community-driven examples clearly.
- If an example exists mainly to promote another project, keep it out of core paths.

## Validation

- Verify the README commands still match the file layout.
- Keep example policies and sample outputs consistent with the documented scenario.
