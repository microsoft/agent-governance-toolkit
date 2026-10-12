---
title: TypeScript 7 toolchain upgrade across three packages
last_reviewed: 2026-09-24
owner: Ricky-G
---

# TypeScript 7 toolchain upgrade across three packages

## Which dependencies changed and why

The SDK, Copilot extension, and MCP server move their build compiler from
`typescript@6.0.3` to `typescript@7.0.2`. Because TypeScript 7.0 does not expose
the TypeScript 6 JavaScript compiler API, `@typescript/native` aliases the
TypeScript 7 compiler and the official `@typescript/typescript6@6.0.2`
compatibility package supplies the
TypeScript 6 API to ESLint and `ts-node`. The compatibility package resolves
the previous compiler API through `typescript@6.0.3`. Build and test typecheck
scripts invoke `node node_modules/@typescript/native/bin/tsc` explicitly to
avoid npm selecting the compatibility compiler based on bin-link order.

The SDK and Copilot extension replace `ts-jest@29.4.12`, which requires
TypeScript below 7, with `@swc/jest@0.2.39` and `@swc/core@1.16.2`. Test files
are typechecked with TypeScript 7 before Jest runs, so the transform change
does not remove the existing test typecheck. The MCP server keeps Vitest.
All three lockfiles were regenerated with exact direct versions and public
npm registry URLs. The local mirror supplied SHA1-only pins; each tarball was
checked against its original SHA1 before recording its SHA512 digest. The
upstream registry integrity check in CI must also confirm these digests.

These versions were released more than seven days before this update. The
TypeScript compatibility package is published by the TypeScript team; SWC
uses platform-specific optional packages and declares a postinstall script.
CI installs dependencies with `--ignore-scripts`, and clean local installs,
builds, and tests succeeded with the script disabled. New dependency names
and install scripts require the repository's normal supply-chain review.

## Security advisory relevance

This is a compiler and test toolchain upgrade, not an advisory-specific fix.
No production dependency is added; SWC and both compiler versions are
development dependencies.

## Breaking change risk assessment

TypeScript 7 removes the old `node10` module resolution mode, so the SDK and
Copilot extension use `NodeNext`. The compiler and the tools that consume the
TypeScript 6 API are intentionally separate. SWC changes only Jest's
transformation; TypeScript 7 checks the test files before execution.

Clean installs, builds, and lint passed in all three packages. The SDK passed
625 tests across 40 suites; the Copilot extension passed 13 tests across two
suites. The MCP server's existing Vitest command has no test files and exits
successfully with `--passWithNoTests`; its build, typecheck, and CLI help
command passed. The new extension ESLint configs provide syntax checks, matching
the existing SDK config's parser-only setup; TypeScript performs type checking.
The MCP server's generated declaration files have type-equivalent ordering and
quote-style changes under TypeScript 7, while its emitted JavaScript is unchanged.
The new native compiler is packaged for multiple operating systems, so repository
CI must also confirm the Linux install and checks.

## Rollback plan

Revert the TypeScript 7 compiler aliases, SWC Jest configuration, TypeScript
configuration updates, and corresponding lockfiles together. Reverting only
the compiler would leave tests and lint on mismatched toolchains.
