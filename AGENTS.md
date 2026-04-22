# Agent Governance Toolkit - Repository Instructions

## Project Overview

Agent Governance Toolkit is a multi-package OSS monorepo for runtime governance of AI agents:
policy enforcement, zero-trust identity, execution sandboxing, SRE, compliance, examples,
docs, demos, SDKs, and publishing pipelines.

Use this file for repository-wide routing. When you enter a subdirectory that has its own
`AGENTS.md`, that narrower file takes precedence.

## Repository Layout Status

This routing reflects the repo **as it exists today** while reserving room for approved language
SDK migrations. Language SDKs may live in **standalone top-level directories** at the repository
root. For contributor routing, treat `agent-governance-dotnet/` as the canonical .NET home, with
`agent-governance-golang/` as the matching sibling pattern for Go and future standalone SDKs.

Treat current paths as a **point-in-time representation**, not a permanent architecture promise.
When a standalone top-level implementation exists for a language, changes for that language should
go there rather than into `packages/` or an older shared SDK path.

## Where Changes Belong

| Area | Path | Use it for |
|------|------|------------|
| Core Python packages | `packages/*/` | Runtime code, policy engines, trust, SRE, compliance |
| Current shared SDK paths | `packages/agent-mesh/sdks/` | Public SDK APIs and language-specific packaging that still live in the shared layout today |
| Standalone language implementations | `agent-governance-dotnet/`, `agent-governance-golang/`, and other `agent-governance-*` siblings | Top-level language-specific implementations at the repository root; use these as the canonical contributor-facing paths |
| Docs site | `docs/` | Reference docs, tutorials, architecture, package pages |
| Runnable examples | `examples/` | Self-contained integrations and worked examples |
| Interactive demos | `demo/` | Live demos, dashboards, real-service walkthroughs |
| Release pipelines | `pipelines/` | Azure DevOps ESRP publishing and release automation |
| GitHub automation | `.github/` | CI, PR automation, issue templates, CODEOWNERS |

## Routing Rules

1. Prefer the smallest correct scope for a change.
2. Put third-party integrations in `examples/` or `packages/agentmesh-integrations/` before
   expanding core packages.
3. Put marketing or ecosystem references in docs only after the integration is real, attributable,
   and useful to users.
4. Keep `.github/` changes separate from feature work; they require extra security review.
5. If both a legacy shared path and a standalone top-level path exist, prefer the standalone
   top-level path for new work unless maintainers say otherwise. For .NET, contributor guidance
   should target `agent-governance-dotnet/` as the canonical path.

## OSS Contribution Expectations

- Read the nearest `AGENTS.md` before changing code in that area.
- Keep PRs scoped to the path described in the PR.
- Add or update tests for behavior changes, bug fixes, security fixes, and new public API surface.
- Attribute prior art in PR descriptions and docs when a design borrows from another project.
- Prefer examples and docs for low-risk ecosystem additions; prefer core package changes only when
  the project has clear adoption and the integration belongs in AGT long-term.
- Do not add obscure dependencies to core paths just to support a single external project.

## Decision Escalation

Ask a maintainer before proceeding with:

- new top-level packages or modules
- cross-cutting changes across 3+ packages
- security model changes
- public breaking API changes
- new framework integrations that materially expand the core surface
- CI/CD architecture changes

## Boundaries

- Never commit secrets, credentials, or real tokens.
- Never weaken security defaults, trust thresholds, or review requirements.
- Do not mix unrelated changes into docs-only or example-only PRs.
- Preserve honesty in docs: document shipped behavior, not aspirational behavior.

## Validation

- Run the narrowest existing tests for the paths you touched.
- For bug fixes, prefer a regression test that would fail without the change.
- For docs-only changes, make sure links, commands, and file paths are still correct.
- For SDK changes, verify language-specific build and test commands in the scoped instructions.
