# Microsoft.AgentGovernance - Coding Agent Instructions

## Project Overview

`agent-governance-dotnet/` contains the .NET SDK for Agent Governance Toolkit:
policy enforcement, execution rings, trust, SRE controls, MCP security, lifecycle management,
and auditability for .NET applications.

## Build and Test Commands

```bash
dotnet build AgentGovernance.sln
dotnet test AgentGovernance.sln
```

## Key Paths

| Path | Purpose |
|------|---------|
| `src/` | .NET implementation |
| `tests/` | xUnit coverage |
| `README.md` | Package overview and examples |
| `AgentGovernance.sln` | Solution entry point |

## Coding Conventions

- Keep public APIs clear and stable.
- Prefer explicit types and validation over convenience shortcuts.
- Match existing naming and namespace conventions.
- If a feature brings the .NET SDK closer to parity with other SDKs, update relevant docs.

## Boundaries

- Do not loosen governance checks or trust enforcement.
- Do not add hidden runtime dependencies.
- Keep secrets and tenant-specific values out of code and samples.

## Validation

- Run `dotnet test AgentGovernance.sln` after changes.
- Check README snippets if public APIs move or rename.
