# Agent Governance Toolkit v3.7.0

**Release Date:** 2026-05-18

> [!IMPORTANT]
> **Public Preview** - All packages published from this repository are
> **Microsoft-signed public preview releases**. They are production-quality but
> may have breaking changes before GA.

## Highlights

### Version Bump and Release Hygiene

v3.7.0 opens the next development cycle with full release documentation for the
v3.6.0 milestone that was previously undocumented.

### Tool Usage Policies (oracle/agent-spec)

Contributed the `ToolPolicy` schema to the Agent Spec standard (PR #191),
enabling declarative rate-limit, approval, and justification guards on tool
invocations. AGT will adopt the ratified schema once merged upstream.

## Added

- **v3.6.0 release notes** documenting the full scope of the previous release
- **Presentation demos** committed to `examples/demos/presentation/` (6 offline scripts)
- **EU AI Act demo** Windows UTF-8 fix
- **StdoutAuditSink** overlapping merge fix
- **Repo structure** simplified with layout guide
- **Tutorials** reorganized into customer-centric categories

## Packages

| Package | Version |
|---------|---------|
| `agent-governance-toolkit` (meta) | 3.7.0 |
| `agent-os-kernel` | 3.7.0 |
| `agentmesh-platform` | 3.7.0 |
| `agentmesh-runtime` | 3.7.0 |
| `agent-sre` | 3.7.0 |
| `agent-compliance` | 3.7.0 |
| `agent-rag-governance` | 3.7.0 |
| `agent-hypervisor` | 3.7.0 |
| `agent-lightning` | 3.7.0 |
| `agentmesh-marketplace` | 3.7.0 |

## Upgrade Guide

```bash
pip install --upgrade agent-governance-toolkit[full]
agt doctor  # verify installation
agt verify  # confirm OWASP ASI 2026 compliance
```

No breaking changes from v3.6.0.
