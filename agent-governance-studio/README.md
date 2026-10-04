# AGT Studio

AGT Studio is the unified UI for the Agent Governance Toolkit.

## Status

Public Preview.

## Scope

This package provides the initial Python package and frontend scaffold for AGT Studio. Product UI capabilities, Engine API integration, transport abstractions, navigation, and operational workflows are deferred to later issues.

## Related design

- [AGT Studio Epic #2729](https://github.com/microsoft/agent-governance-toolkit/issues/2729)
- [ADR 0028 — AGT Studio unified UI](../../docs/adr/0028-agt-studio-unified-ui.md)

## Development

### Python

```bash
python -m build agent-governance-studio
python -m pytest agent-governance-studio/tests -q
ruff check agent-governance-studio/src agent-governance-studio/tests --select E,F,W --ignore E501
```

### Frontend

```bash
npm ci --prefix agent-governance-studio/web
npm run lint --prefix agent-governance-studio/web
npm test --prefix agent-governance-studio/web
npm run build --prefix agent-governance-studio/web
```

## Deferred work

The initial scaffold does not include `agt ui`, `agt serve`, Engine API calls, transport abstractions, policy screens, navigation, or operational write-path actions. These are addressed by subsequent AGT Studio issues.