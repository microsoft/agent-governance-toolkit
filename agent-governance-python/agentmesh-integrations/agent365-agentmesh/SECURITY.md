# Security

This package is part of the [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit).

## Reporting Vulnerabilities

**Please do not report security vulnerabilities through public GitHub issues.**

For security reporting, please follow the guidance at the root repository:
https://github.com/microsoft/agent-governance-toolkit/blob/main/SECURITY.md

## Security properties of this package

- **Threat detection fails closed when it can answer.** Copilot Studio treats
  a reply slower than 1,000 ms as "allow". The handler evaluates under an
  internal budget (700 ms by default) and returns `blockAction: true` on
  timeout, evaluation error or malformed input. A network outage or a
  host that cannot answer at all remains fail-open by Copilot Studio's design.
- **Callers must be authenticated and allow-listed.** `create_app` requires a
  token verifier and a non-empty set of caller application IDs.
- **Purview errors block by default** (`fail_closed=True`).
- **Graph pagination stays on Microsoft Graph.** `iter_agent_identities`
  refuses `@odata.nextLink` values outside the configured Graph root so that a
  tampered response cannot redirect the bearer token.
- **No invented identities.** Registry sync never derives AgentMesh DIDs from
  Entra data; the caller supplies the mapping.
