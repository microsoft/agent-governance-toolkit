# Security

## Reporting

Please report security vulnerabilities via https://github.com/microsoft/agent-governance-toolkit/security/advisories

For ScopeBlind-specific issues: tommy@scopeblind.com

## Design

This integration does not handle cryptographic material directly.
Receipt verification and key management are delegated to the `protect-mcp` runtime
and the `@veritasacta/verify` offline verifier.
