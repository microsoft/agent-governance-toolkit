# Security Policy

## Reporting a vulnerability

Report security issues to **playplay2736@gmail.com** (Mycelium / Giskard team).

Please do **not** open public GitHub issues for security vulnerabilities.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Security model

`mycelium-agt` is a thin HTTP client. It does **not** handle private keys, secrets, or authentication credentials.

- All HTTP calls use `urllib.request` (stdlib only — no third-party HTTP deps in the default install).
- `action_ref` is a hash of public metadata — it is not a secret.
- The `verify_url` is a public endpoint; no auth token is embedded.

If your deployment requires mTLS or token-based auth for the Mycelium API, pass a pre-configured `mycelium_url` pointing to an authenticated proxy.
