# 2026-07-02 — Agent-OS Credential Detection and Redaction

PR: [microsoft/agent-governance-toolkit#3248](https://github.com/microsoft/agent-governance-toolkit/pull/3248)

## What changed and why

`agent_os` had two components that handled secrets in tool output and disagreed
with each other. `MCPResponseScanner.scan_response` flagged credential threats,
but `MCPResponseScanner.sanitize_response` only stripped instruction tags and
returned the secrets intact. `CredentialRedactor` missed several common secret
formats that the scanner still reported, so detection and redaction produced
different verdicts on the same input. This PR makes credential handling
internally consistent.

- `CredentialRedactor.redact` is now driven by the exact spans that
  `find_matches` reports, instead of applying each pattern sequentially to a
  progressively mutated string. The old approach let an earlier greedy pattern
  consume the anchor keyword of a later pattern, so redaction removed less than
  detection reported and left a secret in place.
- New credential patterns cover the AWS secret access key, Azure Storage SAS
  token, and Slack, Google, and Stripe tokens.
- Prefix-anchored patterns use a `(?<![A-Za-z0-9])` left anchor instead of `\b`,
  so a secret glued to a preceding word character (for example `session_sk-...`)
  is detected. Under redact-and-allow this matters because a secret the scanner
  cannot see would otherwise be returned when it co-occurs with a detected one.
- `MCPResponseScanner.sanitize_response` strips instruction tags and redacts
  credential values, returning the removed credential type names rather than the
  raw secret.
- `MCPGateway` under `ResponsePolicy.SANITIZE` now redacts credential leaks and
  allows the cleaned response, matching the behavior required by
  `docs/specs/MCP-SECURITY-GATEWAY-1.0.md` section 21.3. PII and exfiltration
  URLs are still blocked because they cannot be safely removed from prose.

## Threat model impact

This change strengthens the response data-loss boundary and does not introduce a
new external attack surface. It touches only detection and redaction of secrets
in tool output.

| Dimension | Direction |
|---|---|
| Detection and redaction consistency | **Strengthened.** Redaction now removes exactly the spans detection reports, so a credential the scanner flags can no longer survive `sanitize_response`. |
| Secret coverage | **Strengthened.** AWS secret keys, Azure SAS tokens, and Slack, Google, and Stripe tokens are now detected and redacted. |
| SANITIZE behavior | **Changed.** Credential-bearing responses are returned redacted rather than hard-blocked. A fail-closed guard re-checks the redacted output and blocks if a credential remains, so relaxing the hard block cannot leak a detected secret. |
| Denial-of-service | **Strengthened.** The Azure SAS pattern matches the signature value directly instead of a lazy cross-parameter span that scanned to end from each marker, removing a super-linear backtracking path on untrusted input. |
| Secret gluing | **Strengthened.** Prefix-anchored patterns use a `(?<![A-Za-z0-9])` left anchor instead of a word boundary, so a secret joined directly to a preceding word character (for example `session_sk-...`) is now detected and redacted. Previously such a secret was missed, and under redact-and-allow it could leak when it co-occurred with a separately detected credential. |
| Log and audit exposure | **Unchanged.** Threats and the new `scan_and_redact` API expose only credential type names, never raw secret values; `redact` logs a span count only. |
| PII handling | **Unchanged.** PII is still detected and hard-blocked; PII matches that fall inside a credential span are suppressed so a secret is not double-reported. |

### Known limitations

Two narrow, pre-existing behaviors remain out of scope for this change and are
tracked as follow-ups. Both reproduce identically on the base branch.

- Tag stripping can join fragments into PII or an exfiltration URL with no
  post-sanitize re-scan of those categories.
- A secret glued to a following alphanumeric run of a fixed-length identifier
  (for example an AWS access key id immediately followed by more letters) can
  still evade detection; the left-edge case (`session_sk-...`) is fixed here.

## Test coverage

- `tests/test_credential_redactor.py` covers each new secret class, full removal
  of the AWS secret value, order-independent Azure SAS detection, redaction of a
  Slack token followed by a word character, the absence of super-linear
  backtracking on repeated SAS markers, detection and redaction agreeing on
  adjacent anchored secrets, detection of secrets glued to a preceding word
  character, and the loosened anchor still refusing matches inside words.
- `tests/test_mcp_response_scanner.py` covers `sanitize_response` removing
  credentials, combined tag stripping and redaction, PII suppression inside a
  credential span, and one credential finding per secret.
- `tests/test_mcp_pii_and_response_gateway.py` covers the `SANITIZE` policy
  redacting and allowing credential leaks, still blocking PII and exfiltration,
  not leaking an adjacent anchored secret, and not leaking a word-glued secret
  that co-occurs with a detected one.
