---
title: "2026-09-14 — Credential Boundary Redaction (Cross-SDK)"
last_reviewed: 2026-09-14
owner: agt-maintainers
---

# 2026-09-14 — Credential Boundary Redaction (Cross-SDK)

Issue: [microsoft/agent-governance-toolkit#3933](https://github.com/microsoft/agent-governance-toolkit/issues/3933)

## What changed and why

`McpCredentialRedactor` (C#), `AuditLogger` (TypeScript), `CredentialRedactor`
(Python), and the Rust `CredentialRedactor` all contained credential-detection
patterns for GitHub, OpenAI, AWS, and Google API tokens with incorrect boundary
anchors. The anchors treated `_` (and, for some patterns, `-`) as a
boundary-blocking character, so a valid secret glued to a preceding or following
word character via `_` — the way rotation notes, environment prefixes, and
config-file annotations actually annotate secrets — passed through completely
unredacted.

Concrete shapes that were missed:

- Right-edge: `AKIAIOSFODNN7EXAMPLE_old`, `ghp_XXXX_deprecated`,
  `AIzaXXXX_rotated`
- Left-edge: `session_AKIAIOSFODNN7EXAMPLE`, `env_ghp_XXXX`,
  `svc_AIzaXXXX`
- Both: `old_AKIAIOSFODNN7EXAMPLE_new`

The root cause in C# and TypeScript was `_` included in the lookaround
exclusion set (`(?<![A-Za-z0-9_])` / `(?![A-Za-z0-9_])`) for GitHub and
OpenAI tokens, and `\b` word boundaries (which treat `_` as a word character
in all regex engines) for AWS and Google tokens. In Rust the same logic was
expressed procedurally via `is_left_boundary_char` / `is_right_boundary_char`
methods that included `_` in the rejection set. In Python the left anchor was
already correct (`(?<![A-Za-z0-9])`), but the right anchor used `\b` for AWS,
Google, OpenAI, and Stripe tokens, and the GitHub lookahead still included `_`.

The `SlackToken` pattern in all four SDKs was already correct and served as
the reference for the fix: its lookaround excludes only characters that form
part of the token's own value class (`-` and alphanumerics), not separators
like `_`.

### Fix applied

All four patterns in all four SDKs now use `(?<![A-Za-z0-9])` on the left
edge and `(?![A-Za-z0-9])` on the right edge. In Rust, `is_left_boundary_char`
and `is_right_boundary_char` now return `true` only for ASCII alphanumerics
(plus `-` for Slack, whose value class includes it).

Additionally, the `content_scanner.py` SSN pattern in `agent-rag-governance`
was updated from `\b\d{3}-\d{2}-\d{4}\b` (dash-only, `\b`-anchored) to
`(?<![A-Za-z0-9])\d{3}[\s.-]\d{2}[\s.-]\d{4}(?![A-Za-z0-9])` to match the
separator forms (`credential_redactor.py` already accepted) and use the
consistent lookaround anchor (issue #3815).

## Threat model impact

This change strengthens credential detection across all language SDKs and does
not introduce a new external attack surface. It touches only boundary-anchor
logic in detection patterns.

| Dimension | Direction |
|---|---|
| Right-edge detection | **Strengthened.** A secret followed by `_old`, `_deprecated`, `_rotated`, or any `_`-prefixed suffix is now detected and redacted in all four SDKs. Previously it passed through silently. |
| Left-edge detection | **Strengthened.** A secret preceded by `session_`, `env_`, `svc_`, or any `_`-suffixed prefix is now detected and redacted. The Python left anchor was already correct; C#, TypeScript, and Rust are now aligned. |
| False-positive surface | **Unchanged.** A token prefix embedded inside a contiguous alphanumeric word (e.g. `fooAKIA…`) is still correctly rejected. The `(?<![A-Za-z0-9])` anchor blocks this case identically to the old `_`-including anchor. |
| Cross-SDK consistency | **Strengthened.** All four SDKs now use the same boundary semantics: alphanumeric-only lookaround. Previously each SDK had a different combination of `\b`, `_`-inclusive lookaround, and procedural boundary checks. |
| SSN detector parity | **Strengthened.** `content_scanner.py` now matches the same separator forms as `credential_redactor.py`, closing the detection-disagreement gap described in #3815. |
| Log and audit exposure | **Unchanged.** No raw secret values are exposed in any new code path. |

### Known limitations

- The Bearer token and JWT patterns in `credential_redactor.py` still use
  a trailing `\b`. Their value classes do not include `_`, so the practical
  impact is minimal, but they are inconsistent with the other patterns.
  A follow-up can align them.

## Test coverage

- **C# `McpCredentialRedactorTests.cs`**: right-edge, left-edge, both-edges,
  multi-credential, still-rejects-alphanumeric, and SlackToken-unchanged
  tests for all four affected patterns.
- **C# `McpResponseSanitizerTests.cs`**: end-to-end pipeline tests verifying
  glued credentials are caught by `ScanText` (AWS, GitHub, Google, OpenAI),
  including combined-threat scenarios.
- **TypeScript `policy-audit.test.ts`**: boundary tests for GitHub, AWS,
  Google, and OpenAI tokens through the `AuditLogger.sanitizeValue` pipeline.
- **Rust `redactor.rs` (inline tests)**: left-edge, right-edge, both-edges,
  multi-credential, and still-rejects-alphanumeric tests for all four patterns.
- **Python `test_credential_redactor.py`**: right-edge `_old` tests for
  GitHub, AWS, Google, OpenAI, and Stripe; multi-credential single-pass;
  false-positive guard; trailing-bare-underscore for GitHub.
- **Python `test_content_scanner.py`**: SSN dash, space, dot separator tests;
  underscore-glued SSN; bare-nine-digit rejection.
