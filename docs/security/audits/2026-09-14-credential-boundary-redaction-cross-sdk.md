---
title: "2026-09-14 -- Credential Boundary Redaction (Cross-SDK)"
last_reviewed: 2026-09-14
owner: agt-maintainers
---

# 2026-09-14 -- Credential Boundary Redaction (Cross-SDK)

Issue: [microsoft/agent-governance-toolkit#3933](https://github.com/microsoft/agent-governance-toolkit/issues/3933)

## What changed and why

Credential-detection patterns in the TypeScript, Python, and Rust SDKs used
boundary anchors that treated `_` (and, for some patterns, `-`) as a
boundary-blocking character. A valid secret glued to a word character via `_` or
`-` -- rotation notes, environment prefixes, config-file annotations -- passed
through unredacted.

C# fixes will land separately in #3934 (open) and are not part of this PR.

### Per-SDK delta versus main

| SDK | Left anchor change (vs main) | Right anchor change (vs main) |
|-----|------------------------------|-------------------------------|
| TypeScript | `(?<![A-Za-z0-9_-])` -> `(?<![A-Za-z0-9])` for OpenAI and Google (removes `_` and `-` from exclusion set) | `\b` -> `(?![A-Za-z0-9])` for AWS; Google tail -> `(?:(?![A-Za-z0-9])|(?<=-))` (superset) |
| Python | Already correct on main | OpenAI `\b` -> `(?![A-Za-z0-9])` (only change vs main; AWS/GitHub/Google/Stripe right anchors were fixed by #3853) |
| Rust | `is_left_boundary_char`: all non-Slack kinds simplified to `ch.is_ascii_alphanumeric()` (removes `_` for GitHub and generic; removes `_` and `-` for OpenAI and Google) | `is_right_boundary_char`: all non-Slack kinds now return `ch.is_ascii_alphanumeric()` (was unenforced for AWS/GitHub/Google/Stripe/generic; was `alnum + _ + -` for OpenAI). Google adds hyphen superset via `last_consumed == '-'` check |

### OpenAI left-edge widening (TypeScript and Rust)

The TypeScript OpenAI pattern previously used `(?<![A-Za-z0-9_-])` which
excluded both `_` and `-` from the left boundary. The fix removed both,
aligning with the Python SDK which has always used `(?<![A-Za-z0-9])`.

In Rust, `is_left_boundary_char` for `OpenAiToken` previously blocked
alphanumerics, `_`, and `-`. It now blocks only alphanumerics, again aligning
with Python.

This means kebab identifiers like `my-sk-aaaa...` are now matched in TypeScript
and Rust where they were previously skipped. This is intentional: a real secret
preceded by a `-` separator (e.g. `env-sk-...`) must be detected, and the
Python SDK has accepted this trade-off since its initial implementation.

### content_scanner.py SSN pattern reconciliation

The `content_scanner.py` SSN pattern was updated from
`\b\d{3}-\d{2}-\d{4}\b` (dash-only, `\b`-anchored) to
`(?<![A-Za-z0-9])\d{3}[\s.-]\d{2}[\s.-]\d{4}(?![A-Za-z0-9])` to match the
separator forms already accepted by `credential_redactor.py` (#3815).

## Threat model impact

| Dimension | Direction |
|---|---|
| Right-edge detection | **Strengthened** in TypeScript and Rust (previously unenforced for most kinds). Python: OpenAI right anchor strengthened (`\b` -> lookahead). |
| Left-edge detection | **Strengthened** in TypeScript and Rust (removes `_` from exclusion set). Python: already correct on main. |
| False-positive surface | **Widened slightly** for OpenAI in TypeScript and Rust: kebab identifiers like `my-sk-...` are now matched (aligned with Python). Unchanged for all other patterns. |
| SSN detector parity | **Strengthened.** `content_scanner.py` now matches the same separator forms as `credential_redactor.py`. |
| Log and audit exposure | **Unchanged.** No raw secret values are exposed in any new code path. |

## Test coverage

- **TypeScript `policy-audit.test.ts`**: boundary tests for GitHub, AWS,
  Google, and OpenAI tokens through the `AuditLogger.sanitizeValue` pipeline.
  Includes `my-sk-...` pinning test for the OpenAI left-edge widening and
  Google-key-ending-in-hyphen superset test for the `(?<=-)` tail branch.
- **Rust `redactor.rs` (inline tests)**: left-edge, right-edge, both-edges,
  multi-credential, and still-rejects-alphanumeric tests. Updated
  `prefix_ghp_` test to assert detection (behaviour change from bug fix).
  Includes Google-key-ending-in-hyphen superset test and `my-sk-...` pinning.
- **Python `test_credential_redactor.py`**: right-edge `_old` tests for
  GitHub, AWS, Google, OpenAI, and Stripe; multi-credential single-pass;
  false-positive guard; trailing-bare-underscore for GitHub.
- **Python `test_content_scanner.py`**: SSN dash, space, dot separator tests;
  underscore-glued SSN; bare-nine-digit rejection.
- **Source-level regression guard** (`test_regression_credential_boundary.py`):
  scans TypeScript (`audit.ts`) and Python (`credential_redactor.py`) source
  files for `_` inside lookaround character classes. The guard regex covers
  both lookbehind and lookahead forms. Rust boundary logic is checked via
  separate match-arm assertions that inspect `is_left_boundary_char` and
  `is_right_boundary_char` source for `'_'` in non-Slack arms.
