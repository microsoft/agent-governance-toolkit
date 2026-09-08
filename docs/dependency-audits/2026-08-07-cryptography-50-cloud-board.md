---
title: "Dependency audit: cryptography 48.0.1 -> 50.0.0 (cloud-board)"
last_reviewed: 2026-08-07
owner: agt-maintainers
---

# 2026-08-07 - cryptography 48.0.1 -> 50.0.0 in cloud-board

Supersedes dependabot #3588 (same bump; the audit-trail gate requires this
doc in the bumping PR, which dependabot cannot author for majors).

## What changed and why

`agent-governance-python/agent-os/services/cloud-board/requirements.txt`
pins cryptography 50.0.0 (was 48.0.1). Adoption motivation: 50.0.0 hardens
PKCS7 decryption against Bleichenbacher-style padding oracles and tightens
DER parsing (SPKI BIT STRING unused bits, SCT trailing bytes, OCSP
version, CRL InvalidityDate fractional seconds).

## Breaking-change risk assessment

Releases in range: 49.0.0 and 50.0.0.

- 49.0.0: macOS x86_64 / 32-bit Windows wheels removed (CI is
  ubuntu-latest); deprecated type aliases removed; ChaCha20 nonce treated
  as RFC-7539 counter; X.509 NULL-params ECDSA/DSA rejected.
- 50.0.0: FFDH deprecated (not removed); stricter DER rejects; PKCS7
  hardening.

None apply: cloud-board's service code uses PyNaCl only; the image's real
cryptography consumer is the nexus module (Ed25519 raw sign/verify +
AESGCM), untouched by every listed change. No pyOpenSSL anywhere in the
service. Verified empirically: the service test suite passes under
50.0.0 (85 tests: cloud-board API auth + nexus client/escrow/registry/
reputation), and separately the full agent-mesh suite passed under 50.0.0
during the repo-wide cap-widen work (#3615/#3621, 3601 tests).

## Security advisory relevance

No CVE forced this bump; the PKCS7/DER hardening in 50.0.0 is
defense-in-depth. Release age at adoption: 7 days (published 2026-07-31),
satisfying the cooling-off policy.
