---
title: "2026-09-14 — Agent-OS Nested Response Sanitization"
last_reviewed: 2026-09-14
owner: agt-maintainers
---

# 2026-09-14 — Agent-OS Nested Response Sanitization

PR: [microsoft/agent-governance-toolkit#3752](https://github.com/microsoft/agent-governance-toolkit/pull/3752)

## What changed and why

Nested instruction-tag removal can expose new adjacent text after each sanitization pass. The Agent-OS MCP response path now iterates sanitization to convergence, bounds the number of passes, and re-scans the converged result before allowing it through the gateway.

The gateway fails closed if sanitization does not converge or if the final scan still reports instruction tags, credentials, PII, data-exfiltration content, or a scanner error. This closes cases where removing nested tags could splice together content that was not detectable in the original response.

## Threat model impact

This change strengthens the untrusted MCP-response boundary and adds no new external interface.

- Nested or split instruction tags cannot survive by relying on a single sanitization pass.
- A bounded pass count prevents adversarial nesting from turning sanitization into an unbounded loop.
- Post-sanitize scanning prevents newly adjacent fragments from creating an allowed exfiltration URL, PII value, credential, or residual instruction tag.
- Scanner failures and non-convergence are denied rather than treated as clean output.

The residual risk remains limited to threat classes the response scanner does not model; this PR does not broaden the scanner vocabulary or relax any existing deny policy.

## Test coverage

`agent-governance-python/agent-os/tests/test_mcp_nested_response_sanitization.py` covers nested tags, the exact eight-pass convergence boundary, over-depth fail-closed behavior, split bracket/tag forms, and splice-created exfiltration and SSN content. Existing MCP gateway and scanner tests continue to cover credential redaction and the hard-block categories enforced after sanitization.
