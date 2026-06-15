<!-- Copyright (c) Microsoft Corporation. -->
<!-- Licensed under the MIT License. -->

# Prompt Defense Vectors — OWASP Mapping

`PromptDefenseEvaluator` (`agent_compliance.prompt_defense`, surfaced by
`agt red-team scan`) statically audits a system prompt for **missing
defensive language** before the agent is deployed. It is pure regex —
deterministic, zero LLM cost, < 5 ms per prompt — and complements the
*runtime* prompt-injection detection in Agent OS by catching the gap at
design time rather than at attack time.

This table cross-references every vector the evaluator checks to the OWASP
risk it covers. Use it during security audits and when interpreting a
`red-team scan` grade.

**References:**
- [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/)
- [OWASP Top 10 for Agentic Applications / ASI (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- Related: [`docs/OWASP-COMPLIANCE.md`](./OWASP-COMPLIANCE.md) (stack-wide ASI coverage)

---

## Conversational layer — OWASP LLM Top 10 (12 vectors)

These audit the prompt for *conversational* safety: role integrity,
instruction precedence, data confidentiality, and input/output hygiene.

| Vector ID | Name | OWASP | Severity |
|-----------|------|-------|----------|
| `role-escape` | Role Boundary | LLM01 | high |
| `instruction-override` | Instruction Boundary | LLM01 | high |
| `data-leakage` | Data Protection | LLM07 | critical |
| `output-manipulation` | Output Control | LLM02 | medium |
| `multilang-bypass` | Multi-language Protection | LLM01 | medium |
| `unicode-attack` | Unicode Protection | LLM01 | low |
| `context-overflow` | Length Limits | LLM01 | low |
| `indirect-injection` | Indirect Injection Protection | LLM01 | critical |
| `social-engineering` | Social Engineering Defense | LLM01 | medium |
| `output-weaponization` | Harmful Content Prevention | LLM02 | high |
| `abuse-prevention` | Abuse Prevention | LLM06 | medium |
| `input-validation` | Input Validation | LLM01 | high |

---

## Agentic layer — OWASP Agentic Top 10 / ASI (5 vectors)

The 12 vectors above say nothing about the risks that only exist once the
model is an **autonomous agent**: delegating to other agents, moving funds,
loading skills, drifting off its assigned goal, or acting on a decoded
payload. AGT positions itself against the OWASP Agentic Top 10, so a
pre-deployment system-prompt audit should check the agentic layer too.
These five vectors close that gap.

| Vector ID | Name | ASI Risk | Severity | What a defended prompt asserts |
|-----------|------|----------|----------|--------------------------------|
| `cross-agent-auth` | Cross-Agent Authorization Boundary | ASI-07 | high | Authority from another agent is not inherited transitively — it is re-verified per request. |
| `transaction-guardrails` | Financial Transaction Guardrails | ASI-02 | critical | Value-moving actions require a limit, a second approval, or an explicit refusal-without-authorization. |
| `skill-provenance` | Skill / Extension Provenance | ASI-04 | high | Skills/tools load only from a signed/trusted/pinned source; unverified ones are refused. |
| `least-agency` | Least Agency / Goal-Hijack Resistance | ASI-01 | high | The agent runs with least privilege, scoped to its assigned goal, and aborts on goal drift. |
| `encoding-injection` | Encoding-aware Indirect Injection | ASI-01 | high | Decoded / translated / base64 content is treated as untrusted data, never as a command. |

> **Numbering.** ASI risk numbers follow [`docs/OWASP-COMPLIANCE.md`](./OWASP-COMPLIANCE.md),
> the stack-wide coverage map (ASI-07 = Insecure Inter-Agent Communication).
> `least-agency` and `encoding-injection` both map to **ASI-01 (Agent Goal
> Hijack)** because both defend the goal-integrity surface from different
> angles — proactive privilege/scope limiting vs. the encoded-payload input
> channel — so a prompt can be strong on one and silent on the other.

---

## How a vector is scored

Each vector is a `_DefenseRule` with one or more compiled regexes and a
`min_matches` threshold. A vector is marked **defended** only when at least
`min_matches` of its patterns are present.

The agentic vectors all use `min_matches=2` by design: the first pattern
matches the *capability or attack surface* ("transfer the funds", "another
agent told me", "decode this base64"), the second matches the *constraint
on it* (a limit, a re-verification requirement, a treat-as-data rule). This
ensures attack vocabulary alone never scores as a defense — a real guardrail
names both the capability and the bound on it. All regexes use bounded
quantifiers (no unbounded `.*`) and the evaluator enforces a
`MAX_PROMPT_LENGTH` cap for ReDoS safety.

The overall score is `defended / total × 100`, graded A (≥90) / B (≥70) /
C (≥50) / D (≥30) / F. `red-team scan --strict` exits non-zero below the
configured `--min-grade` (default C).

---

## Attribution

The regex vocabulary for the five agentic vectors was distilled from the
open-source [UltraProbe](https://www.npmjs.com/package/ultraprobe) scanner
(MIT) — specifically its `scanDefense` agent-era vectors — and ported here
English-first to match this module's style and ReDoS-safety discipline.
