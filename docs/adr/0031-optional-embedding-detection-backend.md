# ADR 0031: Optional embedding evidence backend for prompt-injection detection

- Status: proposed
- Date: 2026-06-13

## Context

The rules-based `PromptInjectionDetector` (Python `agent_os` and Rust
`agentmesh`) is deliberately high-precision / low-recall: it catches obvious
patterns but misses disguised or semantically novel injection. An optional
embedding/kNN signal already exists in both SDKs
(`prompt_injection_embedding`) — a local, default-off nearest-neighbour margin
against a labelled exemplar bank — but it was not connected to the detection
pipeline. Connecting that signal was the remaining gap discussed in #2918.

Two constraints shaped the design:

1. The deterministic detector's behaviour must not change by default, and the
   embedding signal must never block on its own — governance/policy decides any
   action (consistent with the project's "controls are deterministic, models are
   evidence" posture).
2. Content normalization (RFC #2957, PR #2991) sits upstream of any detector or
   backend and is unchanged here.

## Decision

Introduce a **pluggable, default-off evidence backend** following the
pluggable-backend pattern of ADR-0015:

- A small backend interface — a Python `Protocol` and a Rust `trait`
  (`DetectionEvidenceBackend`) — with a stable `name` and an `evaluate(text)`
  that returns an advisory `EvidenceSignal` or nothing.
- `PromptInjectionDetector` consults registered backends **only after** the
  deterministic verdict is computed, and appends their `EvidenceSignal`s to a new
  additive `DetectionResult.evidence` field. Evidence **never** influences
  `is_injection` / `threat_level` / `injection_type` / `confidence` /
  `matched_patterns`, and `EvidenceSignal.blocks` is always false.
- The evidence-only invariants are **enforced**, not conventional: `blocks=true`
  and a non-finite (`NaN`/`inf`) score are rejected at the boundary (Python
  raises in `__post_init__`; Rust forces `blocks=false` and drops a non-finite
  score to a `non_finite_score` error code). A backend that raises — or, in
  Rust, *panics* (e.g. the embedding signal's `cosine()` asserting on a
  dimension mismatch) — is caught and recorded as a static `backend_error` code,
  so a misbehaving backend can never alter the verdict or break detection.
- `EmbeddingSignalBackend` adapts the existing `prompt_injection_embedding` kNN
  signal to this interface. It is inert unless explicitly enabled, so the
  embedding model/runtime remains an optional dependency.
- Backends are registered explicitly (Python `evidence_backends=`, Rust
  `with_evidence_backends(...)`). With none registered, `detect()` output is
  byte-identical to the rules-only path.
- In Rust, `DetectionResult` is marked `#[non_exhaustive]` so the additive
  `evidence` field is a non-breaking change.

`EvidenceSignal` carries only a static backend identifier, a numeric score, and
a static error *code* — never raw input or input-derived text — so the audit
surface stays hash/ID-only. The raw numeric score is additionally **stripped
from the durable audit copy**: a continuous per-request score is an evasion
oracle (anyone with audit-log access could watch the margin move and tune a
payload toward a lower score), so only backend identity and error codes are
persisted. The live `DetectionResult` returned to the caller keeps raw scores
for in-process telemetry and aggregation.

## Consequences

- The pipeline gains an optional, auditable recall signal for review/routing
  without any change to default behaviour, false-positive profile, or blocking.
- Adding another evidence backend (e.g. a classifier) is implementing the
  two-method interface and registering it — no detector changes.
- Cross-SDK parity is preserved: the Python `Protocol` and Rust `trait` are
  symmetric, with matching invariants and tests.
- Trade-off: evidence is advisory only; turning it into an enforced control is a
  separate, explicit policy/governance decision. A model-backed backend adds an
  optional dependency only when enabled.

## References

- ADR-0015 (pluggable external policy backends) — the pattern this follows.
- #2918 — the embedding-signal proposal and the "connect it to the pipeline" gap.
- RFC #2957 / PR #2991 — content normalization, upstream of any backend.
- `docs/benchmarks/prompt-injection-methodology.md` — the evidence-only,
  default-off methodology and the kNN-margin definition.
