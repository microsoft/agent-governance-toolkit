# SLO Completion — PR2 optional embedding evidence signal (Python + Rust)

Adds the optional, default-off embedding evidence signal specified in
`docs/UPSTREAM-PR-PLAN.md` (PR 2), in **both** SDKs to avoid cross-SDK drift,
ported from the research repo's kNN-margin detector. Branch:
`slo/pr2-embedding-signal` (off `slo/pr2-methodology`, so this PR also carries the
corpus methodology doc that unblocks it). Builds on merged PR #2924.

## What ships

| SDK | File | Public surface |
|---|---|---|
| Python | `agent-governance-python/agent-os/src/agent_os/prompt_injection_embedding.py` | `EmbeddingSignal`, `EmbeddingSignalConfig`, `EmbeddingEvidence`, `Embedder` type, `EmbeddingSignalUnavailable` |
| Rust | `agent-governance-rust/agentmesh/src/prompt_injection_embedding.rs` | `EmbeddingSignal<E>`, `EmbeddingSignalConfig`, `EmbeddingEvidence`, `Embedder` trait, `EmbeddingSignalError` |

Both compute the same margin: `mean top-k cosine(attack exemplars) − mean top-k
cosine(benign exemplars)`; higher = more attack-like.

## Maintainer default-posture spec → how it's honored

| Requirement | Implementation |
|---|---|
| disabled by default | `EmbeddingSignalConfig::enabled` defaults to `false`; `score()` returns `None`/`Option::None` and the embedder is never invoked |
| explicit flag/config | `enabled` must be set true intentionally |
| evidence-only, no hard block | `score()` returns an `EmbeddingEvidence` with `blocks = false` and a "do not block" note; neither type exposes any block/deny/enforce method |
| governance decides action | the signal only surfaces a margin; routing/enforcement is the caller's policy |
| no hosted inference | embedder is a pluggable local trait/callable; the default (Python) `fastembed` backend is **optional** and loads a local ONNX model; Rust embedder is caller-provided |
| additive | brand-new modules; existing detectors untouched; full suites stay green |

## Evidence log

| Check | Command | Result |
|---|---|---|
| Rust module tests | `cargo test -p agentmesh --lib prompt_injection_embedding` | **6 passed** |
| Rust full suite | `cargo test -p agentmesh --lib` | **354 passed, 0 failed** (no regression) |
| Rust lint | `cargo clippy -p agentmesh --lib` | **0 warnings in module** |
| Python module tests | `PYTHONPATH=src python3 -m unittest tests.test_prompt_injection_embedding` | **8 passed**, no model download (injected fake embedder) |
| Python compile | `python3 -m py_compile prompt_injection_embedding.py` | clean |

### Tests prove the invariants (no model needed)

A deterministic fake embedder is injected in both languages, so CI never
downloads a model. The suites assert: **default-off returns nothing and never
calls the embedder**; an attack-like query scores a **higher margin** than a
benign one; the output is **evidence-only** (`blocks == false`, no enforce
method); results are **deterministic**; and misconfiguration (empty bank,
single-class bank, missing optional backend) **fails safe** with a clear error.

## Caveats

- Margins depend on the embedder; the *logic and posture* are deterministic and
  tested. Real detector quality numbers come from the research corpus (synthetic;
  see the methodology doc) and are not production guarantees.
- A real ONNX/bge-small backend implementing the Rust `Embedder` trait (and the
  matching exemplar bank loading) is a natural follow-up behind an optional
  feature; this PR lands the backend-agnostic, evidence-only core.
- This is intentionally **not** wired into enforcement; policy/IFC consuming the
  margin is a separate, opt-in step.
