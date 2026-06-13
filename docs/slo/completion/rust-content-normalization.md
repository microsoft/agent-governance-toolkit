# SLO Completion — Rust content-normalization module (`agentmesh::normalize`)

Implements the upstream RFC microsoft/agent-governance-toolkit#2957 — strengthen
and **surface** content normalization as a shared pre-detection control — in the
Rust SDK. Branch: `slo/rust-content-normalization` (off upstream `main`).

## Goal (smallest user-visible outcome)

A public `agentmesh::normalize` module that produces a canonical view of
untrusted text **plus the set of transforms that fired**, with FP-safety guards
so legitimate inputs pass through unchanged. Any text control (the regex
detector, classifier/LLM annotators, policy/IFC, human review) can consume it.

## Contract block

| Field | Value |
|---|---|
| Files changed | NEW `agent-governance-rust/agentmesh/src/normalize.rs`; `src/lib.rs` (+1 line `pub mod normalize;`); NEW `agentmesh/examples/normalize_b64.rs` (validation helper) |
| Files NOT touched | the existing private `normalize_for_detection` in `prompt_injection.rs` is left in place (non-breaking); this module is additive |
| New dependencies | none (uses `base64`, already a dependency) |
| Public surface | `normalize(&str)`, `normalize_with(&str, &NormalizeConfig)`, `Normalized{text, transforms}`, `Transform` enum, `NormalizeConfig` |
| Compatibility | additive, no existing behaviour changed; full agentmesh suite stays green |
| Invariants | deterministic; idempotent (`normalize(normalize(x)) == normalize(x)`) — property-tested |
| Resource bounds | decode depth ≤ 2; output ≤ 4× input (truncate + tag); guarded per transform |
| Forbidden shortcuts | no decode without printable-ratio/English-benefit guard; no leet de-sub unless the result is entirely alphabetic & len ≥ 3 (preserves measured 0-FP); transform vocabulary is a closed enum (no free-form audit strings) |

## Transforms (FP-safety is the design centerpiece)

Strip invisible incl. **bidi override/isolate (Trojan Source)** · width fold ·
bounded decode layers (base64/hex/rot13/percent/unicode-escape/HTML-entity, each
behind a printable-ratio + English-benefit acceptance guard) · homoglyph/
confusable fold · letter-spacing collapse · token-guarded leetspeak · lowercase ·
whitespace collapse. Each fires only under its guard; legit percentages,
ampersands, real base64, hashes, codes, and prose are left unchanged.

## Evidence log

| Check | Command | Result |
|---|---|---|
| Build | `cargo build -p agentmesh` | clean |
| Unit tests (module) | `cargo test -p agentmesh --lib normalize` | **19 passed** (transforms + benign-safety + idempotency + determinism + Trojan-Source) |
| Full SDK suite | `cargo test -p agentmesh --lib` | **365 passed, 0 failed** (no regression) |
| Lint | `cargo clippy -p agentmesh --lib --example normalize_b64` | **0 warnings in normalize.rs** |
| Format | `cargo fmt` (module only; unrelated upstream churn reverted) | clean |
| **Corpus parity** | normalize 3,680 frozen test-split attacks (Rust example) vs the measured Python normalizer | **100% functional agreement** — identical de-obfuscation decision on every row |

### Corpus de-obfuscation parity (per bypass class)

Rust vs Python "did it un-disguise the attack" rate, on the research corpus:

| bypass_class | Python | Rust |
|---|---:|---:|
| encoding | 66.7% | 66.7% |
| homoglyph | 66.7% | 66.7% |
| leet_spacing | 62.5% | 62.5% |
| letter_spaced / leet_letter_spaced | 100% | 100% |
| rot13 | 54.2% | 54.2% |
| multilingual | 75.0% | 75.0% |
| compact_leet / separator_spaced / diacritics | 0% | 0% (matched — FP-safe residual) |
| **ALL** | **59.9%** | **59.9%** |

The Python-measured gains therefore transfer: zero-FP detector recall
43% → 49%, encoding bypass-class catch 35% → 62%, 0 benign-control FP.

## Definition of Learned / Done

- The Rust port is **functionally faithful** to the measured Python normalizer
  (100% agreement), additive, non-breaking, lint-clean, fully tested.
- FP-safety guards (esp. the entirely-alphabetic leet guard) are what preserve
  the measured zero false-positives; without them the Rust port was briefly more
  aggressive on `compact_leet` — caught and fixed.

## Python port (`agent_os.normalize`)

The module is also shipped in the Python SDK, ported 1:1 from the Rust
implementation (same transforms, same order, same guards, same closed transform
vocabulary), stdlib-only.

| Check | Command | Result |
|---|---|---|
| Unit tests | `python3 -m unittest tests.test_normalize -v` | **21 passed** (mirrors the Rust suite + immutability/decoder-off cases) |
| Cross-SDK parity | both implementations over the regenerated 280-row smoke corpus + a 21-case obfuscation battery (300 rows) | **byte-identical normalized text AND identical transform tags on every row** |
| Full agentmesh suite | `cargo test -p agentmesh --lib` | **371 passed, 0 failed** on current `main` |
| Lint | `cargo clippy -p agentmesh --lib` | 0 warnings in `normalize.rs` (3 pre-existing elsewhere) |

## Caveats

- All metrics derive from a **synthetic** research corpus — directional, not a
  production guarantee. Real-traffic FP audit is separate work.
- `normalize_b64.rs` is a validation helper, not core API; it can be dropped from
  the eventual upstream PR.
- Full NFKC is not applied (manual width-fold instead, dependency-free); could be
  added via `unicode-normalization` if maintainers prefer — noted for review.
