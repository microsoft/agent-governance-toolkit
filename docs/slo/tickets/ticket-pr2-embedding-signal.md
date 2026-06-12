# Ticket — PR2 optional embedding evidence signal

Source: `docs/UPSTREAM-PR-PLAN.md` "PR 2: Optional Embedding Signal" + the
default-posture spec. Builds on PR1 (#2924 fixture) and the methodology doc
(this branch's parent `slo/pr2-methodology`). Target branch:
`slo/pr2-embedding-signal`. Stack: Python (`agent_os`) + Rust (`agentmesh`) —
the signal shipped in both SDKs with matching semantics. Ported from the research
repo's kNN-margin detector (`AGT-Embeddings-Experiment`, fastembed + bge-small).

## Smallest user-visible outcome

An **optional, default-off** module that, when explicitly enabled, returns an
**auditable embedding margin (evidence only)** for a piece of text — a
nearest-neighbour score against a labelled exemplar bank — without changing any
existing AGT enforcement behavior.

## Maintainer-specified default posture (the spec to honor)

- disabled by default;
- configured by an explicit feature flag / config option;
- **evidence-only** — auditable score/margin; **no hard block from embeddings alone**;
- governance metadata / policy decides any action;
- **no hosted-inference requirement** (local embedder, pluggable);
- additive: existing behavior unchanged by default.

## Sizing gate

| Row | Value |
|---|---|
| One outcome | yes — opt-in evidence signal |
| Changed files | 10 as merged (#2974): Python module + test + pyproject extra, Rust module + `lib.rs` export, methodology/evaluation docs, SLO evidence + tickets |
| Public surface | 2 new modules (`agent_os.prompt_injection_embedding`, `agentmesh::prompt_injection_embedding`); no change to existing detectors |
| Migration | none |
| New deps | `fastembed` as an **optional** extra only (never a hard dep) |
| One PR | yes |

Fits one ticket.

## Contract block

| Field | Value |
|---|---|
| Files allowed to change | NEW `agent-governance-python/agent-os/src/agent_os/prompt_injection_embedding.py`; NEW `agent-governance-python/agent-os/tests/test_prompt_injection_embedding.py`; `agent-governance-python/agent-os/pyproject.toml` (+`embedding` optional extra); NEW `docs/slo/completion/pr2-embedding-signal.md` |
| Files to read first | `agent_os/prompt_injection.py` (style), research `meta/harness/round6-cascade/common.py` (kNN margin), the methodology doc |
| Compatibility | additive; existing `PromptInjectionDetector` untouched; module is inert unless `enabled=True` |
| Data classification | Public (synthetic exemplars / metadata) |
| Proactive controls | C4 Address Security from the Start (default-off, fail-safe), C8 (no raw text persisted in evidence), C9 (auditable margin) |
| Abuse scenarios | `tm-pr2-abuse-1`: enabling the signal must NOT auto-block (evidence-only invariant asserted in tests); `tm-pr2-abuse-2`: missing fastembed must fail safe (disabled / clear error), never crash the host |
| Resource bounds | bank size bounded by caller; k ≤ bank size; pure-Python cosine over small banks |
| Invariants | default-off returns `None`; evidence object carries a margin and an explicit "does not block" note; deterministic for a fixed embedder + bank |
| Reversibility | additive module; revert = delete files + the extra |
| Exemplar to copy | research `knn_margin` / `topk_mean`; agent-os dataclass style |
| Anti-exemplar | do NOT wire it into enforcement; do NOT make fastembed a hard dependency; no "embeddings replace rules" framing |
| AI tolerance contract | ai_component: true. Accepted variance: the margin depends on the embedder; the *logic* (kNN margin, default-off, evidence-only) is deterministic and unit-tested with an injected deterministic fake embedder (no model download in tests). Must-never: auto-block; hard fastembed dep; persist raw text. |
| Forbidden shortcuts | no hard block; no network/hosted inference; no hard dep; no enforcement wiring |

## BDD scenarios

| Scenario | Category | Given | When | Then |
|---|---|---|---|---|
| default off | happy path | signal with `enabled=False` | `score(text)` | returns `None` (inert) |
| evidence margin | happy path | enabled signal + labelled bank + injected embedder | `score(attack-like text)` | returns `EmbeddingEvidence` with margin > margin of a benign-like text |
| evidence-only | abuse `tm-pr2-abuse-1` | enabled signal | inspect API | no method blocks/enforces; evidence note says "does not block" |
| fastembed missing | abuse `tm-pr2-abuse-2` / dependency failure | enabled, no embedder, fastembed absent | construct/score | clear error or safe-disabled, never an unhandled crash |
| empty bank | empty state | enabled, empty bank | construct | rejects with a clear error (cannot score without exemplars) |
| determinism | invariant | fixed embedder + bank | two `score` calls | identical margin |

## Validation plan

| Check | Command | Expected |
|---|---|---|
| Unit tests | `python3 -m unittest test_prompt_injection_embedding` (stdlib; injected embedder) | green, no model download |
| Default-off proven | test asserts `score()` is `None` when disabled | pass |
| No enforcement wiring | grep module for block/deny/raise-on-detect | none |
| Compile | `python3 -m py_compile prompt_injection_embedding.py` | clean |

## Out of scope

Policy/IFC routing that consumes the margin (separate); real-traffic validation;
any change to the existing rules detector.
