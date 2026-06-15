# Ticket — PR2 methodology documentation (unblocks the optional embedding signal)

Source: methodology-blocker table in the AGT-Embeddings research repo
`docs/UPSTREAM-PR-PLAN.md` (6 open questions). No GitHub issue number; the
blocker table is the contract. Builds on merged PR #2924 (the evaluation fixture).
Target branch: `slo/pr2-methodology` (off upstream `main`).
Stack: Markdown docs (no runtime code). Validation: doc claims cross-checked
against the already-merged generator.

## Smallest user-visible outcome

A maintainer can read one methodology document and verify, against the merged
generator, exactly how the prompt-injection fixture corpus is produced, split,
de-duplicated, and baselined — closing the explicit prerequisite for PR2.

## Sizing gate

| Row | Value |
|---|---|
| One outcome | yes — reviewable methodology doc |
| Changed files | 2 (new doc + one link line) |
| Public surfaces | 0 (docs only) |
| Migration / new deps | none |
| One PR | yes |

Fits one ticket.

## Compact architecture delta

`N/A — no runtime/architecture delta.` Documentation only. It describes the
existing, merged generator `benchmarks/prompt-injection/harness/generate-corpus.py`
and the existing fixture; it adds no code and changes no behavior.

## Contract block

| Field | Value |
|---|---|
| Files allowed to change | NEW `docs/benchmarks/prompt-injection-methodology.md`; `docs/benchmarks/prompt-injection-evaluation.md` (+1 cross-link line) |
| Files to read first | `benchmarks/prompt-injection/harness/generate-corpus.py`, `benchmarks/prompt-injection/README.md`, `docs/benchmarks/prompt-injection-evaluation.md`, the baseline harness `benchmarks/prompt-injection/harness/agt-rules-baseline/src/main.rs` |
| Compatibility | additive docs; no runtime change; no overclaim language |
| Data classification | Public (synthetic, metadata-only) |
| Proactive controls | C9 Security Logging/transparency (reproducibility); honesty/no-overclaim |
| Abuse scenarios | `N/A — no new surface` (docs only) |
| Resource bounds | n/a |
| Invariants | every documented number/constant matches the generator source (SEED=1337, NEAR_DUPLICATE_THRESHOLD=0.92, NGRAM=7, 5-bucket split, etc.); no claim exceeds the evidence |
| Reversibility | pure doc; revert = delete the file |
| Exemplar to copy | the existing `docs/benchmarks/prompt-injection-evaluation.md` tone/structure |
| Anti-exemplar | any "embeddings replace rules" or "production-ready / zero-FP guaranteed" framing |
| AI tolerance contract | `N/A — documentation, no AI behavior introduced` |
| Forbidden shortcuts | no methodology claim that isn't checkable in the generator; no real-traffic/production-safety claim; no raw prompt text beyond what the fixture already ships |

## The 6 questions → required answers (acceptance criteria)

1. **How were synthetic families generated?** Generator contract: stdlib-only,
   deterministic for `SEED=1337` + profile; `ATTACK_TEMPLATES` / `BENIGN_TEMPLATES`
   families; `ACTIONS`/`TARGETS`/`TOOL_NAMES` slot fillers; bypass/mutation
   operators (`rot13`, `compact_alnum`, `compact_leet`, `separator_spaced`,
   `chunked`, `homoglyph`, `compact_pressure_mutations`); `ALLOWED_BYPASS_CLASSES`;
   `PROFILE_LIMITS` row caps; `ID_PREFIX=pi1`.
2. **How is overfitting controlled?** Split unit = `family_id`/`group_id` via
   `split_for()` (5-bucket deterministic hash, not random rows); exact-normalized
   (NFKC casefold) cross-split hash check; near-duplicate check (7-gram, simhash
   16-bit bands, Jaccard ≥ 0.92) — all required zero across splits.
3. **How are benign controls constructed?** Matched adjacent-security benign
   (`benign_security_discussion`, quoted-injection examples, security training/
   changelog, docs/code fixtures), benign obfuscation controls, and legitimate
   imperative/tool-use requests — one matched control set per attack family.
4. **What is the baseline?** AGT rules-only detector via
   `agentmesh::prompt_injection` at an exact upstream commit + detector source
   SHA, run by `agt-rules-baseline`.
5. **What does "zero FP observed" mean?** A finite-sample observation on this
   frozen test split, reported with a Wilson interval and a base-rate-prevalence
   caveat — not a guarantee.
6. **What is the production path?** Review/routing evidence only; optional,
   default-off; governance metadata decides action; embeddings never hard-block
   alone; no hosted inference.

## Validation plan

| Check | Command | Expected |
|---|---|---|
| Generator constants match doc | `grep -E "SEED|NEAR_DUPLICATE|SPLITS|ALLOWED_BYPASS" benchmarks/prompt-injection/harness/generate-corpus.py` | values equal those cited in the doc |
| Corpus reproduces | `python3 benchmarks/prompt-injection/harness/generate-corpus.py --profile smoke` then re-check leakage = 0 | deterministic, zero cross-split leakage |
| No runtime change | `git diff --stat origin/main..HEAD` | only the 2 doc files |
| Link resolves | manual: evaluation doc → methodology doc | link valid |

## Out of scope

The embedding detector itself (PR2 implementation) — gated on this doc being
reviewed. Real-traffic validation. Any change to runtime code or the generator.
