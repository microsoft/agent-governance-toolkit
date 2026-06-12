# Prompt-Injection Fixture — Corpus Methodology

This document makes the corpus-generation methodology behind
`benchmarks/prompt-injection/` reviewable in detail. It is the methodology
prerequisite for any follow-up that adds an **optional, default-off embedding
evidence signal**: maintainers should be able to confirm the corpus is
generated, split, de-duplicated, and baselined in a reproducible, non-overfit
way *before* a detector path that consumes it is considered.

Everything below is checkable against the merged generator
[`benchmarks/prompt-injection/harness/generate-corpus.py`](../../benchmarks/prompt-injection/harness/generate-corpus.py)
and the baseline harness
[`benchmarks/prompt-injection/harness/agt-rules-baseline/`](../../benchmarks/prompt-injection/harness/agt-rules-baseline/).
No runtime behavior is described or changed here — this is documentation only.

> Scope honesty: the corpus is **synthetic** research data for controlled,
> reproducible detector evaluation. It is not training data, not production
> policy, and not a real-traffic guarantee.

## 1. How are synthetic families generated?

Deterministic, stdlib-only generation, fully reproducible for a fixed seed and
profile:

- **Seed / round:** `SEED = 1337`, `ROUND = "prompt_injection_fixture_v1"`,
  `ID_PREFIX = "pi1"`. Re-running with the same `--profile` reproduces the
  corpus byte-for-byte.
- **Profiles (row caps):** `PROFILE_LIMITS = { smoke: 10, pilot: 120, large: 1600 }`
  per family — the fixture ships the `smoke` profile; larger profiles regenerate
  on demand.
- **Attack families (8):** `direct_override`, `prompt_leakage`,
  `indirect_injection`, `tool_abuse`, `tool_result_injection`,
  `output_exfiltration`, `memory_poisoning`, `data_boundary_abuse` — each defined
  by `ATTACK_TEMPLATES` with slot fillers `ACTIONS` / `TARGETS` / `TOOL_NAMES`.
- **Bypass classes** (the obfuscation surface, `ALLOWED_BYPASS_CLASSES`,
  14 classes): `none`, `plain`, `rot13`, `compact_plain`, `compact_leet`,
  `chunked_leet`, `separator_spaced`, `letter_spaced`, `leet_spacing`,
  `leet_letter_spaced`, `homoglyph`, `diacritics`, `encoding`, `multilingual`.
  Each row records its `bypass_class`, so coverage and per-class results are
  auditable.
- **Provenance metadata per row:** `source_type`, `trust_level`, `attack_class`,
  `benign_subclass`, `family_id`, `group_id`, `split`, `bypass_class`. A
  fixed `TEXT_MARKER` (`PI1`) tags every synthetic row so fixture text can never
  be mistaken for real traffic.

## 2. How is overfitting controlled?

Splitting is by **family/group, never by random row**, and three independent
leakage checks must all read zero across splits:

- **Split unit:** `split_for(family_id)` assigns each family deterministically to
  one of 5 buckets (hash of `SEED:family_id` with a per-prefix offset), mapped to
  `SPLITS = (exemplar_bank, validation, test)`. All rows of a family land in the
  same split — no family or group straddles splits.
- **Exact-normalized leakage:** every row is normalized (`NFKC` + casefold +
  whitespace-collapse) and hashed; any identical normalized text appearing in two
  splits is reported and must be zero.
- **Near-duplicate leakage:** 7-gram shingles (`NEAR_DUPLICATE_NGRAM = 7`),
  simhash with 16-bit bands (`SIMHASH_BAND_BITS = 16`) for candidate blocking,
  Jaccard similarity threshold `NEAR_DUPLICATE_THRESHOLD = 0.92`; any cross-split
  pair at or above threshold is reported and must be zero.
- **Held-out bypass classes:** because obfuscation is a per-row `bypass_class`,
  evaluation can hold bypass classes out of the exemplar bank and measure
  generalization to disguises the detector never saw.

The manifest records `family_split_leaks`, `group_split_leaks`, exact and
near-duplicate cross-split counts, and `split_coverage` — so the
no-overfit claim is a checkable artifact, not an assertion.

## 3. How are benign controls constructed?

Every attack family ships with **matched benign controls** so false-positives are
inspectable and the corpus does not reward "attack-shaped wording" alone:

- **Adjacent-security benign** (`benign_security_discussion`,
  `quoted_injection_example`, plus security training / changelog / docs-and-code
  fixtures): legitimate text that *discusses or quotes* injection techniques —
  the hardest negatives.
- **Benign obfuscation controls** (`BENIGN_OBFUSCATION_BASES`): legitimate text
  carrying the same obfuscation surface (compact/high-entropy), so a detector
  cannot pass by treating obfuscation itself as malicious.
- **Legitimate imperative / tool-use requests** (`benign_tool_use`): ordinary
  "do X" requests, so imperative phrasing alone is not a tell.

## 4. What is the baseline?

The baseline is AGT's **existing rules-only detector**, run via
`agentmesh::prompt_injection::PromptInjectionDetector` by the
`agt-rules-baseline` harness. It is pinned to an exact upstream commit and a
detector-source SHA recorded alongside the metrics, so the baseline is
reproducible against a known AGT state. This detector is intentionally
high-precision / low-recall; low recall on hard held-out disguises is expected,
not a defect.

## 5. What does "zero false-positives observed" mean?

A **finite-sample observation on this frozen test split — not a guarantee.** The
baseline summarizer (`summarize-baseline.py`) reports, for every operating point:

- recall and false-positive rate with **Wilson 95% confidence intervals**, and
- **base-rate-adjusted precision** at realistic attack rarity (100:1 and 1000:1
  benign:attack), because a low absolute FP rate still collapses precision when
  attacks are rare.

So "0 FP observed" always carries its interval and its base-rate caveat. Any
threshold is fit on **validation only and frozen before** the test split is
scored.

## 6. What is the production path (for the optional embedding signal)?

Strictly additive and conservative — the deterministic AGT controls remain the
authority:

- **Evidence only:** the embedding produces an auditable score/margin that can
  feed review/routing; it does **not** hard-block on its own.
- **Default-off, behind an explicit flag/config option.**
- **Governance metadata decides action** — the embedding surfaces semantic cases
  current rules miss; policy/IFC decides what happens.
- **No hosted-inference requirement** (local, auditable).

This framing is deliberate: embeddings do **not** replace rules. The reviewable
result is that AGT's rules baseline is high-precision/low-recall, and a
conservative embedding operating point catches a meaningful subset of attacks the
rules miss at zero observed FP on this corpus — enough to justify a
reviewer/routing signal, not default blocking.

## Reproduce the methodology claims

```bash
# regenerate a profile deterministically and re-check leakage = 0
python3 benchmarks/prompt-injection/harness/generate-corpus.py --profile smoke
python3 benchmarks/prompt-injection/harness/check-corpus.py \
  benchmarks/prompt-injection/corpus/injection-smoke.jsonl
# rerun the AGT rules baseline + summary (Wilson CI + base-rate precision)
benchmarks/prompt-injection/run-smoke.sh
```

Every constant cited here (`SEED=1337`, `NEAR_DUPLICATE_THRESHOLD=0.92`,
`NEAR_DUPLICATE_NGRAM=7`, the 5-bucket split, the profile caps, the family and
bypass-class sets) lives in the merged generator and can be grepped directly.
