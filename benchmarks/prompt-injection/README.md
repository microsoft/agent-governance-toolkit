# Prompt-Injection Evaluation Fixture

This directory contains a standalone fixture for evaluating AGT's existing Rust prompt-injection detector against a labelled synthetic corpus.

It is intentionally evaluation-only:

- no runtime behavior changes
- no embedding detector
- no default blocking or routing policy
- no production performance claim

The fixture is useful because it gives maintainers a reproducible way to inspect where the existing rules catch prompt-injection variants and where they produce false positives on benign security discussion or documentation text.

## Contents

| Path | Purpose |
|---|---|
| `corpus/injection-smoke.jsonl` | 280-row smoke corpus with labelled attack and benign rows. |
| `corpus/manifest-smoke.json` | Deterministic generation manifest, counts, hash, and hygiene gates. |
| `corpus/check-smoke-summary.json` | Corpus validation output. |
| `harness/generate-corpus.py` | Stdlib-only deterministic corpus generator. |
| `harness/check-corpus.py` | Corpus schema, split-leakage, duplicate, and hash checks. |
| `harness/agt-rules-baseline/` | Rust scorer that imports AGT's in-repo `agentmesh` crate. |
| `harness/summarize-baseline.py` | Wilson interval and base-rate summary builder. |
| `artifacts/rules-baseline-smoke-summary.json` | Metadata-only scorer summary. |
| `artifacts/rules-baseline-smoke-metrics.json` | Metadata-only rate and interval summary. |
| `run-smoke.sh` | End-to-end smoke reproduction command. |

## Reproduce

From the repository root:

```bash
bash benchmarks/prompt-injection/run-smoke.sh
```

The script:

1. compiles the Python helpers
2. regenerates the smoke corpus and manifest
3. validates corpus hygiene
4. compiles the Rust scorer against AGT's in-repo `agentmesh` crate
5. regenerates metadata-only scorer artifacts
6. confirms evidence outputs do not include raw prompt text

Build artifacts, Python bytecode, and per-row scorer evidence are written under the system temporary directory by default. The committed evidence files are summaries only.

## Smoke Corpus Shape

The committed smoke fixture contains:

| Class | Rows |
|---|---:|
| Attack-labelled rows | 110 |
| Benign-labelled rows | 170 |
| Total rows | 280 |

The split is deterministic and family-based:

| Split | Rows |
|---|---:|
| `exemplar_bank` | 171 |
| `validation` | 64 |
| `test` | 45 |

## Current Smoke Baseline

The current scorer artifact records AGT's existing Rust `PromptInjectionDetector` with default configuration on the smoke corpus:

| Metric | Value |
|---|---:|
| Attack rows caught | 7 / 110 |
| Attack recall | 0.0636 |
| Benign rows flagged | 16 / 170 |
| Benign false-positive rate | 0.0941 |
| False positives per 1k benign rows | 94.12 |

These are smoke-fixture numbers only. They should not be read as production detector performance or as a broad security benchmark.

## Why This Fixture Exists

Rules-based prompt-injection detection is expected to be high precision for known patterns, not a complete general-purpose detector. This fixture makes that trade-off auditable by keeping attack variants, benign adjacent text, and detector evidence in one reproducible place.

The most important false-positive pressure in the smoke fixture is benign material that quotes or discusses prompt-injection phrases, such as security training, detector fixtures, documentation comments, and research excerpts. That is useful signal for future thresholding, routing, or reviewer-surfacing experiments.
