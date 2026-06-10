# Prompt-Injection Evaluation Fixture

AGT now includes a standalone prompt-injection evaluation fixture under [`benchmarks/prompt-injection/`](../../benchmarks/prompt-injection/).

This fixture is not a runtime feature and does not change enforcement behavior. It provides a reproducible corpus and harness for inspecting the current Rust prompt-injection detector on labelled synthetic examples.

## Scope

The fixture covers:

- direct override attempts
- prompt leakage attempts
- indirect prompt injection in retrieved or tool-result-like text
- tool abuse and output exfiltration patterns
- memory poisoning and data-boundary abuse patterns
- benign adjacent examples, including security training, documentation, code fixtures, and legitimate imperative requests

The fixture does not introduce:

- an embedding detector
- new blocking policy
- production thresholds
- policy-routing integration
- a production detector-performance claim

## Reproduce

From the repository root:

```bash
bash benchmarks/prompt-injection/run-smoke.sh
```

The command regenerates the 280-row smoke corpus, validates corpus hygiene, compiles the Rust scorer against the in-repo `agentmesh` crate, and rebuilds the metadata-only baseline artifacts.

## Current Smoke Result

The committed smoke baseline records the existing Rust `PromptInjectionDetector` with default configuration:

| Measure | Smoke result |
|---|---:|
| Attack-labelled rows | 110 |
| Benign-labelled rows | 170 |
| Attack rows caught | 7 |
| Benign rows flagged | 16 |
| Attack recall | 0.0636 |
| Benign false-positive rate | 0.0941 |

These numbers are intentionally labelled as smoke-fixture results. They are useful for regression tracking and methodology review, but they should not be presented as production AGT detector performance.

## Interpretation

The fixture is designed to make detector behavior auditable, especially the difference between:

- malicious instructions that should be surfaced or blocked by downstream policy
- benign security material that quotes prompt-injection phrases but should not be treated as an active attack

This makes it a low-risk first step before any optional detector experiments or routing changes are considered.
