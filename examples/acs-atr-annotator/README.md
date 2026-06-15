# ACS + Agent Threat Rules (ATR) annotator

Enforce [Agent Threat Rules](https://github.com/Agent-Threat-Rule/agent-threat-rules) (ATR) through the Agent Control Specification (ACS) runtime: a host-provided annotator scans the policy target with the open-source ATR engine, and a thin `custom` policy denies when ATR matches.

ATR is an open, MIT-licensed detection ruleset for AI-agent threats — prompt injection, tool-argument tampering, context exfiltration, and malicious skill manifests. Detection runs in-process with deterministic pattern rules (no model call, no network). This example is the runtime/behavioral counterpart to the static control mapping in `docs/mappings/atr-agt-mapping.md`; the two sit at different levels and do not overlap.

## Overview

| | |
|---|---|
| **Pattern** | `custom` policy + host annotator dispatcher |
| **Decision** | `deny` on an ATR match at or above `min_severity`, else `allow` |
| **Engine** | `pyatr` (Agent Threat Rules), in-process, deterministic |
| **Network / model calls** | none |

How it maps onto ACS:

- `ATRAnnotator.dispatch(...)` runs ATR over the policy target and returns a free-form annotation (the match summary). It makes no decision.
- `ATRPolicy.evaluate(invocation)` reads that annotation and returns an ACS verdict — `deny` with a `reason` and an `evidence` payload (rule IDs plus links to verify each rule), or `allow`.

The adapter only translates shapes; it does not re-implement detection. A dispatcher exception fails closed in the ACS runtime (`runtime_error:annotation_failed`), so an engine error blocks rather than silently allows. Verdicts use only `decision`/`reason`/`evidence` — the `effects[]` surface was removed by AGT D1, and this example has no need to mutate the target (which would require a `transform` verdict).

## Files

```
acs-atr-annotator/
  atr_adapter.py            ATRAnnotator.dispatch + ATRPolicy.evaluate + make_control
  manifest.yaml            type: custom policy + atr_scanner annotator + intervention points
  demo.py                  benign + injection prompt through the input intervention point
  requirements.txt         pyatr, PyYAML, pytest (ACS SDK installed from this repo)
  test_atr_annotator.py    smoke tests (dispatcher logic + optional ACS runtime e2e)
```

## Setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e policy-engine/sdk/python        # ACS Python SDK (builds the native core)
pip install -r examples/acs-atr-annotator/requirements.txt
```

## Run

```bash
cd examples/acs-atr-annotator
python demo.py
```

Expected:

```
[benign] decision=allow reason=No Agent Threat Rules matched the policy target
[prompt injection] decision=deny reason=Agent Threat Rules matched N rule(s) (max severity critical): ATR-2026-...
```

## Test

```bash
cd examples/acs-atr-annotator
pytest test_atr_annotator.py
```

The dispatcher-logic tests run with only `pyatr` installed. The end-to-end test additionally needs the ACS SDK and native core; it is skipped automatically when they are unavailable.

## Configuration

`manifest.yaml` carries the custom policy's `adapter_config`:

- `rules_dir`: empty uses the rules bundled with `pyatr`; set a path to point at a checkout of the ATR repository or a curated subset.
- `min_severity`: `low` | `medium` | `high` | `critical` — the threshold at or above which a match denies.

`make_control(rules_dir=..., min_severity=...)` lets the host override either at construction time.

## Notes

- `pyatr` is pre-1.0; it is an optional dependency, imported lazily, and the annotator raises a clear `ImportError` if it is missing.
- ATR is independent and MIT-licensed; the live ruleset and per-rule references are at <https://github.com/Agent-Threat-Rule/agent-threat-rules>.
