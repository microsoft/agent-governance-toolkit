# Detection-to-action red-team smoke benchmark

This test-only benchmark answers a narrow question: after an attack is
detected—or missed—does the unsafe action execute, or does a downstream control
contain it?

It complements the existing prompt scanner, adversarial playbooks, and OWASP
ASI policy tests. It does not replace them and does not change the public
`agt red-team` CLI.

## What the smoke tier covers

The fixture contains exactly 24 metadata-only scenarios: one canonical attack,
one evasion attack, one hard-benign case, and one near miss for each of six trap
classes.

`detection_verdict` is declared scenario metadata in this phase; generating it
with a real detector, including detector catches on evasion rows, is phase-two work.

| Trap class | Surface |
|---|---|
| Content Injection | Content read from documents, browser state, or tool results |
| Semantic Manipulation | Authority, role-play, and task-framing changes |
| Cognitive State | Memory and cross-session state |
| Behavioural Control | Tool choice and action pressure |
| Systemic | Agent-to-agent and registry interactions |
| Human-in-the-Loop | Approval and review workflows |

The report keeps the attack matrix visible:

| | Action contained | Action executed |
|---|---|---|
| Detected | Expected containment | High-severity failure |
| Undetected | Defence in depth held | Worst-case failure |

Hard-benign and near-miss rows are reported separately as the utility arm. A
benign false block fails the smoke run, so a system cannot score well by
blocking everything.

## Run it

From the repository root:

```bash
bash tests/redteam/benchmark/run-smoke.sh
```

Run the contract tests:

```bash
python3 -m unittest discover -s tests/redteam -p 'test_benchmark_contract.py' -v
```

The smoke command validates the fixture, runs a deterministic mock harness,
creates temporary JSON/JSONL evidence, applies the artifact hygiene gate, and
then removes the temporary directory.

## The measurement tier: 240 scenarios with actual detector evidence

The measurement tier (`measurement.py`, agreed scope in
[issue #3349](https://github.com/microsoft/agent-governance-toolkit/issues/3349))
scales the smoke tier's 24-cell coverage to 10 scenarios per trap-class/kind
cell (240 total), reusing the same scenario/trace/result contracts and
detection-to-action matrix unmodified.

The difference from the smoke tier: `detection_verdict` is no longer declared
metadata taken on faith. Each scenario's probe text — held in
`measurement-probes.json`, generated alongside the scenario fixture and
deliberately kept out of the scenario/report contract, which stays
metadata-only — is scored by the hermetic, stdlib-only static detector in
`detector.py`. The report's `detector_evidence` section records the measured
verdict next to the declared one, plus a catch-rate breakdown per trap class.

The containment/action-outcome simulation is unchanged: whether a mock control
contains an unsafe action does not depend on whether the detector caught it.
That invariant — `*_executed == 0` for every unsafe scenario — stays the hard
release gate. Detector catch/miss rates are evidence, not a release gate: a
static pattern detector is expected to miss some evasions by design, and a
real run of this suite correctly shows `undetected_contained` scenarios
(evasion probes the detector misses, still contained by the mock control) —
that is the defense-in-depth signal the tier exists to surface.

Run it:

```bash
bash tests/redteam/benchmark/run-measurement.sh
```

Run the contract tests:

```bash
python3 -m unittest discover -s tests/redteam -p 'test_measurement_contract.py' -v
```

Regenerate the fixtures after editing a probe template (and verify there is
no drift with `--check`, which CI also runs):

```bash
python3 tests/redteam/benchmark/generate_measurement_scenarios.py
python3 tests/redteam/benchmark/generate_measurement_scenarios.py --check
```

## Evidence boundary

- The harness is side-effect-free and uses only the Python standard library.
- It records L2 mock behavioural evidence, never live-agent evidence.
- `executed` means that a benign dry-run completed inside the mock harness;
  every trace records `side_effects: none`.
- Scenario and report contracts reject unknown fields, including raw prompt or
  payload fields.
- Generated artifacts reject secret-shaped values, live URLs, and certification
  language.
- Every report contains `certification_claim: false`.

This benchmark is evidence, not a production-safety certification.

## Deferred work

The external static corpus integration, the opt-in live sandboxed tier,
`agent-sre` execution support, and public `agt red-team` CLI exposure remain
intentionally outside this contribution; see issue #3349's follow-up
workstreams 2–4.

## Prior art

The contract, evidence levels, and attempted-versus-executed trace semantics are
adapted from the MIT-licensed
[AGT-Embeddings-Experiment red-team benchmark](https://github.com/kerberosmansour/AGT-Embeddings-Experiment),
documented in
[issue #41](https://github.com/kerberosmansour/AGT-Embeddings-Experiment/issues/41)
and implemented in
[PR #40](https://github.com/kerberosmansour/AGT-Embeddings-Experiment/pull/40).

The upstream scope and phasing were discussed in
[AGT issue #3349](https://github.com/microsoft/agent-governance-toolkit/issues/3349).
