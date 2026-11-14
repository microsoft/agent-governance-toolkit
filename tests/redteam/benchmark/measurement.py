# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""240-scenario red-team measurement tier with actual detector evidence.

Builds on the deterministic smoke benchmark (``benchmark.py``, merged via
#3362) per the scope agreed in microsoft/agent-governance-toolkit#3349:
a balanced canonical/evasion/hard-benign/near-miss suite (10 scenarios per
trap-class cell instead of smoke's 1), reusing the same scenario/trace/result
contracts and detection-to-action matrix unmodified.

What's new relative to the smoke tier:

- ``detection_verdict`` is no longer declared metadata taken on faith. The
  measurement report's ``detector_evidence`` section runs each scenario's
  probe text (``measurement-probes.json``, generated alongside the scenario
  fixture — never embedded in the scenario contract, which stays metadata
  only) through the hermetic static detector in ``detector.py`` and records
  the measured verdict next to the declared one.
- The containment/action-outcome mock simulation is reused byte-for-byte
  from ``benchmark.py`` (``simulate_trace``, ``build_result``,
  ``summarize_results``, ``summary_passes``): whether a control contains an
  unsafe action does not depend on whether the detector caught it. That is
  the point of defense in depth, and it is still the hard release gate.
- Detector catch/miss rates are evidence, not a release gate: a static
  pattern detector is expected to miss some evasions by design, and the
  measurement tier's job is to report that rate accurately, not to fail the
  build over it.

Deliberately out of scope here (left for later #3349 workstreams, per
maintainer direction): the external static corpus, the live sandboxed tier,
and the public ``agt red-team`` CLI surface.
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from benchmark import (  # noqa: E402
    DELIVERY_VECTORS,
    POSITIVE_KINDS,
    SCENARIO_FIELDS,
    SCENARIO_KINDS,
    TARGET_LAYERS,
    TRAP_CLASSES,
    TRAP_TOOL_CONTROL,
    ContractError,
    HygieneError,
    _unexpected_fields,
    build_result,
    ensure_hygiene,
    load_scenarios,
    simulate_trace,
    summarize_results,
    summary_passes,
    validate_result,
    write_artifacts,
    _scenario_set_hash,
)
from detector import score_probe  # noqa: E402

MEASUREMENT_SCENARIO_COUNT = 240
MEASUREMENT_CELL_SIZE = 10
_MEASUREMENT_ID_RE = re.compile(r"rt-measure-[a-z0-9-]+-[0-9]{3}\Z")

DETECTOR_EVIDENCE_FIELDS = frozenset(
    {"scenario_id", "trap_class", "scenario_kind", "declared_verdict", "measured_verdict", "matched_declared"}
)
MEASUREMENT_REPORT_FIELDS = frozenset(
    {
        "benchmark",
        "scenario_set_hash",
        "evidence_level",
        "certification_claim",
        "scenario_count",
        "passed",
        "summary",
        "results",
        "detector_evidence",
    }
)


def _validate_measurement_scenario(scenario: Any, index: int) -> None:
    """Schema-identical to ``benchmark._validate_scenario``, except the id
    pattern and per-cell count are the measurement tier's own (240 total,
    10 per cell, ``rt-measure-...`` ids). Kept as its own function rather than
    parameterizing the smoke validator so the already-reviewed smoke contract
    in benchmark.py stays untouched by this addition.
    """
    label = f"scenario[{index}]"
    if not isinstance(scenario, dict):
        raise ContractError(f"{label} must be an object")
    _unexpected_fields(scenario, SCENARIO_FIELDS, label)
    if not isinstance(scenario["id"], str) or not _MEASUREMENT_ID_RE.fullmatch(scenario["id"]):
        raise ContractError(f"{label}.id has invalid format")
    if not isinstance(scenario["title"], str) or not 8 <= len(scenario["title"]) <= 100:
        raise ContractError(f"{label}.title must contain 8-100 characters")
    trap_class = scenario["trap_class"]
    scenario_kind = scenario["scenario_kind"]
    if trap_class not in TRAP_CLASSES:
        raise ContractError(f"{label}.trap_class is unknown: {trap_class!r}")
    if scenario_kind not in SCENARIO_KINDS:
        raise ContractError(f"{label}.scenario_kind is unknown: {scenario_kind!r}")
    if scenario["delivery_vector"] not in DELIVERY_VECTORS:
        raise ContractError(f"{label}.delivery_vector is unknown")
    if scenario["target_layer"] not in TARGET_LAYERS:
        raise ContractError(f"{label}.target_layer is unknown")
    if scenario["detection_verdict"] not in {"flagged", "clean"}:
        raise ContractError(f"{label}.detection_verdict is unknown")
    expected_tool, expected_control = TRAP_TOOL_CONTROL[trap_class]
    if scenario["tool"] != expected_tool or scenario["control_id"] != expected_control:
        raise ContractError(f"{label} tool/control does not match its trap class")
    if not isinstance(scenario["unsafe"], bool):
        raise ContractError(f"{label}.unsafe must be boolean")

    if scenario_kind in POSITIVE_KINDS:
        if not scenario["unsafe"] or scenario["expected_action_outcome"] != "contained":
            raise ContractError(f"{label} positive scenario must be unsafe and contained")
    else:
        if scenario["unsafe"] or scenario["expected_action_outcome"] != "executed":
            raise ContractError(f"{label} benign scenario must be a safe executed dry-run")

    expected_detection = "flagged" if scenario_kind == "canonical_positive" else "clean"
    if scenario["detection_verdict"] != expected_detection:
        raise ContractError(
            f"{label}.{scenario_kind} requires detection_verdict {expected_detection!r}"
        )


def validate_measurement_scenarios(scenarios: Any) -> dict[str, Any]:
    """Validate the 240-scenario (10-per-cell) measurement contract."""
    if not isinstance(scenarios, list):
        raise ContractError("scenarios must be a list")
    if len(scenarios) != MEASUREMENT_SCENARIO_COUNT:
        raise ContractError(
            f"measurement suite requires exactly {MEASUREMENT_SCENARIO_COUNT} "
            f"scenarios, got {len(scenarios)}"
        )

    ids: set[str] = set()
    cell_counts: Counter[tuple[str, str]] = Counter()
    for index, scenario in enumerate(scenarios):
        _validate_measurement_scenario(scenario, index)
        if scenario["id"] in ids:
            raise ContractError(f"duplicate scenario id: {scenario['id']}")
        ids.add(scenario["id"])
        cell_counts[(scenario["trap_class"], scenario["scenario_kind"])] += 1

    invalid_cells = [
        f"{trap}/{kind}={cell_counts[(trap, kind)]}"
        for trap in TRAP_CLASSES
        for kind in SCENARIO_KINDS
        if cell_counts[(trap, kind)] != MEASUREMENT_CELL_SIZE
    ]
    if invalid_cells:
        raise ContractError(
            f"coverage requires exactly {MEASUREMENT_CELL_SIZE} scenarios per "
            "trap-class/kind cell: " + ", ".join(invalid_cells)
        )
    ensure_hygiene(scenarios, source="measurement scenarios")
    return {"scenario_count": len(scenarios), "cells": len(cell_counts)}


def load_probes(path: Path | str) -> dict[str, str]:
    """Load the ``scenario_id -> probe_text`` map. Never hygiene-checked:
    this file intentionally carries illustrative probe wording that the
    scenario/report contract forbids (see module docstring).
    """
    probe_path = Path(path)
    try:
        value = json.loads(probe_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ContractError(f"probe file not found: {probe_path}") from exc
    except json.JSONDecodeError as exc:
        raise ContractError(f"invalid probe JSON at line {exc.lineno}: {exc.msg}") from exc
    if not isinstance(value, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in value.items()
    ):
        raise ContractError("probe file must be a flat object of string to string")
    return value


def score_detector_evidence(
    scenarios: list[dict[str, Any]], probes: dict[str, str]
) -> list[dict[str, Any]]:
    """Run each scenario's probe through the hermetic detector and compare
    the measured verdict to the scenario's declared ``detection_verdict``.
    """
    evidence: list[dict[str, Any]] = []
    missing = [s["id"] for s in scenarios if s["id"] not in probes]
    if missing:
        raise ContractError(f"no probe text for scenario ids: {missing[:5]}")
    for scenario in scenarios:
        probe_text = probes[scenario["id"]]
        measured = score_probe(scenario["trap_class"], probe_text)
        evidence.append(
            {
                "scenario_id": scenario["id"],
                "trap_class": scenario["trap_class"],
                "scenario_kind": scenario["scenario_kind"],
                "declared_verdict": scenario["detection_verdict"],
                "measured_verdict": measured,
                "matched_declared": measured == scenario["detection_verdict"],
            }
        )
    return evidence


def validate_detector_evidence(evidence: Any) -> None:
    if not isinstance(evidence, list) or len(evidence) != MEASUREMENT_SCENARIO_COUNT:
        raise ContractError(
            f"detector_evidence must contain exactly {MEASUREMENT_SCENARIO_COUNT} entries"
        )
    for entry in evidence:
        if not isinstance(entry, dict):
            raise ContractError("detector evidence entry must be an object")
        _unexpected_fields(entry, DETECTOR_EVIDENCE_FIELDS, "detector evidence entry")
        if entry["trap_class"] not in TRAP_CLASSES:
            raise ContractError("detector evidence trap_class is unknown")
        if entry["scenario_kind"] not in SCENARIO_KINDS:
            raise ContractError("detector evidence scenario_kind is unknown")
        for field in ("declared_verdict", "measured_verdict"):
            if entry[field] not in {"flagged", "clean"}:
                raise ContractError(f"detector evidence {field} is unknown")
        expected_match = entry["declared_verdict"] == entry["measured_verdict"]
        if entry["matched_declared"] is not expected_match:
            raise ContractError("detector evidence matched_declared does not match verdicts")


def summarize_detector_evidence(evidence: list[dict[str, Any]]) -> dict[str, Any]:
    validate_detector_evidence(evidence)
    matched = sum(1 for entry in evidence if entry["matched_declared"])
    catch_rate: dict[str, dict[str, int]] = {
        trap: {"flagged": 0, "total": 0} for trap in TRAP_CLASSES
    }
    for entry in evidence:
        bucket = catch_rate[entry["trap_class"]]
        bucket["total"] += 1
        if entry["measured_verdict"] == "flagged":
            bucket["flagged"] += 1
    return {
        "probes_scored": len(evidence),
        "matched_declared": matched,
        "mismatched_declared": len(evidence) - matched,
        "catch_rate_by_trap_class": catch_rate,
    }


def run_measurement_benchmark(
    scenarios: list[dict[str, Any]], probes: dict[str, str]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    validate_measurement_scenarios(scenarios)
    traces = [simulate_trace(scenario) for scenario in scenarios]
    results = [build_result(scenario, trace) for scenario, trace in zip(scenarios, traces)]
    summary = summarize_results(results)
    detector_evidence = score_detector_evidence(scenarios, probes)
    report = {
        "benchmark": "agt-redteam-measurement-v1",
        "scenario_set_hash": _scenario_set_hash(scenarios),
        "evidence_level": "L2_mock_behavioural",
        "certification_claim": False,
        "scenario_count": len(scenarios),
        "passed": summary_passes(summary),
        "summary": summary,
        "results": results,
        "detector_evidence": detector_evidence,
    }
    validate_measurement_report(report, scenarios=scenarios)
    return traces, report


def validate_measurement_report(
    report: Any, *, scenarios: list[dict[str, Any]] | None = None
) -> None:
    if not isinstance(report, dict):
        raise ContractError("report must be an object")
    _unexpected_fields(report, MEASUREMENT_REPORT_FIELDS, "report")
    if report["certification_claim"] is not False:
        raise ContractError("report certification_claim must be false")
    if report["benchmark"] != "agt-redteam-measurement-v1":
        raise ContractError("report benchmark identifier is unknown")
    if report["evidence_level"] != "L2_mock_behavioural":
        raise ContractError("report must remain L2_mock_behavioural")
    if report["scenario_count"] != MEASUREMENT_SCENARIO_COUNT:
        raise ContractError(f"report scenario_count must be exactly {MEASUREMENT_SCENARIO_COUNT}")
    if not isinstance(report["results"], list) or len(report["results"]) != MEASUREMENT_SCENARIO_COUNT:
        raise ContractError(f"report must contain exactly {MEASUREMENT_SCENARIO_COUNT} results")
    if scenarios is not None:
        validate_measurement_scenarios(scenarios)
        if report["scenario_set_hash"] != _scenario_set_hash(scenarios):
            raise ContractError("report scenario_set_hash does not match scenarios")
        expected_ids = sorted(scenario["id"] for scenario in scenarios)
        result_ids = sorted(
            result.get("scenario_id") if isinstance(result, dict) else None
            for result in report["results"]
        )
        if result_ids != expected_ids:
            raise ContractError("report result scenario_ids do not match scenarios")
        evidence_ids = sorted(
            entry.get("scenario_id") if isinstance(entry, dict) else None
            for entry in report.get("detector_evidence", [])
        )
        if evidence_ids != expected_ids:
            raise ContractError("report detector_evidence scenario_ids do not match scenarios")
    for result in report["results"]:
        validate_result(result)
    expected_summary = summarize_results(report["results"])
    if report["summary"] != expected_summary:
        raise ContractError("report summary does not match its results")
    expected_passed = summary_passes(report["summary"])
    if report["passed"] is not expected_passed:
        raise ContractError("report passed flag does not match the release gate")
    validate_detector_evidence(report["detector_evidence"])
    # detector_evidence entries carry only categorical verdicts (see
    # DETECTOR_EVIDENCE_FIELDS), never probe text, so the full report can be
    # hygiene-checked directly.
    ensure_hygiene(report, source="measurement report")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="measurement.py")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate", help="validate the 240-scenario contract")
    validate_parser.add_argument("--scenarios", required=True)

    run_parser = subparsers.add_parser("run", help="run the measurement benchmark")
    run_parser.add_argument("--scenarios", required=True)
    run_parser.add_argument("--probes", required=True)
    run_parser.add_argument("--out", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "validate":
            coverage = validate_measurement_scenarios(load_scenarios(args.scenarios))
            print(json.dumps(coverage, sort_keys=True))
            return 0
        scenarios = load_scenarios(args.scenarios)
        probes = load_probes(args.probes)
        traces, report = run_measurement_benchmark(scenarios, probes)
        write_artifacts(args.out, traces, report)
        summary_line = {
            "summary": report["summary"],
            "detector_evidence": summarize_detector_evidence(report["detector_evidence"]),
        }
        print(json.dumps(summary_line, sort_keys=True))
        return 0 if report["passed"] else 1
    except (ContractError, HygieneError) as exc:
        print(f"{exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"OSError: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
