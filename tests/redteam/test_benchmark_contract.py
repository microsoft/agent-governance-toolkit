# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Contract tests for the deterministic red-team evidence benchmark."""

from __future__ import annotations

import ast
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


BENCHMARK_DIR = Path(__file__).resolve().parent / "benchmark"
SCRIPT = BENCHMARK_DIR / "benchmark.py"
SCHEMA = BENCHMARK_DIR / "contract.schema.json"
SCENARIOS = BENCHMARK_DIR / "smoke-scenarios.json"
SMOKE = BENCHMARK_DIR / "run-smoke.sh"


def load_benchmark():
    """Load the test-only benchmark module from its file path."""
    spec = importlib.util.spec_from_file_location("agt_redteam_benchmark", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load benchmark module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BenchmarkPresenceTests(unittest.TestCase):
    def test_implementation_exists(self):
        self.assertTrue(SCRIPT.exists(), "benchmark implementation is not present")


@unittest.skipUnless(SCRIPT.exists(), "implementation not added yet")
class BenchmarkContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.benchmark = load_benchmark()

    def test_schema_contract_covers_all_records_and_forbids_certification(self):
        contract = json.loads(SCHEMA.read_text(encoding="utf-8"))

        self.assertEqual(
            {"scenario", "tool_trace", "result", "report"},
            set(contract["$defs"]),
        )
        for name in ("scenario", "tool_trace", "result", "report"):
            self.assertFalse(contract["$defs"][name]["additionalProperties"])
        self.assertFalse(
            contract["$defs"]["report"]["properties"]["certification_claim"]["const"]
        )

    def test_schema_fields_match_python_contract_constants(self):
        contract = json.loads(SCHEMA.read_text(encoding="utf-8"))
        field_contracts = {
            "scenario": self.benchmark.SCENARIO_FIELDS,
            "tool_trace": self.benchmark.TRACE_FIELDS,
            "result": self.benchmark.RESULT_FIELDS,
            "report": self.benchmark.REPORT_FIELDS,
        }

        for definition, python_fields in field_contracts.items():
            with self.subTest(definition=definition):
                schema = contract["$defs"][definition]
                self.assertEqual(python_fields, frozenset(schema["properties"]))
                self.assertEqual(python_fields, frozenset(schema["required"]))

    def test_smoke_scenarios_cover_each_trap_class_and_scenario_kind(self):
        scenarios = self.benchmark.load_scenarios(SCENARIOS)

        coverage = self.benchmark.validate_scenarios(scenarios)

        self.assertEqual(24, coverage["scenario_count"])
        self.assertEqual(
            {trap: 4 for trap in self.benchmark.TRAP_CLASSES}, coverage["trap_counts"]
        )
        self.assertEqual(
            {kind: 6 for kind in self.benchmark.SCENARIO_KINDS}, coverage["kind_counts"]
        )

    def test_happy_path_preserves_detection_action_matrix_and_utility(self):
        scenarios = self.benchmark.load_scenarios(SCENARIOS)

        traces, report = self.benchmark.run_benchmark(scenarios)

        self.assertEqual(24, len(traces))
        self.assertEqual(24, len(report["results"]))
        self.assertEqual("L2_mock_behavioural", report["evidence_level"])
        self.assertFalse(report["certification_claim"])
        self.assertEqual(
            {
                "detected_contained": 6,
                "detected_executed": 0,
                "undetected_contained": 6,
                "undetected_executed": 0,
            },
            report["summary"]["attack_matrix"],
        )
        self.assertEqual(
            {
                "benign_total": 12,
                "benign_allowed": 12,
                "benign_false_blocks": 0,
                "benign_detector_flags": 0,
            },
            report["summary"]["utility"],
        )
        self.assertEqual(0, report["summary"]["failure_count"])
        self.assertTrue(report["passed"])
        self.assertTrue(all(trace["side_effects"] == "none" for trace in traces))
        self.assertTrue(all(trace["audit_event_present"] for trace in traces))

    def test_unknown_raw_payload_field_is_rejected(self):
        scenarios = self.benchmark.load_scenarios(SCENARIOS)
        scenarios[0]["payload"] = "untrusted raw content"

        with self.assertRaisesRegex(
            self.benchmark.ContractError, "unexpected fields.*payload"
        ):
            self.benchmark.validate_scenarios(scenarios)

    def test_missing_and_malformed_scenario_files_fail_with_structured_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(
                self.benchmark.ContractError, "scenario file not found"
            ):
                self.benchmark.load_scenarios(root / "missing.json")

            malformed = root / "malformed.json"
            malformed.write_text("[{", encoding="utf-8")
            with self.assertRaisesRegex(
                self.benchmark.ContractError, "invalid scenario JSON"
            ):
                self.benchmark.load_scenarios(malformed)

    def test_live_url_is_rejected_by_metadata_hygiene(self):
        with self.assertRaisesRegex(self.benchmark.HygieneError, "live URL"):
            self.benchmark.ensure_hygiene(
                {"title": "See https://example.invalid/live"}, source="planted-url"
            )

    def test_duplicate_scenario_id_is_rejected(self):
        scenarios = self.benchmark.load_scenarios(SCENARIOS)
        scenarios[1]["id"] = scenarios[0]["id"]

        with self.assertRaisesRegex(
            self.benchmark.ContractError, "duplicate scenario id"
        ):
            self.benchmark.validate_scenarios(scenarios)

    def test_unknown_trap_and_mismatched_control_are_rejected(self):
        cases = (
            ("trap_class", "Unknown Trap", "trap_class is unknown"),
            ("control_id", "mock:wrong-boundary", "tool/control does not match"),
        )
        for field, value, error in cases:
            with self.subTest(field=field):
                scenarios = self.benchmark.load_scenarios(SCENARIOS)
                scenarios[0][field] = value
                with self.assertRaisesRegex(self.benchmark.ContractError, error):
                    self.benchmark.validate_scenarios(scenarios)

    def test_missing_class_kind_cell_is_rejected(self):
        scenarios = self.benchmark.load_scenarios(SCENARIOS)[:-1]

        with self.assertRaisesRegex(
            self.benchmark.ContractError, "exactly 24 scenarios"
        ):
            self.benchmark.validate_scenarios(scenarios)

    def test_hygiene_rejects_secret_and_unsupported_certification_claim(self):
        with self.assertRaisesRegex(self.benchmark.HygieneError, "secret-shaped"):
            self.benchmark.ensure_hygiene(
                {"title": "AKIA" + ("A" * 16)}, source="planted-secret"
            )
        with self.assertRaisesRegex(
            self.benchmark.HygieneError, "certification language"
        ):
            self.benchmark.ensure_hygiene(
                {"title": "officially certified agent"}, source="planted-claim"
            )
        with self.assertRaisesRegex(self.benchmark.ContractError, "must be false"):
            report = self.benchmark.run_benchmark(
                self.benchmark.load_scenarios(SCENARIOS)
            )[1]
            report["certification_claim"] = True
            self.benchmark.validate_report(report)

    def test_real_execution_capabilities_are_absent(self):
        tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported.update(
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        )
        self.assertTrue(
            {"subprocess", "socket", "requests", "httpx", "urllib"}.isdisjoint(imported)
        )

    def test_executed_attacks_are_visible_and_fail_gate(self):
        report = self.benchmark.run_benchmark(self.benchmark.load_scenarios(SCENARIOS))[
            1
        ]
        cases = (
            ("canonical_positive", "detected_executed"),
            ("evasion_positive", "undetected_executed"),
        )
        for scenario_kind, matrix_cell in cases:
            with self.subTest(matrix_cell=matrix_cell):
                result = copy.deepcopy(
                    next(
                        row
                        for row in report["results"]
                        if row["scenario_kind"] == scenario_kind
                    )
                )
                result["action_outcome"] = "executed"
                result["status"] = "fail"
                result["trace"][0].update(
                    {
                        "executed": True,
                        "action_outcome": "executed",
                        "blocked_at": None,
                        "control_id": None,
                        "reason": "unsafe action executed",
                    }
                )

                summary = self.benchmark.summarize_results([result])

                self.assertEqual(1, summary["attack_matrix"][matrix_cell])
                self.assertFalse(self.benchmark.summary_passes(summary))

    def test_benign_false_block_fails_gate(self):
        report = self.benchmark.run_benchmark(self.benchmark.load_scenarios(SCENARIOS))[
            1
        ]
        result = copy.deepcopy(
            next(
                row
                for row in report["results"]
                if row["scenario_kind"] == "hard_benign"
            )
        )
        result["action_outcome"] = "contained"
        result["status"] = "fail"
        result["trace"][0].update(
            {
                "executed": False,
                "action_outcome": "contained",
                "blocked_at": "mock:policy-boundary",
                "control_id": "mock:content-boundary",
                "reason": "benign action blocked by mock control",
            }
        )

        summary = self.benchmark.summarize_results([result])

        self.assertEqual(1, summary["utility"]["benign_false_blocks"])
        self.assertFalse(self.benchmark.summary_passes(summary))

    def test_benign_detector_flag_is_visible_and_fails_gate(self):
        report = self.benchmark.run_benchmark(self.benchmark.load_scenarios(SCENARIOS))[
            1
        ]
        result = copy.deepcopy(
            next(
                row for row in report["results"] if row["scenario_kind"] == "near_miss"
            )
        )
        result["detection_verdict"] = "flagged"

        summary = self.benchmark.summarize_results([result])

        self.assertEqual(1, summary["utility"]["benign_detector_flags"])
        self.assertFalse(self.benchmark.summary_passes(summary))

    def test_cli_run_writes_bounded_metadata_only_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "run",
                    "--scenarios",
                    str(SCENARIOS),
                    "--out",
                    tmp,
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(0, completed.returncode, completed.stderr)
            report = json.loads((Path(tmp) / "report.json").read_text(encoding="utf-8"))
            traces = (
                (Path(tmp) / "traces.jsonl").read_text(encoding="utf-8").splitlines()
            )
            self.assertTrue(report["passed"])
            self.assertEqual(24, len(traces))
            self.assertNotIn("payload", completed.stdout.lower())

    def test_cli_invalid_input_fails_closed_without_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            scenarios = self.benchmark.load_scenarios(SCENARIOS)
            scenarios[0]["payload"] = "untrusted raw content"
            invalid_path = tmp_path / "invalid-scenarios.json"
            invalid_path.write_text(json.dumps(scenarios), encoding="utf-8")
            out_path = tmp_path / "out"

            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "run",
                    "--scenarios",
                    str(invalid_path),
                    "--out",
                    str(out_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(1, completed.returncode)
            self.assertIn("ContractError", completed.stderr)
            self.assertIn("unexpected fields", completed.stderr)
            self.assertNotIn("Traceback", completed.stderr)
            self.assertFalse((out_path / "report.json").exists())

    def test_smoke_script_runs_front_to_end(self):
        bash = shutil.which("bash")
        if bash is None:
            self.skipTest("Bash is required for the smoke wrapper")
        completed = subprocess.run(
            [bash, f"./{SMOKE.name}"],
            check=False,
            capture_output=True,
            text=True,
            cwd=BENCHMARK_DIR,
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("[redteam-smoke] OK", completed.stdout)


if __name__ == "__main__":
    unittest.main()
