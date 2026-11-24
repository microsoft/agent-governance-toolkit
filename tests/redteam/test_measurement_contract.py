# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Contract tests for the 240-scenario red-team measurement tier."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import unittest


BENCHMARK_DIR = Path(__file__).resolve().parent / "benchmark"
MEASUREMENT_SCRIPT = BENCHMARK_DIR / "measurement.py"
DETECTOR_SCRIPT = BENCHMARK_DIR / "detector.py"
GENERATOR_SCRIPT = BENCHMARK_DIR / "generate_measurement_scenarios.py"
SCENARIOS = BENCHMARK_DIR / "measurement-scenarios.json"
PROBES = BENCHMARK_DIR / "measurement-probes.json"


def load_module(path: Path, name: str):
    """Load a test-only module from its file path."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load module from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(MEASUREMENT_SCRIPT.exists(), "measurement tier not added yet")
class MeasurementContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.measurement = load_module(MEASUREMENT_SCRIPT, "agt_redteam_measurement")
        cls.detector = load_module(DETECTOR_SCRIPT, "agt_redteam_detector")

    def test_measurement_scenarios_cover_240_in_10_per_cell(self):
        scenarios = self.measurement.load_scenarios(SCENARIOS)

        coverage = self.measurement.validate_measurement_scenarios(scenarios)

        self.assertEqual(240, coverage["scenario_count"])
        self.assertEqual(24, coverage["cells"])

    def test_probe_corpus_covers_every_scenario_id_exactly(self):
        scenarios = self.measurement.load_scenarios(SCENARIOS)
        probes = self.measurement.load_probes(PROBES)

        scenario_ids = {s["id"] for s in scenarios}
        self.assertEqual(scenario_ids, set(probes))

    def test_happy_path_detector_evidence_matches_declared_metadata(self):
        scenarios = self.measurement.load_scenarios(SCENARIOS)
        probes = self.measurement.load_probes(PROBES)

        traces, report = self.measurement.run_measurement_benchmark(scenarios, probes)

        self.assertEqual(240, len(traces))
        self.assertEqual(240, len(report["results"]))
        self.assertEqual(240, len(report["detector_evidence"]))
        self.assertTrue(report["passed"])

        evidence_summary = self.measurement.summarize_detector_evidence(
            report["detector_evidence"]
        )
        self.assertEqual(240, evidence_summary["matched_declared"])
        self.assertEqual(0, evidence_summary["mismatched_declared"])
        for trap_counts in evidence_summary["catch_rate_by_trap_class"].values():
            self.assertEqual({"flagged": 10, "total": 40}, trap_counts)

    def test_attack_matrix_shows_evasion_misses_still_contained(self):
        """The whole point of real detector evidence: evasion probes should
        slip past the static detector (undetected) while the mock control
        still contains the unsafe action (defense in depth), and canonical
        probes should be both detected and contained.
        """
        scenarios = self.measurement.load_scenarios(SCENARIOS)
        probes = self.measurement.load_probes(PROBES)

        _, report = self.measurement.run_measurement_benchmark(scenarios, probes)

        self.assertEqual(
            {
                "detected_contained": 60,
                "detected_executed": 0,
                "undetected_contained": 60,
                "undetected_executed": 0,
            },
            report["summary"]["attack_matrix"],
        )
        self.assertEqual(
            {
                "benign_total": 120,
                "benign_allowed": 120,
                "benign_false_blocks": 0,
                "benign_detector_flags": 0,
            },
            report["summary"]["utility"],
        )

    def test_scenario_set_hash_is_independent_of_scenario_order(self):
        scenarios = self.measurement.load_scenarios(SCENARIOS)
        probes = self.measurement.load_probes(PROBES)

        original = self.measurement.run_measurement_benchmark(scenarios, probes)[1]
        reordered = self.measurement.run_measurement_benchmark(
            list(reversed(scenarios)), probes
        )[1]

        self.assertEqual(original["scenario_set_hash"], reordered["scenario_set_hash"])

    def test_report_validation_rejects_forged_scenario_identity(self):
        scenarios = self.measurement.load_scenarios(SCENARIOS)
        probes = self.measurement.load_probes(PROBES)
        report = self.measurement.run_measurement_benchmark(scenarios, probes)[1]

        forged = copy.deepcopy(report)
        forged["scenario_set_hash"] = "sha256:" + ("0" * 64)
        with self.assertRaisesRegex(
            self.measurement.ContractError, "scenario_set_hash does not match"
        ):
            self.measurement.validate_measurement_report(forged, scenarios=scenarios)

    def test_report_validation_rejects_detector_evidence_mismatch(self):
        scenarios = self.measurement.load_scenarios(SCENARIOS)
        probes = self.measurement.load_probes(PROBES)
        report = self.measurement.run_measurement_benchmark(scenarios, probes)[1]

        forged = copy.deepcopy(report)
        forged["detector_evidence"][0]["matched_declared"] = (
            not forged["detector_evidence"][0]["matched_declared"]
        )
        with self.assertRaisesRegex(
            self.measurement.ContractError, "matched_declared does not match verdicts"
        ):
            self.measurement.validate_measurement_report(forged, scenarios=scenarios)

    def test_detector_flags_canonical_and_clears_evasion_and_benign(self):
        scenarios = self.measurement.load_scenarios(SCENARIOS)
        probes = self.measurement.load_probes(PROBES)
        by_kind = {
            kind: [s for s in scenarios if s["scenario_kind"] == kind]
            for kind in ("canonical_positive", "evasion_positive", "hard_benign", "near_miss")
        }

        for scenario in by_kind["canonical_positive"]:
            verdict = self.detector.score_probe(
                scenario["trap_class"], probes[scenario["id"]]
            )
            self.assertEqual("flagged", verdict, scenario["id"])

        for kind in ("evasion_positive", "hard_benign", "near_miss"):
            for scenario in by_kind[kind]:
                verdict = self.detector.score_probe(
                    scenario["trap_class"], probes[scenario["id"]]
                )
                self.assertEqual("clean", verdict, scenario["id"])

    def test_detector_rejects_unknown_trap_class(self):
        with self.assertRaises(KeyError):
            self.detector.score_probe("Not A Real Trap Class", "irrelevant text")


@unittest.skipUnless(GENERATOR_SCRIPT.exists(), "generator not added yet")
class GeneratorDriftTests(unittest.TestCase):
    def test_committed_fixtures_match_generator_output(self):
        generator = load_module(GENERATOR_SCRIPT, "agt_redteam_measurement_generator")

        scenarios, probes = generator.build_scenarios_and_probes()

        self.assertEqual(scenarios, json.loads(SCENARIOS.read_text(encoding="utf-8")))
        self.assertEqual(probes, json.loads(PROBES.read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
