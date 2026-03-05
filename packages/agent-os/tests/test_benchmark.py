# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the prompt injection benchmark."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure benchmark module is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from benchmarks.injection_benchmark import (
    CANARY_TOKENS,
    Metrics,
    TestCase,
    build_dataset,
    evaluate,
    evaluate_by_category,
    generate_markdown_report,
    run_benchmark,
)
from agent_os.prompt_injection import DetectionConfig, PromptInjectionDetector


class TestDataset:
    """Verify the curated dataset is well-formed."""

    def test_dataset_has_100_cases(self):
        ds = build_dataset()
        assert len(ds) == 100

    def test_category_counts(self):
        ds = build_dataset()
        counts = {}
        for tc in ds:
            counts[tc.category] = counts.get(tc.category, 0) + 1
        assert counts["direct_injection"] == 20
        assert counts["indirect_injection"] == 20
        assert counts["jailbreak"] == 20
        assert counts["benign"] == 40

    def test_malicious_labels(self):
        ds = build_dataset()
        for tc in ds:
            if tc.category == "benign":
                assert not tc.is_malicious, f"Benign case labeled malicious: {tc.description}"
            else:
                assert tc.is_malicious, f"Malicious case labeled benign: {tc.description}"

    def test_all_cases_have_text_and_description(self):
        ds = build_dataset()
        for tc in ds:
            assert tc.text.strip(), f"Empty text in: {tc.description}"
            assert tc.description.strip(), "Empty description found"


class TestMetrics:
    """Verify metrics calculations including edge cases."""

    def test_perfect_detection(self):
        m = Metrics(true_positives=60, false_positives=0,
                    true_negatives=40, false_negatives=0)
        assert m.tpr == 1.0
        assert m.fpr == 0.0
        assert m.precision == 1.0
        assert m.recall == 1.0
        assert m.f1 == 1.0

    def test_no_detections(self):
        m = Metrics(true_positives=0, false_positives=0,
                    true_negatives=40, false_negatives=60)
        assert m.tpr == 0.0
        assert m.fpr == 0.0
        assert m.precision == 0.0
        assert m.f1 == 0.0

    def test_all_flagged(self):
        m = Metrics(true_positives=60, false_positives=40,
                    true_negatives=0, false_negatives=0)
        assert m.tpr == 1.0
        assert m.fpr == 1.0
        assert m.precision == 0.6
        assert abs(m.f1 - 0.75) < 1e-9

    def test_divide_by_zero_empty(self):
        m = Metrics(true_positives=0, false_positives=0,
                    true_negatives=0, false_negatives=0)
        assert m.tpr == 0.0
        assert m.fpr == 0.0
        assert m.precision == 0.0
        assert m.recall == 0.0
        assert m.f1 == 0.0


class TestBenchmarkExecution:
    """Verify the full benchmark runs without errors."""

    def test_run_benchmark_completes(self):
        overall, by_category = run_benchmark()
        assert set(overall.keys()) == {"strict", "balanced", "permissive"}
        for level in overall:
            m = overall[level]
            assert 0.0 <= m["tpr"] <= 1.0
            assert 0.0 <= m["fpr"] <= 1.0
            assert 0.0 <= m["precision"] <= 1.0
            assert 0.0 <= m["f1"] <= 1.0

    def test_category_metrics_present(self):
        _, by_category = run_benchmark()
        expected_cats = {"direct_injection", "indirect_injection", "jailbreak", "benign"}
        for level in ("strict", "balanced", "permissive"):
            assert set(by_category[level].keys()) == expected_cats

    def test_markdown_report_generated(self):
        overall, by_category = run_benchmark()
        report = generate_markdown_report(overall, by_category)
        assert "# Prompt Injection Detection" in report
        assert "LlamaFirewall" in report
        assert "Agent OS" in report
        assert "Category Breakdown" in report
        assert "Key Findings" in report
