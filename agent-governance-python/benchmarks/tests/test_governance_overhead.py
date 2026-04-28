# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for benchmarks/governance_overhead.py.

All tests use low iteration counts (n=10) so the suite completes in
under a second.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Make the benchmark module importable
# ---------------------------------------------------------------------------
_BENCH_DIR = Path(__file__).resolve().parent.parent
_ROOT = _BENCH_DIR.parent
sys.path.insert(0, str(_BENCH_DIR))
for _pkg in ("agent-os", "agent-mesh", "agent-hypervisor"):
    sys.path.insert(0, str(_ROOT / "packages" / _pkg / "src"))

from governance_overhead import (
    BenchmarkResult,
    bench_sync,
    bench_async,
    save_json,
    generate_charts,
    run_e2e_comparison,
)

# Shared low iteration count for fast tests
N = 10


# ═══════════════════════════════════════════════════════════════════════════
# 1. bench_sync returns a valid BenchmarkResult
# ═══════════════════════════════════════════════════════════════════════════


class TestBenchSync:
    def test_returns_benchmark_result(self):
        result = bench_sync("test-op", "test", lambda: None, iterations=N)
        assert isinstance(result, BenchmarkResult)

    def test_correct_iteration_count(self):
        result = bench_sync("test-op", "test", lambda: None, iterations=N)
        assert result.iterations == N
        assert len(result.latencies_ms) == N

    def test_percentile_ordering(self):
        result = bench_sync("test-op", "test", lambda: None, iterations=N)
        assert result.p50 > 0
        assert result.p95 > 0
        assert result.p99 > 0
        assert result.p50 <= result.p95
        assert result.p95 <= result.p99

    def test_ops_per_sec_positive(self):
        result = bench_sync("test-op", "test", lambda: None, iterations=N)
        assert result.ops_per_sec > 0

    def test_to_dict_keys(self):
        result = bench_sync("test-op", "test", lambda: None, iterations=N)
        d = result.to_dict()
        expected_keys = {
            "name", "category", "iterations",
            "p50_ms", "p95_ms", "p99_ms", "mean_ms", "ops_per_sec",
        }
        assert set(d.keys()) == expected_keys

    def test_name_and_category_preserved(self):
        result = bench_sync("my-bench", "my-cat", lambda: None, iterations=N)
        assert result.name == "my-bench"
        assert result.category == "my-cat"


# ═══════════════════════════════════════════════════════════════════════════
# 2. Ungoverned baseline < governed full-stack latency
# ═══════════════════════════════════════════════════════════════════════════


class TestGovernedVsUngoverned:
    @pytest.fixture(scope="class")
    def e2e_results(self):
        """Run E2E comparison once for all tests in this class."""
        # Monkey-patch the module-level defaults so run_e2e_comparison
        # uses low iterations.  The function calls bench_sync with the
        # module-level ITERATIONS default, so we patch it.
        import governance_overhead as mod
        orig_iter = mod.ITERATIONS
        orig_warmup = mod.WARMUP
        mod.ITERATIONS = N
        mod.WARMUP = 2
        try:
            results = run_e2e_comparison()
        finally:
            mod.ITERATIONS = orig_iter
            mod.WARMUP = orig_warmup
        return {r.name: r for r in results}

    def test_ungoverned_present(self, e2e_results):
        assert "E2E: Ungoverned action" in e2e_results

    def test_governed_present(self, e2e_results):
        assert "E2E: Governed action (full stack)" in e2e_results

    def test_ungoverned_faster_p50(self, e2e_results):
        ungoverned = e2e_results["E2E: Ungoverned action"]
        governed = e2e_results["E2E: Governed action (full stack)"]
        assert ungoverned.p50 < governed.p50

    def test_ungoverned_faster_p99(self, e2e_results):
        ungoverned = e2e_results["E2E: Ungoverned action"]
        governed = e2e_results["E2E: Governed action (full stack)"]
        assert ungoverned.p99 < governed.p99


# ═══════════════════════════════════════════════════════════════════════════
# 3. save_json produces valid JSON with expected structure
# ═══════════════════════════════════════════════════════════════════════════


class TestSaveJson:
    def test_creates_json_file(self, tmp_path):
        results = [
            bench_sync("E2E: Ungoverned action", "e2e", lambda: None, iterations=N),
            bench_sync("E2E: Governed action (full stack)", "e2e", lambda: None, iterations=N),
        ]
        out = tmp_path / "results" / "test.json"
        save_json(results, out)
        assert out.exists()

    def test_valid_json(self, tmp_path):
        results = [
            bench_sync("E2E: Ungoverned action", "e2e", lambda: None, iterations=N),
            bench_sync("E2E: Governed action (full stack)", "e2e", lambda: None, iterations=N),
        ]
        out = tmp_path / "test.json"
        save_json(results, out)
        data = json.loads(out.read_text(encoding="utf-8"))
        assert isinstance(data, dict)

    def test_top_level_keys(self, tmp_path):
        results = [
            bench_sync("E2E: Ungoverned action", "e2e", lambda: None, iterations=N),
            bench_sync("E2E: Governed action (full stack)", "e2e", lambda: None, iterations=N),
        ]
        out = tmp_path / "test.json"
        save_json(results, out)
        data = json.loads(out.read_text(encoding="utf-8"))
        for key in ("benchmark", "timestamp", "python", "platform", "results"):
            assert key in data, f"Missing top-level key: {key}"

    def test_results_array_length(self, tmp_path):
        results = [
            bench_sync("a", "cat", lambda: None, iterations=N),
            bench_sync("b", "cat", lambda: None, iterations=N),
            bench_sync("c", "cat", lambda: None, iterations=N),
        ]
        out = tmp_path / "test.json"
        save_json(results, out)
        data = json.loads(out.read_text(encoding="utf-8"))
        assert len(data["results"]) == 3

    def test_overhead_summary_present(self, tmp_path):
        results = [
            bench_sync("E2E: Ungoverned action", "e2e", lambda: None, iterations=N),
            bench_sync("E2E: Governed action (full stack)", "e2e", lambda: None, iterations=N),
        ]
        out = tmp_path / "test.json"
        save_json(results, out)
        data = json.loads(out.read_text(encoding="utf-8"))
        assert "overhead_summary" in data
        summary = data["overhead_summary"]
        for key in ("ungoverned_p50_ms", "governed_p50_ms", "overhead_p50_ms", "multiplier_p50"):
            assert key in summary, f"Missing overhead_summary key: {key}"


# ═══════════════════════════════════════════════════════════════════════════
# 4. generate_charts creates both PNG files
# ═══════════════════════════════════════════════════════════════════════════


class TestGenerateCharts:
    @pytest.fixture()
    def sample_results(self):
        """Minimal set of results that covers all names the chart code looks for."""
        names = [
            ("Bare action (no governance)", "baseline"),
            ("Policy eval (10 rules)", "policy"),
            ("Trust policy eval (10 rules)", "trust"),
            ("Ring enforcement check", "rings"),
            ("Ring computation", "rings"),
            ("Audit log write (Merkle)", "audit"),
            ("Credential issuance", "credential"),
            ("Delta capture", "delta_audit"),
            ("Session lifecycle", "hypervisor"),
            ("E2E: Ungoverned action", "e2e"),
            ("E2E: Governed (policy only)", "e2e"),
            ("E2E: Governed action (full stack)", "e2e"),
        ]
        return [
            bench_sync(name, cat, lambda: None, iterations=N)
            for name, cat in names
        ]

    def test_creates_latency_chart(self, tmp_path, sample_results):
        generate_charts(sample_results, tmp_path)
        assert (tmp_path / "latency_comparison.png").exists()

    def test_creates_breakdown_chart(self, tmp_path, sample_results):
        generate_charts(sample_results, tmp_path)
        assert (tmp_path / "overhead_breakdown.png").exists()

    def test_png_files_non_empty(self, tmp_path, sample_results):
        generate_charts(sample_results, tmp_path)
        for name in ("latency_comparison.png", "overhead_breakdown.png"):
            path = tmp_path / name
            assert path.stat().st_size > 1000, f"{name} is suspiciously small"

    def test_creates_charts_dir_if_missing(self, tmp_path, sample_results):
        nested = tmp_path / "a" / "b" / "charts"
        generate_charts(sample_results, nested)
        assert (nested / "latency_comparison.png").exists()
        assert (nested / "overhead_breakdown.png").exists()
