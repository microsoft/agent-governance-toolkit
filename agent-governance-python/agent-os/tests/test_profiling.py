# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for governance profiling decorator and context manager."""

import time

import pytest

from agent_os.integrations.profiling import (
    MethodStats,
    ProfileGovernanceContext,
    ProfilingReport,
    get_report,
    profile_governance,
    reset_report,
)


class TestMethodStats:
    def test_avg_time_zero_calls(self):
        s = MethodStats(name="test")
        assert s.avg_time_ms == 0.0

    def test_avg_time(self):
        s = MethodStats(name="test", call_count=4, total_time_ms=100.0)
        assert s.avg_time_ms == 25.0


class TestProfilingReport:
    def test_empty_report(self):
        r = ProfilingReport()
        assert r.total_calls == 0
        assert r.total_time_ms == 0.0
        assert "No profiling data" in r.format_report()

    def test_format_report(self):
        r = ProfilingReport(methods={
            "a": MethodStats(name="a", call_count=2, total_time_ms=10.0, min_time_ms=4.0, max_time_ms=6.0),
        })
        text = r.format_report()
        assert "a" in text
        assert "TOTAL" in text
        assert "2" in text


class TestProfileGovernanceDecorator:
    def setup_method(self):
        reset_report()

    def test_basic_timing(self):
        @profile_governance
        def slow():
            time.sleep(0.05)

        slow()
        report = get_report()
        stats = report.methods["slow"]
        assert stats.call_count == 1
        assert stats.total_time_ms >= 40  # at least 40ms

    def test_multiple_calls(self):
        @profile_governance
        def fast():
            pass

        for _ in range(5):
            fast()
        stats = get_report().methods["fast"]
        assert stats.call_count == 5

    def test_return_value_preserved(self):
        @profile_governance
        def add(a, b):
            return a + b

        assert add(2, 3) == 5

    def test_exception_still_recorded(self):
        @profile_governance
        def fails():
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError, match="boom"):
            fails()
        assert get_report().methods["fails"].call_count == 1

    def test_min_max_tracking(self):
        @profile_governance
        def varied(t):
            time.sleep(t)

        varied(0.01)
        varied(0.05)
        stats = get_report().methods["varied"]
        assert stats.min_time_ms < stats.max_time_ms

    def test_decorator_with_track_memory(self):
        @profile_governance(track_memory=True)
        def allocate():
            return [0] * 10000

        allocate()
        stats = get_report().methods["allocate"]
        assert stats.call_count == 1
        assert stats.total_memory_delta >= 0


class TestProfileGovernanceContext:
    def setup_method(self):
        reset_report()

    def test_scoped_report(self):
        @profile_governance
        def work():
            time.sleep(0.01)

        with ProfileGovernanceContext() as report:
            work()

        assert report.total_calls == 1
        # Global report should be restored
        assert get_report().total_calls == 0

    def test_format_in_context(self):
        @profile_governance
        def task():
            pass

        with ProfileGovernanceContext() as report:
            task()
            task()

        assert report.total_calls == 2
        assert "TOTAL" in report.format_report()
