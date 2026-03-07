# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for version compatibility checker."""

import pytest

from agent_os.integrations.compat import (
    CompatReport,
    check_compatibility,
    doctor,
    _parse_version,
    _version_in_range,
)


class TestVersionParsing:
    def test_simple_version(self):
        assert _parse_version("1.2.3") == (1, 2, 3)

    def test_two_part_version(self):
        assert _parse_version("2.0") == (2, 0)

    def test_non_numeric(self):
        assert _parse_version("1.0.0rc1") == (1, 0, 0)


class TestVersionInRange:
    def test_in_range(self):
        assert _version_in_range("2.0.2", "2.0.0", "2.99.99") is True

    def test_at_minimum(self):
        assert _version_in_range("2.0.0", "2.0.0", "2.99.99") is True

    def test_at_maximum(self):
        assert _version_in_range("2.99.99", "2.0.0", "2.99.99") is True

    def test_below_range(self):
        assert _version_in_range("1.9.9", "2.0.0", "2.99.99") is False

    def test_above_range(self):
        assert _version_in_range("3.0.0", "2.0.0", "2.99.99") is False


class TestCheckCompatibility:
    def test_compatible_pair(self):
        ok, msg = check_compatibility(
            "agent-os-kernel", "2.0.2", "agentmesh-platform", "2.0.2"
        )
        assert ok is True
        assert "compatible" in msg

    def test_incompatible_pair(self):
        ok, msg = check_compatibility(
            "agent-os-kernel", "3.5.0", "agentmesh-platform", "2.0.0"
        )
        assert ok is False
        assert "WARNING" in msg

    def test_unknown_pair(self):
        ok, msg = check_compatibility(
            "unknown-pkg", "1.0.0", "other-pkg", "1.0.0"
        )
        assert ok is True
        assert "assumed" in msg

    def test_reversed_key_order(self):
        ok, msg = check_compatibility(
            "agentmesh-platform", "2.0.2", "agent-os-kernel", "2.0.2"
        )
        assert ok is True


class TestCompatReport:
    def test_ok_when_no_incompatible(self):
        report = CompatReport(
            installed={"agent-os-kernel": "2.0.2"},
            compatible_pairs=["some pair"],
        )
        assert report.ok is True

    def test_not_ok_when_incompatible(self):
        report = CompatReport(
            incompatible_pairs=["bad pair"],
        )
        assert report.ok is False

    def test_str_contains_status(self):
        report = CompatReport(
            installed={"agent-os-kernel": "2.0.2"},
        )
        text = str(report)
        assert "OK" in text
        assert "agent-os-kernel" in text


class TestDoctor:
    def test_returns_report(self):
        report = doctor()
        assert isinstance(report, CompatReport)
        # Should detect installed or not-installed packages
        total = len(report.installed) + len(report.not_installed)
        assert total > 0
