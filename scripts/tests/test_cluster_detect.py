#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for cluster_detect.py."""

from __future__ import annotations

import json
import sys
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cluster_detect import (
    Edge,
    AccountInfo,
    ClusterReport,
    format_report,
)


# ---------------------------------------------------------------------------
# ClusterReport tests
# ---------------------------------------------------------------------------

class TestClusterReport:
    def test_empty_cluster_is_none(self):
        report = ClusterReport(seed="test", depth=1)
        assert report.risk_level() == "NONE"

    def test_two_accounts_is_low(self):
        report = ClusterReport(seed="a", depth=1)
        report.accounts = {
            "a": AccountInfo("a"),
            "b": AccountInfo("b"),
        }
        report.edges = [Edge("a", "b", "shared_fork", "detail")]
        assert report.risk_level() == "LOW"

    def test_three_accounts_four_edges_is_medium(self):
        report = ClusterReport(seed="a", depth=1)
        report.accounts = {
            "a": AccountInfo("a"),
            "b": AccountInfo("b"),
            "c": AccountInfo("c"),
        }
        report.edges = [
            Edge("a", "b", "shared_fork", "d1"),
            Edge("a", "c", "co_comment", "d2"),
            Edge("b", "c", "sync_filing", "d3"),
            Edge("a", "b", "co_comment", "d4"),
        ]
        assert report.risk_level() == "MEDIUM"

    def test_five_accounts_eight_edges_is_high(self):
        report = ClusterReport(seed="a", depth=1)
        report.accounts = {c: AccountInfo(c) for c in "abcde"}
        report.edges = [Edge("a", chr(ord("b") + i), "shared_fork", f"d{i}") for i in range(8)]
        assert report.risk_level() == "HIGH"

    def test_account_count(self):
        report = ClusterReport(seed="x", depth=1)
        report.accounts = {"x": AccountInfo("x"), "y": AccountInfo("y")}
        assert report.account_count == 2

    def test_edge_count(self):
        report = ClusterReport(seed="x", depth=1)
        report.edges = [Edge("x", "y", "t", "d"), Edge("x", "z", "t", "d")]
        assert report.edge_count == 2


# ---------------------------------------------------------------------------
# Edge tests
# ---------------------------------------------------------------------------

class TestEdge:
    def test_edge_creation(self):
        edge = Edge("alice", "bob", "shared_fork", "Both forked repo/x")
        assert edge.source == "alice"
        assert edge.target == "bob"
        assert edge.weight == 1.0

    def test_edge_weight(self):
        edge = Edge("a", "b", "co_comment", "detail", weight=3.0)
        assert edge.weight == 3.0


# ---------------------------------------------------------------------------
# Format tests
# ---------------------------------------------------------------------------

class TestFormat:
    def test_text_output(self):
        report = ClusterReport(seed="test-seed", depth=1)
        report.accounts = {
            "test-seed": AccountInfo("test-seed", "2025-01-01T00:00:00Z", 10, 50, 20),
            "connected": AccountInfo("connected", "2026-03-01T00:00:00Z", 40, 2, 0),
        }
        report.edges = [
            Edge("test-seed", "connected", "shared_fork", "Both forked repo/x"),
        ]
        output = format_report(report)
        assert "test-seed" in output
        assert "connected" in output
        assert "shared_fork" in output

    def test_json_output_valid(self):
        report = ClusterReport(seed="json-seed", depth=2)
        report.accounts = {
            "json-seed": AccountInfo("json-seed", "2024-01-01T00:00:00Z", 5, 10, 5),
        }
        report.edges = [
            Edge("json-seed", "other", "co_comment", "2 shared threads", 2.0),
        ]
        report.shared_forks = {"repo/x": ["other", "another"]}

        output = format_report(report, as_json=True)
        data = json.loads(output)
        assert data["seed"] == "json-seed"
        assert data["depth"] == 2
        assert data["account_count"] == 1
        assert data["edge_count"] == 1
        assert len(data["edges"]) == 1
        assert data["edges"][0]["weight"] == 2.0
        assert "repo/x" in data["shared_forks"]

    def test_empty_report(self):
        report = ClusterReport(seed="lonely", depth=1)
        output = format_report(report)
        assert "lonely" in output
        assert "NONE" in output

    def test_shared_forks_displayed(self):
        report = ClusterReport(seed="s", depth=1)
        report.shared_forks = {"owner/obscure-repo": ["user1", "user2"]}
        output = format_report(report)
        assert "obscure-repo" in output
        assert "user1" in output
