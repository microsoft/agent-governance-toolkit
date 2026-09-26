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

import cluster_detect
from cluster_detect import (
    Edge,
    AccountInfo,
    ClusterReport,
    format_report,
)


# ---------------------------------------------------------------------------
# _search / _paginate pagination tests
# ---------------------------------------------------------------------------

class TestSearchPagination:
    def test_paginates_across_multiple_pages(self):
        """A short first page must still trigger a request for the next page,
        not be treated as the end of the results."""
        pages = {
            "1": {"items": [{"number": i} for i in range(100)]},
            "2": {"items": [{"number": i} for i in range(100, 150)]},
        }

        def fake_api(path, params=None):
            return pages.get(params["page"])

        with patch.object(cluster_detect, "_api", side_effect=fake_api) as mock_api:
            items = cluster_detect._search("issues", "author:x is:issue", per_page=100)

        assert len(items) == 150
        assert mock_api.call_count == 2

    def test_stops_when_a_short_page_is_returned(self):
        pages = {"1": {"items": [{"number": 1}, {"number": 2}]}}

        def fake_api(path, params=None):
            return pages.get(params["page"])

        with patch.object(cluster_detect, "_api", side_effect=fake_api) as mock_api:
            items = cluster_detect._search("issues", "author:x is:issue", per_page=100)

        assert len(items) == 2
        assert mock_api.call_count == 1

    def test_stops_at_github_search_result_window(self):
        """GitHub's Search API never returns more than 1000 results for a
        query; a subject with more than that must not cause unbounded
        pagination."""
        def fake_api(path, params=None):
            return {"items": [{"number": i} for i in range(int(params["per_page"]))]}

        with patch.object(cluster_detect, "_api", side_effect=fake_api) as mock_api:
            items = cluster_detect._search("issues", "author:x is:issue", per_page=100)

        assert len(items) == 1000
        assert mock_api.call_count == 10

    def test_empty_first_page_returns_no_items(self):
        with patch.object(cluster_detect, "_api", return_value=None) as mock_api:
            items = cluster_detect._search("issues", "author:x is:issue", per_page=100)

        assert items == []
        assert mock_api.call_count == 1


class TestPaginate:
    """`_paginate` backs the regular (non-Search) REST calls in
    detect_shared_forks/detect_co_comments (`/users/{x}/repos`, `/repos/{x}/forks`,
    an issue's comments_url) — these return a bare JSON array, not a `{"items": [...]}`
    envelope, and have no 1000-result Search API cap, only the `_MAX_PAGES` safety cap."""

    def test_paginates_across_multiple_pages(self):
        pages = {
            "1": [{"id": i} for i in range(100)],
            "2": [{"id": i} for i in range(100, 130)],
        }

        def fake_api(path, params=None):
            return pages.get(params["page"])

        with patch.object(cluster_detect, "_api", side_effect=fake_api) as mock_api:
            items = cluster_detect._paginate("/users/x/repos", {"type": "all"}, per_page=100)

        assert len(items) == 130
        assert mock_api.call_count == 2

    def test_stops_when_a_short_page_is_returned(self):
        pages = {"1": [{"id": 1}, {"id": 2}]}

        def fake_api(path, params=None):
            return pages.get(params["page"])

        with patch.object(cluster_detect, "_api", side_effect=fake_api) as mock_api:
            items = cluster_detect._paginate("/repos/x/forks", {}, per_page=30)

        assert len(items) == 2
        assert mock_api.call_count == 1

    def test_stops_at_max_pages_safety_cap(self):
        """No Search-API-style 1000-result cap applies to these endpoints, so an
        account with more pages than `_MAX_PAGES` must still terminate rather than
        loop unboundedly."""
        def fake_api(path, params=None):
            return [{"id": i} for i in range(int(params["per_page"]))]

        with patch.object(cluster_detect, "_api", side_effect=fake_api) as mock_api:
            items = cluster_detect._paginate("/users/x/repos", {}, per_page=100)

        assert len(items) == cluster_detect._MAX_PAGES * 100
        assert mock_api.call_count == cluster_detect._MAX_PAGES

    def test_empty_first_page_returns_no_items(self):
        with patch.object(cluster_detect, "_api", return_value=None) as mock_api:
            items = cluster_detect._paginate("/users/x/repos", {}, per_page=100)

        assert items == []
        assert mock_api.call_count == 1


class TestDetectorCallBounds:
    """detect_co_comments and detect_sync_filing both call _search inside a loop over
    up to 20-30 items. Mocking _search/_paginate directly (as the tests above do) can't
    see how many *underlying* _api calls actually happen when a real account has more
    results than fit on a single page at every one of those call sites - that's
    exactly the shape of regression a call-count-agnostic per-function mock would miss.
    These tests mock _api itself and assert an upper bound on its call count against a
    fake account that always has a full page of results available, at every endpoint,
    forever."""

    def test_detect_co_comments_bounds_api_calls(self):
        def fake_api(path, params=None):
            if path == "/search/issues":
                page = int(params["page"])
                per_page = int(params["per_page"])
                # An account with far more issues than fit on any one page.
                return {
                    "items": [
                        {
                            "url": f"https://api.github.com/repos/x/y/issues/{page}-{i}",
                            "comments_url": f"https://api.github.com/repos/x/y/issues/{page}-{i}/comments",
                        }
                        for i in range(per_page)
                    ]
                }
            if path.endswith("/comments"):
                # A short thread - stops _paginate after one call, isolating this
                # assertion to the _search over-fetch-then-discard bug, not the
                # (separate, expected) per-issue comments pagination.
                return [{"user": {"login": "commenter"}}]
            return None

        with patch.object(cluster_detect, "_api", side_effect=fake_api) as mock_api:
            cluster_detect.detect_co_comments("seed")

        # Before the fix, the seed-issues search alone (per_page=30, no max_results)
        # walked up to 33 pages before the result was sliced down to issues[:20] -
        # 32 of those 33 calls were thrown away. With max_results=20 the search
        # itself must stop within a page or two, so total calls (search + one
        # comments call per issue) stays well under what 33 discarded search pages
        # plus 20 comments calls (53) would require.
        assert mock_api.call_count <= 25

    def test_detect_sync_filing_bounds_api_calls(self):
        def fake_api(path, params=None):
            if path != "/search/issues":
                return None
            q = params["q"]
            per_page = int(params["per_page"])
            if "repo:" in q:
                # A repo with far more matching issues than fit on any one page.
                return {
                    "items": [
                        {
                            "created_at": "2026-01-01T00:00:00Z",
                            "user": {"login": f"other{i}"},
                        }
                        for i in range(per_page)
                    ]
                }
            # The seed's own issues: a full page every time, spread across more
            # repos than detect_sync_filing actually uses (it only looks at the
            # first 10). Before max_results was added to this call site, an
            # account with more issues than fit on one page walked every page
            # in the 1000-result window fetching this.
            return {
                "items": [
                    {
                        "repository_url": f"https://api.github.com/repos/org/repo{i % 15}",
                        "created_at": "2026-01-01T00:00:00Z",
                    }
                    for i in range(per_page)
                ]
            }

        with patch.object(cluster_detect, "_api", side_effect=fake_api) as mock_api:
            cluster_detect.detect_sync_filing("seed")

        # Before either fix, the seed-issues search itself was unbounded (per_page=50,
        # no max_results) and each of up to 30 (repo, issue) pairs below it ran its own
        # unbounded search (per_page=20, no max_results, no time window) against a repo
        # that always has a full page available - thousands of calls combined. With
        # both fixes (max_results=100 on the seed-issues search, time-windowed query +
        # max_results=20 per pair), the seed-issues search takes one call and each pair
        # takes at most one, so the total stays near 1 + 10 repos * 3 issues = 31.
        assert mock_api.call_count <= 35


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
