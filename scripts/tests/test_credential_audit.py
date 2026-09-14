#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for credential_audit.py."""

from __future__ import annotations

import json
import sys
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import credential_audit
from credential_audit import (
    MergeRecord,
    SprayCitation,
    CredentialAuditReport,
    format_report,
)


# ---------------------------------------------------------------------------
# _search pagination tests
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

        with patch.object(credential_audit, "_api", side_effect=fake_api) as mock_api:
            items = credential_audit._search("issues", "author:x is:issue", per_page=100)

        assert len(items) == 150
        assert mock_api.call_count == 2

    def test_stops_when_a_short_page_is_returned(self):
        """A page with fewer than per_page items is the last page; no further
        request should be made."""
        pages = {"1": {"items": [{"number": 1}, {"number": 2}]}}

        def fake_api(path, params=None):
            return pages.get(params["page"])

        with patch.object(credential_audit, "_api", side_effect=fake_api) as mock_api:
            items = credential_audit._search("issues", "author:x is:issue", per_page=100)

        assert len(items) == 2
        assert mock_api.call_count == 1

    def test_stops_at_github_search_result_window(self):
        """GitHub's Search API never returns more than 1000 results for a
        query; a subject with more than that must not cause unbounded
        pagination."""
        def fake_api(path, params=None):
            return {"items": [{"number": i} for i in range(int(params["per_page"]))]}

        with patch.object(credential_audit, "_api", side_effect=fake_api) as mock_api:
            items = credential_audit._search("issues", "author:x is:issue", per_page=100)

        assert len(items) == 1000
        assert mock_api.call_count == 10

    def test_empty_first_page_returns_no_items(self):
        with patch.object(credential_audit, "_api", return_value=None) as mock_api:
            items = credential_audit._search("issues", "author:x is:issue", per_page=100)

        assert items == []
        assert mock_api.call_count == 1


# ---------------------------------------------------------------------------
# CredentialAuditReport tests
# ---------------------------------------------------------------------------

class TestCredentialAuditReport:
    def test_no_citations_is_none(self):
        report = CredentialAuditReport(username="clean", target_repo="org/repo")
        assert report.compute_risk() == "NONE"

    def test_one_citation_is_low(self):
        report = CredentialAuditReport(username="user", target_repo="org/repo")
        report.citations = [
            SprayCitation("other/repo", 1, "title", "2026-04-07", "url"),
        ]
        report.spray_repos = {"other/repo"}
        assert report.compute_risk() == "LOW"

    def test_two_repos_is_medium(self):
        report = CredentialAuditReport(username="user", target_repo="org/repo")
        report.citations = [
            SprayCitation("repo/a", 1, "t1", "2026-04-07", "url1"),
            SprayCitation("repo/b", 2, "t2", "2026-04-07", "url2"),
        ]
        report.spray_repos = {"repo/a", "repo/b"}
        assert report.compute_risk() == "MEDIUM"

    def test_three_repos_is_high(self):
        report = CredentialAuditReport(username="user", target_repo="org/repo")
        report.citations = [
            SprayCitation("repo/a", 1, "t1", "2026-04-07", "url1"),
            SprayCitation("repo/b", 2, "t2", "2026-04-07", "url2"),
            SprayCitation("repo/c", 3, "t3", "2026-04-07", "url3"),
        ]
        report.spray_repos = {"repo/a", "repo/b", "repo/c"}
        assert report.compute_risk() == "HIGH"


# ---------------------------------------------------------------------------
# Format tests
# ---------------------------------------------------------------------------

class TestFormatReport:
    def test_text_output_contains_username(self):
        report = CredentialAuditReport(
            username="test-user", target_repo="org/repo", risk="LOW",
        )
        output = format_report(report)
        assert "test-user" in output
        assert "org/repo" in output

    def test_text_shows_merges(self):
        report = CredentialAuditReport(
            username="user", target_repo="org/repo", risk="MEDIUM",
        )
        report.merges = [
            MergeRecord(598, "feat: adapter", "2026-04-06T01:17:17Z", 1051, "url"),
        ]
        output = format_report(report)
        assert "#598" in output
        assert "adapter" in output

    def test_text_shows_citations(self):
        report = CredentialAuditReport(
            username="user", target_repo="org/repo", risk="HIGH",
        )
        report.citations = [
            SprayCitation(
                "contoso/example-project", 12544,
                "Per-flow governance", "2026-04-07T15:53:22Z",
                "https://example.com",
                citation_snippets=["PR #598 merged"],
                days_after_merge=1,
            ),
        ]
        report.spray_repos = {"contoso/example-project"}
        output = format_report(report)
        assert "contoso" in output
        assert "12544" in output

    def test_json_output_valid(self):
        report = CredentialAuditReport(
            username="json-user", target_repo="org/repo", risk="HIGH",
        )
        report.merges = [
            MergeRecord(100, "title", "2026-04-01T00:00:00Z", 50, "url"),
        ]
        report.citations = [
            SprayCitation("other/repo", 1, "t", "2026-04-02T00:00:00Z", "u",
                          ["snippet"], 1),
        ]
        report.spray_repos = {"other/repo"}
        report.spray_window_hours = 0.0
        output = format_report(report, as_json=True)
        data = json.loads(output)
        assert data["username"] == "json-user"
        assert data["risk"] == "HIGH"
        assert len(data["merges"]) == 1
        assert len(data["citations"]) == 1
        assert data["spray_repos_count"] == 1

    def test_no_citations_message(self):
        report = CredentialAuditReport(
            username="clean", target_repo="org/repo", risk="NONE",
        )
        output = format_report(report)
        assert "No credential citations" in output
