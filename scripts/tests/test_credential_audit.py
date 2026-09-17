#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for credential_audit.py."""

from __future__ import annotations

import json
import sys
import os
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import credential_audit
from credential_audit import (
    MergeRecord,
    SprayCitation,
    CredentialAuditReport,
    format_report,
    find_spray_citations,
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
            items = credential_audit._search("issues", "author:x", per_page=100)

        assert len(items) == 150
        assert mock_api.call_count == 2

    def test_stops_when_a_short_page_is_returned(self):
        """A page with fewer than per_page items is the last page; no further
        request should be made."""
        pages = {"1": {"items": [{"number": 1}, {"number": 2}]}}

        def fake_api(path, params=None):
            return pages.get(params["page"])

        with patch.object(credential_audit, "_api", side_effect=fake_api) as mock_api:
            items = credential_audit._search("issues", "author:x", per_page=100)

        assert len(items) == 2
        assert mock_api.call_count == 1

    def test_stops_at_github_search_result_window(self):
        """GitHub's Search API never returns more than 1000 results for a
        query; a subject with more than that must not cause unbounded
        pagination."""
        def fake_api(path, params=None):
            return {"items": [{"number": i} for i in range(int(params["per_page"]))]}

        with patch.object(credential_audit, "_api", side_effect=fake_api) as mock_api:
            items = credential_audit._search("issues", "author:x", per_page=100)

        assert len(items) == 1000
        assert mock_api.call_count == 10

    def test_empty_first_page_returns_no_items(self):
        with patch.object(credential_audit, "_api", return_value=None) as mock_api:
            items = credential_audit._search("issues", "author:x", per_page=100)

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
# find_spray_citations tests
# ---------------------------------------------------------------------------

class TestFindSprayCitations:
    def test_queries_both_issues_and_pull_requests(self):
        """find_spray_citations must query both `is:issue` and `is:pr` so each has its own 1000-result window."""
        with patch.object(credential_audit, "_search", return_value=[]) as mock_search:
            find_spray_citations("test-user", "target/repo", [])

        assert mock_search.call_count == 2
        mock_search.assert_any_call("issues", "author:test-user is:issue", per_page=100)
        mock_search.assert_any_call("issues", "author:test-user is:pr", per_page=100)

    def test_deduplicates_citations_across_queries(self):
        """Items appearing in both issue and PR searches must be deduplicated by html_url."""
        merges = [
            MergeRecord(
                pr_number=42,
                title="feat: add core feature",
                merged_at="2026-04-01T00:00:00Z",
                additions=100,
                url="https://github.com/target/repo/pull/42",
            )
        ]
        shared_item = {
            "number": 105,
            "title": "chore: integrate upstream changes",
            "html_url": "https://github.com/external/project/pull/105",
            "repository_url": "https://api.github.com/repos/external/project",
            "pull_request": {"url": "https://api.github.com/repos/external/project/pulls/105"},
            "body": "As implemented in target/repo PR #42 merged previously.",
            "created_at": "2026-04-05T00:00:00Z",
        }

        with patch.object(credential_audit, "_search", side_effect=[[shared_item], [shared_item]]):
            citations = find_spray_citations("test-user", "target/repo", merges)

        assert len(citations) == 1

    def test_finds_citations_in_pull_requests(self):
        """Pull requests in external repos citing merges from target_repo must be detected."""
        merges = [
            MergeRecord(
                pr_number=42,
                title="feat: add core feature",
                merged_at="2026-04-01T00:00:00Z",
                additions=100,
                url="https://github.com/target/repo/pull/42",
            )
        ]
        pr_item = {
            "number": 105,
            "title": "chore: integrate upstream changes",
            "html_url": "https://github.com/external/project/pull/105",
            "repository_url": "https://api.github.com/repos/external/project",
            "pull_request": {"url": "https://api.github.com/repos/external/project/pulls/105"},
            "body": "As implemented in target/repo PR #42 merged previously.",
            "created_at": "2026-04-05T00:00:00Z",
        }

        with patch.object(credential_audit, "_search", side_effect=[[], [pr_item]]):
            citations = find_spray_citations("test-user", "target/repo", merges)

        assert len(citations) == 1
        citation = citations[0]
        assert citation.repo == "external/project"
        assert citation.issue_number == 105
        assert citation.title == "chore: integrate upstream changes"
        assert citation.url == "https://github.com/external/project/pull/105"
        assert citation.days_after_merge == 4
        assert citation.kind == "pull_request"
        assert len(citation.citation_snippets) > 0
        assert "#42" in citation.citation_snippets[0]

    def test_finds_citations_in_issues(self):
        """Issues in external repos citing merges from target_repo continue to be detected."""
        merges = [
            MergeRecord(
                pr_number=42,
                title="feat: add core feature",
                merged_at="2026-04-01T00:00:00Z",
                additions=100,
                url="https://github.com/target/repo/pull/42",
            )
        ]
        issue_item = {
            "number": 77,
            "title": "bug: downstream alignment",
            "html_url": "https://github.com/external/other/issues/77",
            "repository_url": "https://api.github.com/repos/external/other",
            "body": "See target/repo #42",
            "created_at": "2026-04-03T00:00:00Z",
        }

        with patch.object(credential_audit, "_search", side_effect=[[issue_item], []]):
            citations = find_spray_citations("test-user", "target/repo", merges)

        assert len(citations) == 1
        assert citations[0].repo == "external/other"
        assert citations[0].issue_number == 77
        assert citations[0].days_after_merge == 2
        assert citations[0].kind == "issue"

    def test_skips_items_in_target_repo(self):
        """Items in the target repo itself must be ignored."""
        merges = [
            MergeRecord(
                pr_number=42,
                title="feat: add core feature",
                merged_at="2026-04-01T00:00:00Z",
                additions=100,
                url="https://github.com/target/repo/pull/42",
            )
        ]
        target_pr = {
            "number": 43,
            "title": "follow-up",
            "html_url": "https://github.com/target/repo/pull/43",
            "repository_url": "https://api.github.com/repos/target/repo",
            "body": "Follows up on PR #42",
            "created_at": "2026-04-02T00:00:00Z",
        }

        with patch.object(credential_audit, "_search", side_effect=[[], [target_pr]]):
            citations = find_spray_citations("test-user", "target/repo", merges)

        assert citations == []


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
                kind="pull_request",
            ),
        ]
        report.spray_repos = {"contoso/example-project"}
        output = format_report(report)
        assert "contoso" in output
        assert "12544" in output
        assert "[pull_request]" in output

    def test_json_output_valid(self):
        report = CredentialAuditReport(
            username="json-user", target_repo="org/repo", risk="HIGH",
        )
        report.merges = [
            MergeRecord(100, "title", "2026-04-01T00:00:00Z", 50, "url"),
        ]
        report.citations = [
            SprayCitation("other/repo", 1, "t", "2026-04-02T00:00:00Z", "u",
                          ["snippet"], 1, kind="issue"),
        ]
        report.spray_repos = {"other/repo"}
        report.spray_window_hours = 0.0
        output = format_report(report, as_json=True)
        data = json.loads(output)
        assert data["username"] == "json-user"
        assert data["risk"] == "HIGH"
        assert len(data["merges"]) == 1
        assert len(data["citations"]) == 1
        assert data["citations"][0]["kind"] == "issue"
        assert data["spray_repos_count"] == 1

    def test_no_citations_message(self):
        report = CredentialAuditReport(
            username="clean", target_repo="org/repo", risk="NONE",
        )
        output = format_report(report)
        assert "No credential citations found in external issues or pull requests." in output
