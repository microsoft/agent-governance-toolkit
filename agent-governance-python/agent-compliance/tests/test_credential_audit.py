# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the packaged credential_audit CLI module."""

from unittest.mock import patch

from agent_compliance.cli import credential_audit


class TestSearchPagination:
    def test_paginates_across_multiple_pages(self):
        """A full first page must still trigger a request for the next page,
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


class TestFindSprayCitations:
    def test_query_does_not_contain_is_issue(self):
        """find_spray_citations must search without `is:issue` so pull requests are examined."""
        with patch.object(credential_audit, "_search", return_value=[]) as mock_search:
            credential_audit.find_spray_citations("testuser", "target/repo", [])

        mock_search.assert_called_once_with("issues", "author:testuser", per_page=100)

    def test_finds_citations_in_pull_requests(self):
        """Pull requests in external repos citing merges from target_repo must be detected."""
        merges = [
            credential_audit.MergeRecord(
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

        with patch.object(credential_audit, "_search", return_value=[pr_item]):
            citations = credential_audit.find_spray_citations("testuser", "target/repo", merges)

        assert len(citations) == 1
        citation = citations[0]
        assert citation.repo == "external/project"
        assert citation.issue_number == 105
        assert citation.title == "chore: integrate upstream changes"
        assert citation.url == "https://github.com/external/project/pull/105"
        assert citation.days_after_merge == 4
        assert len(citation.citation_snippets) > 0
        assert "#42" in citation.citation_snippets[0]

    def test_finds_citations_in_issues(self):
        """Issues in external repos citing merges from target_repo continue to be detected."""
        merges = [
            credential_audit.MergeRecord(
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

        with patch.object(credential_audit, "_search", return_value=[issue_item]):
            citations = credential_audit.find_spray_citations("testuser", "target/repo", merges)

        assert len(citations) == 1
        assert citations[0].repo == "external/other"
        assert citations[0].issue_number == 77
        assert citations[0].days_after_merge == 2

    def test_skips_items_in_target_repo(self):
        """Items in the target repo itself must be ignored."""
        merges = [
            credential_audit.MergeRecord(
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

        with patch.object(credential_audit, "_search", return_value=[target_pr]):
            citations = credential_audit.find_spray_citations("testuser", "target/repo", merges)

        assert citations == []

