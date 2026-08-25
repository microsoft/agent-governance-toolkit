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
            items = credential_audit._search("issues", "author:x is:issue", per_page=100)

        assert len(items) == 150
        assert mock_api.call_count == 2

    def test_stops_when_a_short_page_is_returned(self):
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
