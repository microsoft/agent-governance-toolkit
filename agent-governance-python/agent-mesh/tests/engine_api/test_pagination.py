# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the section 11 pagination helper, dependency, and bounds enforcement."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from agentmesh.engine_api.pagination import (  # noqa: E402
    DEFAULT_LIMIT,
    DEFAULT_PAGE,
    MAX_LIMIT,
    MIN_LIMIT,
    PaginationParams,
    paginate,
)


def _params(page: int, limit: int) -> PaginationParams:
    obj = PaginationParams.__new__(PaginationParams)
    obj.page = page
    obj.limit = limit
    return obj


class TestPaginateHelper:
    def test_first_page_slice(self):
        items = list(range(50))
        page_items, page = paginate(items, _params(1, 20))
        assert page_items == list(range(20))
        assert page.page == 1
        assert page.limit == 20
        assert page.total == 50
        assert page.has_next is True

    def test_middle_page_slice(self):
        items = list(range(50))
        page_items, page = paginate(items, _params(2, 20))
        assert page_items == list(range(20, 40))
        assert page.has_next is True

    def test_last_page_has_next_false(self):
        items = list(range(50))
        page_items, page = paginate(items, _params(3, 20))
        assert page_items == list(range(40, 50))
        assert page.has_next is False

    def test_page_past_end_is_empty(self):
        items = list(range(10))
        page_items, page = paginate(items, _params(99, 20))
        assert page_items == []
        assert page.total == 10
        assert page.has_next is False

    def test_empty_collection(self):
        page_items, page = paginate([], _params(1, 20))
        assert page_items == []
        assert page.total == 0
        assert page.has_next is False

    def test_exact_multiple_has_next_false_on_last(self):
        items = list(range(40))
        _, page = paginate(items, _params(2, 20))
        assert page.has_next is False


class TestDefaultsAndBounds:
    def test_defaults(self):
        assert DEFAULT_PAGE == 1
        assert DEFAULT_LIMIT == 20
        assert MIN_LIMIT == 1
        assert MAX_LIMIT == 100

    def test_params_constructor_stores_values(self):
        params = PaginationParams(page=3, limit=15)
        assert params.page == 3
        assert params.limit == 15
