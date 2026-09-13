# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Pagination dependency, response model, and helper for the Engine API.

Implements ``docs/studio/engine-api-contract.md`` section 11 (Pagination Model). The five
paginated list endpoints (``/policies``, ``/audit/log``, ``/trust/scores``, ``/agents``,
``/decisions``) declare :class:`PaginationParams` as a FastAPI dependency and wrap their
results with :func:`paginate`, producing the section 11.2 ``items`` + ``pagination`` shape.

Out-of-range query values (``page < 1``, ``limit < 1`` or ``limit > 100``) are rejected by
FastAPI's query validation, which the adapter's error layer remaps to a ``VALIDATION_ERROR``
envelope.
"""

from __future__ import annotations

from typing import TypeVar

from fastapi import Query
from pydantic import BaseModel, Field

T = TypeVar("T")

#: Section 11.1 defaults and bounds.
DEFAULT_PAGE = 1
DEFAULT_LIMIT = 20
MIN_LIMIT = 1
MAX_LIMIT = 100


class PaginationParams:
    """FastAPI dependency parsing the section 11.1 ``page`` and ``limit`` query params.

    Args:
        page: 1-based page number (default 1, minimum 1).
        limit: Items per page (default 20, minimum 1, maximum 100).
    """

    def __init__(
        self,
        page: int = Query(DEFAULT_PAGE, ge=1, description="1-based page number"),
        limit: int = Query(
            DEFAULT_LIMIT, ge=MIN_LIMIT, le=MAX_LIMIT, description="Items per page (1-100)"
        ),
    ) -> None:
        self.page = page
        self.limit = limit


class Pagination(BaseModel):
    """The section 11.2 ``pagination`` object included in every paginated response."""

    page: int = Field(..., description="Current page number (1-based)")
    limit: int = Field(..., description="Items per page")
    total: int = Field(..., description="Total number of items across all pages")
    has_next: bool = Field(..., description="Whether more pages exist after this one")


def paginate(items: list[T], params: PaginationParams) -> tuple[list[T], Pagination]:
    """Slice ``items`` for the requested page and build the matching :class:`Pagination`.

    Args:
        items: The full, already-ordered collection to page over.
        params: Parsed :class:`PaginationParams`.

    Returns:
        A ``(page_items, pagination)`` tuple. ``page_items`` is the slice for the requested
        page (empty if the page is past the end); ``pagination`` carries the section 11.2
        counters.
    """
    total = len(items)
    start = (params.page - 1) * params.limit
    end = start + params.limit
    page_items = items[start:end]
    return page_items, Pagination(
        page=params.page,
        limit=params.limit,
        total=total,
        has_next=end < total,
    )
