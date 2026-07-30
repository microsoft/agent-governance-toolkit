# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for GET /api/v1/agents placeholder surface (contract section 7.10)."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")


class TestListAgents:
    def test_returns_empty_paginated_payload(self, client):
        resp = client.get("/api/v1/agents")
        assert resp.status_code == 200
        body = resp.json()
        assert body["items"] == []
        assert body["pagination"]["total"] == 0

    def test_pagination_params_accepted(self, client):
        resp = client.get("/api/v1/agents", params={"page": 1, "limit": 50})
        assert resp.status_code == 200
        assert resp.json()["pagination"]["limit"] == 50
