# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for GET /api/v1/audit/log placeholder surface (contract section 7.7)."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")


class TestAuditLog:
    def test_returns_empty_paginated_payload(self, client):
        resp = client.get("/api/v1/audit/log")
        assert resp.status_code == 200
        body = resp.json()
        assert body["items"] == []
        assert body["pagination"]["total"] == 0
        assert body["pagination"]["has_next"] is False

    def test_accepts_filter_query_params(self, client):
        resp = client.get(
            "/api/v1/audit/log",
            params={"agent_did": "did:agt:abc", "from": "2024-01-01T00:00:00Z", "to": "2024-02-01T00:00:00Z"},
        )
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    def test_from_alias_is_accepted(self, client):
        # The query param is spelled "from" on the wire (Python keyword aliased internally).
        resp = client.get("/api/v1/audit/log", params={"from": "2024-01-01T00:00:00Z"})
        assert resp.status_code == 200

    def test_invalid_date_is_validation_error(self, client):
        resp = client.get("/api/v1/audit/log", params={"from": "not-a-date"})
        assert resp.status_code == 422
        assert resp.json()["code"] == "VALIDATION_ERROR"
