# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for GET /api/v1/decisions placeholder surface (contract section 7.11)."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")


class TestListDecisions:
    def test_returns_empty_paginated_payload(self, client):
        resp = client.get("/api/v1/decisions")
        assert resp.status_code == 200
        body = resp.json()
        assert body["items"] == []
        assert body["pagination"]["total"] == 0

    def test_accepts_agent_did_and_verdict_filters(self, client):
        resp = client.get(
            "/api/v1/decisions", params={"agent_did": "did:agt:x", "verdict": "deny"}
        )
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    def test_invalid_verdict_is_validation_error(self, client):
        resp = client.get("/api/v1/decisions", params={"verdict": "not-a-verdict"})
        assert resp.status_code == 422
        assert resp.json()["code"] == "VALIDATION_ERROR"
