# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the trust routes (contract sections 7.8, 7.9)."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")


class TestTrustScores:
    def test_returns_empty_paginated_payload(self, client):
        resp = client.get("/api/v1/trust/scores")
        assert resp.status_code == 200
        body = resp.json()
        assert body["items"] == []
        assert body["pagination"]["total"] == 0

    def test_accepts_agent_did_filter(self, client):
        resp = client.get("/api/v1/trust/scores", params={"agent_did": "did:agt:x"})
        assert resp.status_code == 200


class TestTrustGraph:
    def test_returns_empty_graph_not_paginated(self, client):
        resp = client.get("/api/v1/trust/graph")
        assert resp.status_code == 200
        body = resp.json()
        assert body == {"nodes": [], "edges": []}
        # The graph is a single object, never wrapped in a pagination envelope.
        assert "pagination" not in body
