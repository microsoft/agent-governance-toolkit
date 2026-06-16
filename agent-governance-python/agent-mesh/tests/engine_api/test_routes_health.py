# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for GET /api/v1/health (contract section 7.1)."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")


class TestHealth:
    def test_returns_ok(self, client):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert isinstance(body["version"], str) and body["version"]
        assert isinstance(body["uptime_seconds"], int | float)
        assert body["uptime_seconds"] >= 0.0

    def test_uptime_is_non_negative_without_start_time(self, client, app):
        # Defensive path: if start_time is missing, uptime falls back to 0.0.
        del app.state.start_time
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        assert resp.json()["uptime_seconds"] == 0.0
