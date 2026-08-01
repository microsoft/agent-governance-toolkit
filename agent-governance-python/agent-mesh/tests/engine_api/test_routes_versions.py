# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for GET /api/v1/versions (contract section 7.12)."""

from __future__ import annotations

import platform

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from agentmesh.engine_api.routes.versions import (  # noqa: E402
    API_VERSION,
    ENGINE_CAPABILITIES,
    engine_version,
)


class TestVersions:
    def test_payload_shape(self, client):
        resp = client.get("/api/v1/versions")
        assert resp.status_code == 200
        body = resp.json()
        assert body["api"] == API_VERSION == "1.0.0"
        assert isinstance(body["engine"], str) and body["engine"]
        assert body["python"] == platform.python_version()
        assert body["capabilities"] == list(ENGINE_CAPABILITIES)

    def test_engine_version_is_a_string(self):
        assert isinstance(engine_version(), str)
        assert engine_version()

    def test_engine_version_falls_back_when_metadata_missing(self, monkeypatch):
        import importlib.metadata as md

        def _raise(_name):
            raise md.PackageNotFoundError("agentmesh_platform")

        monkeypatch.setattr(md, "version", _raise)
        # Falls back to agentmesh.__version__ (or "0.0.0"); must still be a non-empty string.
        assert isinstance(engine_version(), str)
        assert engine_version()
