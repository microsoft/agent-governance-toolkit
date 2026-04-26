# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for MetricsServer and HTTP endpoints (server.py)."""

import sys
import os
import json
import random
import time
import urllib.request
import urllib.error
from uuid import uuid4

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent_os_observability.metrics import KernelMetrics
from agent_os_observability.server import MetricsServer, create_fastapi_router


def _unique_ns():
    return f"test_{uuid4().hex[:8]}"


def _random_port():
    return random.randint(19000, 29000)


def _get(url, timeout=5):
    """Helper to perform GET request."""
    req = urllib.request.Request(url)
    return urllib.request.urlopen(req, timeout=timeout)


class TestMetricsServerInit:
    def test_initializes_with_given_port(self):
        port = _random_port()
        metrics = KernelMetrics(namespace=_unique_ns())
        server = MetricsServer(port=port, metrics=metrics)
        assert server.port == port

    def test_creates_default_metrics_if_none(self):
        ns = _unique_ns()
        server = MetricsServer(port=_random_port(), metrics=KernelMetrics(namespace=ns))
        assert server.metrics is not None


class TestMetricsServerStartStop:
    def test_start_background_starts_thread(self):
        port = _random_port()
        metrics = KernelMetrics(namespace=_unique_ns())
        server = MetricsServer(port=port, host="127.0.0.1", metrics=metrics)
        try:
            server.start(blocking=False)
            assert server._thread is not None
            assert server._thread.is_alive()
        finally:
            server.stop()

    def test_stop_cleanly_shuts_down(self):
        port = _random_port()
        metrics = KernelMetrics(namespace=_unique_ns())
        server = MetricsServer(port=port, host="127.0.0.1", metrics=metrics)
        server.start(blocking=False)
        time.sleep(0.2)
        server.stop()
        assert server._server is None
        assert server._thread is None


class TestMetricsServerEndpoints:
    @pytest.fixture(autouse=True)
    def setup_server(self):
        self.port = _random_port()
        self.metrics = KernelMetrics(namespace=_unique_ns())
        self.server = MetricsServer(port=self.port, host="127.0.0.1", metrics=self.metrics)
        self.server.start(blocking=False)
        time.sleep(0.3)
        yield
        self.server.stop()

    def test_get_metrics_returns_200(self):
        resp = _get(f"http://127.0.0.1:{self.port}/metrics")
        assert resp.status == 200
        content_type = resp.headers.get("Content-Type", "")
        assert "text" in content_type
        body = resp.read().decode("utf-8")
        assert "# HELP" in body or "# TYPE" in body

    def test_get_health_returns_200(self):
        resp = _get(f"http://127.0.0.1:{self.port}/health")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["status"] == "healthy"

    def test_get_ready_returns_200(self):
        resp = _get(f"http://127.0.0.1:{self.port}/ready")
        assert resp.status == 200
        data = json.loads(resp.read())
        assert data["ready"] is True

    def test_get_nonexistent_returns_404(self):
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            _get(f"http://127.0.0.1:{self.port}/nonexistent")
        assert exc_info.value.code == 404

    def test_metrics_reflect_recorded_data(self):
        self.metrics.record_request("query", "success")
        self.metrics.record_violation("a1", "act", "pol", "high")
        resp = _get(f"http://127.0.0.1:{self.port}/metrics")
        body = resp.read().decode("utf-8")
        ns = self.metrics.namespace
        assert f"{ns}_requests_total" in body
        assert f"{ns}_violations_total" in body


class TestContextManager:
    def test_context_manager_works(self):
        port = _random_port()
        metrics = KernelMetrics(namespace=_unique_ns())
        with MetricsServer(port=port, host="127.0.0.1", metrics=metrics) as server:
            time.sleep(0.3)
            resp = _get(f"http://127.0.0.1:{port}/health")
            assert resp.status == 200
        # After exit, server should be stopped
        assert server._server is None


class TestFastAPIRouter:
    def test_create_fastapi_router(self):
        try:
            from fastapi import FastAPI
            from fastapi.testclient import TestClient
        except ImportError:
            pytest.skip("FastAPI not installed")

        metrics = KernelMetrics(namespace=_unique_ns())
        router = create_fastapi_router(metrics)
        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)

        resp = client.get("/metrics")
        assert resp.status_code == 200

        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

        resp = client.get("/ready")
        assert resp.status_code == 200
        assert resp.json()["ready"] is True
