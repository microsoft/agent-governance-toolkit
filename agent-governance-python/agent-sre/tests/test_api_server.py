# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the FastAPI REST server in ``agent_sre.api.server``."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from agent_sre.api import models
from agent_sre.api.server import app

# Every route that takes a JSON request body, and the model it is parsed into.
BODY_ROUTES = {
    ("/api/v1/slos", "post"): models.SLOCreateRequest,
    ("/api/v1/slos/{slo_name}/events", "post"): models.SLOEventRequest,
    ("/api/v1/cost/record", "post"): models.CostRecordRequest,
    ("/api/v1/chaos/experiments", "post"): models.ChaosCreateRequest,
    ("/api/v1/chaos/experiments/{experiment_id}/inject", "post"): models.FaultInjectRequest,
    ("/api/v1/incidents/{incident_id}/resolve", "post"): models.IncidentResolveRequest,
    ("/api/v1/signals", "post"): models.SignalIngestRequest,
    ("/api/v1/rollouts", "post"): models.RolloutCreateRequest,
}


class TestRequestBodies:
    @pytest.mark.parametrize(("path", "method"), sorted(BODY_ROUTES))
    def test_route_reads_its_model_from_the_request_body(self, path: str, method: str) -> None:
        operation = app.openapi()["paths"][path][method]

        schema = operation["requestBody"]["content"]["application/json"]["schema"]
        refs = [schema.get("$ref")] + [s.get("$ref") for s in schema.get("anyOf", [])]
        model_name = BODY_ROUTES[(path, method)].__name__
        assert f"#/components/schemas/{model_name}" in refs
        assert "body" not in [p["name"] for p in operation.get("parameters", [])]


class TestEndpoints:
    @pytest.fixture()
    def client(self):
        pytest.importorskip("httpx")
        from fastapi.testclient import TestClient

        with TestClient(app) as client:
            yield client

    def test_register_slo_and_record_event(self, client) -> None:
        resp = client.post(
            "/api/v1/slos",
            json={
                "name": "api-test-slo",
                "indicators": [{"name": "task_success_rate", "target": 0.99}],
            },
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["name"] == "api-test-slo"

        resp = client.post("/api/v1/slos/api-test-slo/events", json={"good": True})
        assert resp.status_code == 200, resp.text
        assert resp.json()["good"] is True

    def test_record_cost(self, client) -> None:
        resp = client.post(
            "/api/v1/cost/record",
            json={"agent_id": "api-test-agent", "task_id": "t1", "cost_usd": 0.25},
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["cost_usd"] == 0.25

    def test_create_rollout(self, client) -> None:
        resp = client.post(
            "/api/v1/rollouts",
            json={"name": "api-test-rollout", "steps": [{"weight": 0.1}]},
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["name"] == "api-test-rollout"
