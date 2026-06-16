# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the section 10 error envelope, codes, and exception handlers."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi import FastAPI, HTTPException, Query  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from agentmesh.engine_api.errors import (  # noqa: E402
    INTERNAL_ERROR,
    POLICY_NOT_FOUND,
    STANDARD_ERROR_CODES,
    VALIDATION_ERROR,
    ApiError,
    ErrorEnvelope,
    register_error_handlers,
)


def _handler_app() -> FastAPI:
    app = FastAPI()
    register_error_handlers(app)

    @app.get("/api-error")
    async def raise_api_error():
        raise ApiError(404, POLICY_NOT_FOUND, "nope", {"id": "x"})

    @app.get("/http-error")
    async def raise_http_error():
        raise HTTPException(status_code=404, detail="missing")

    @app.get("/boom")
    async def raise_unhandled():
        raise RuntimeError("kaboom")

    @app.get("/validated")
    async def validated(n: int = Query(...)):
        return {"n": n}

    return app


@pytest.fixture
def handler_client() -> TestClient:
    # raise_server_exceptions=False so the registered Exception handler runs.
    return TestClient(_handler_app(), raise_server_exceptions=False)


class TestErrorCodes:
    def test_all_nine_standard_codes_present(self):
        assert len(STANDARD_ERROR_CODES) == 9
        assert "POLICY_NOT_FOUND" in STANDARD_ERROR_CODES
        assert "ENGINE_UNAVAILABLE" in STANDARD_ERROR_CODES

    def test_envelope_defaults_details_to_empty_dict(self):
        env = ErrorEnvelope(status=500, code=INTERNAL_ERROR, message="x")
        assert env.details == {}


class TestApiError:
    def test_attributes_round_trip(self):
        err = ApiError(422, VALIDATION_ERROR, "bad", {"k": "v"})
        assert err.status == 422
        assert err.code == VALIDATION_ERROR
        assert err.message == "bad"
        assert err.details == {"k": "v"}

    def test_details_default_empty(self):
        err = ApiError(500, INTERNAL_ERROR, "x")
        assert err.details == {}


class TestHandlers:
    def test_api_error_renders_envelope(self, handler_client):
        resp = handler_client.get("/api-error")
        assert resp.status_code == 404
        body = resp.json()
        assert body == {
            "status": 404,
            "code": POLICY_NOT_FOUND,
            "message": "nope",
            "details": {"id": "x"},
        }

    def test_http_exception_mapped_to_code(self, handler_client):
        resp = handler_client.get("/http-error")
        assert resp.status_code == 404
        assert resp.json()["code"] == POLICY_NOT_FOUND
        assert resp.json()["message"] == "missing"

    def test_unhandled_exception_is_internal_error(self, handler_client):
        resp = handler_client.get("/boom")
        assert resp.status_code == 500
        body = resp.json()
        assert body["code"] == INTERNAL_ERROR
        assert body["status"] == 500
        # The original exception text must not leak to the client.
        assert "kaboom" not in body["message"]

    def test_validation_error_remapped_to_envelope(self, handler_client):
        resp = handler_client.get("/validated")  # missing required ?n=
        assert resp.status_code == 422
        body = resp.json()
        assert body["code"] == VALIDATION_ERROR
        assert body["status"] == 422
        assert "errors" in body["details"]
        assert isinstance(body["details"]["errors"], list)
