# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for inject_capability_extension OpenAPI emission against a FastAPI app."""

from __future__ import annotations

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi import FastAPI  # noqa: E402

from agentmesh.engine_api import (  # noqa: E402
    CAPABILITY_EXTENSION_KEY,
    capability_flags,
    derive_studio_client_allowlist,
    inject_capability_extension,
)


def _build_studio_app() -> FastAPI:
    """A FastAPI app mirroring the spec: 12 read-only ops + 1 mutating save."""
    app = FastAPI(title="AGT Studio Engine API", version="1.0.0")

    @app.get("/api/v1/health", operation_id="getHealth")
    @capability_flags(
        runtime_mutating=False, user_intent_required=False, read_only_surface=True
    )
    async def get_health():
        return {"status": "ok"}

    @app.get("/api/v1/policies", operation_id="listPolicies")
    @capability_flags(
        runtime_mutating=False, user_intent_required=False, read_only_surface=True
    )
    async def list_policies():
        return []

    @app.post("/api/v1/policy/save", operation_id="policy_save")
    @capability_flags(
        runtime_mutating=True, user_intent_required=True, read_only_surface=False
    )
    async def save_policy():
        return {"saved": True}

    return app


class TestInjectCapabilityExtension:
    def test_emits_extension_on_every_operation(self):
        app = _build_studio_app()
        inject_capability_extension(app)
        schema = app.openapi()

        health_op = schema["paths"]["/api/v1/health"]["get"]
        assert health_op[CAPABILITY_EXTENSION_KEY] == {
            "runtime_mutating": False,
            "user_intent_required": False,
            "read_only_surface": True,
        }

        save_op = schema["paths"]["/api/v1/policy/save"]["post"]
        assert save_op[CAPABILITY_EXTENSION_KEY] == {
            "runtime_mutating": True,
            "user_intent_required": True,
            "read_only_surface": False,
        }

    def test_extension_has_all_three_fields(self):
        app = _build_studio_app()
        inject_capability_extension(app)
        schema = app.openapi()

        for path_item in schema["paths"].values():
            for operation in path_item.values():
                flags = operation[CAPABILITY_EXTENSION_KEY]
                assert set(flags) == {
                    "runtime_mutating",
                    "user_intent_required",
                    "read_only_surface",
                }

    def test_shape_matches_openapi_yaml(self):
        # docs/studio/openapi.yaml emits x-capability-flags as a mapping of three
        # booleans on the operation object. Confirm we produce the same shape.
        app = _build_studio_app()
        inject_capability_extension(app)
        schema = app.openapi()

        flags = schema["paths"]["/api/v1/policies"]["get"][CAPABILITY_EXTENSION_KEY]
        assert flags == {
            "runtime_mutating": False,
            "user_intent_required": False,
            "read_only_surface": True,
        }

    def test_idempotent_across_repeated_calls(self):
        app = _build_studio_app()
        inject_capability_extension(app)
        first = app.openapi()
        second = app.openapi()
        assert first == second

    def test_raises_when_decorated_route_missing_flags(self):
        app = FastAPI(title="t", version="1.0.0")

        @app.get("/api/v1/unflagged", operation_id="unflagged")
        async def unflagged():
            return {}

        inject_capability_extension(app)
        with pytest.raises(ValueError, match="missing capability flags"):
            app.openapi()


class TestEndToEndAllowlist:
    def test_allowlist_from_generated_schema(self):
        app = _build_studio_app()
        inject_capability_extension(app)
        schema = app.openapi()

        allowlist = derive_studio_client_allowlist(schema)
        assert allowlist == ["getHealth", "listPolicies"]
        assert "policy_save" not in allowlist
