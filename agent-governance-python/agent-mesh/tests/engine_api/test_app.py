# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""App-assembly tests: route registry, capability flags, allowlist, and no-warning startup."""

from __future__ import annotations

import warnings

import pytest

pytest.importorskip("fastapi")

import agentmesh  # noqa: E402  (import first so its module-level DeprecationWarning fires once)
from agentmesh.engine_api import (  # noqa: E402
    CAPABILITY_EXTENSION_KEY,
    create_app,
    derive_studio_client_allowlist,
)

# Contract section 7: the full set of v1 operationIds this adapter must register.
_ALL_OPERATION_IDS = {
    "getHealth",
    "listPolicies",
    "getPolicy",
    "validatePolicy",
    "testPolicy",
    "savePolicy",
    "getAuditLog",
    "getTrustScores",
    "getTrustGraph",
    "listAgents",
    "listDecisions",
    "getVersions",
}

# Contract section 6.2: the 11 read-only operations (savePolicy excluded), sorted.
_READ_ONLY_ALLOWLIST = sorted(_ALL_OPERATION_IDS - {"savePolicy"})

_READ_ONLY_FLAGS = {
    "runtime_mutating": False,
    "user_intent_required": False,
    "read_only_surface": True,
}
_MUTATING_FLAGS = {
    "runtime_mutating": True,
    "user_intent_required": True,
    "read_only_surface": False,
}


def _operations(schema: dict) -> dict[str, dict]:
    """Map operationId -> operation object from a generated OpenAPI document."""
    ops: dict[str, dict] = {}
    for path_item in schema["paths"].values():
        for method, operation in path_item.items():
            if method.lower() in {"get", "post", "put", "delete", "patch"} and isinstance(
                operation, dict
            ):
                op_id = operation.get("operationId")
                if op_id:
                    ops[op_id] = operation
    return ops


@pytest.fixture
def schema(app):
    return app.openapi()


class TestRouteRegistry:
    def test_all_twelve_operations_registered(self, schema):
        assert set(_operations(schema)) == _ALL_OPERATION_IDS

    def test_app_metadata(self, app):
        assert app.title == "AGT Studio Engine API"
        assert app.version == "1.0.0"

    def test_events_route_not_registered(self, schema):
        assert "getEvents" not in _operations(schema)
        assert "/api/v1/events" not in schema["paths"]

    def test_policy_reload_route_not_registered(self, schema):
        assert "/api/v1/policy/reload" not in schema["paths"]


class TestCapabilityFlags:
    def test_every_operation_has_flags(self, schema):
        for op_id, operation in _operations(schema).items():
            assert CAPABILITY_EXTENSION_KEY in operation, f"{op_id} missing flags"

    def test_read_only_operations_flagged_read_only(self, schema):
        ops = _operations(schema)
        for op_id in _READ_ONLY_ALLOWLIST:
            assert ops[op_id][CAPABILITY_EXTENSION_KEY] == _READ_ONLY_FLAGS

    def test_save_policy_is_only_mutating_operation(self, schema):
        ops = _operations(schema)
        assert ops["savePolicy"][CAPABILITY_EXTENSION_KEY] == _MUTATING_FLAGS
        mutating = [
            op_id
            for op_id, op in ops.items()
            if op[CAPABILITY_EXTENSION_KEY]["runtime_mutating"]
        ]
        assert mutating == ["savePolicy"]


class TestAllowlist:
    def test_allowlist_is_eleven_read_only_ids_sorted(self, schema):
        allowlist = derive_studio_client_allowlist(schema)
        assert allowlist == _READ_ONLY_ALLOWLIST
        assert len(allowlist) == 11

    def test_save_policy_excluded_from_allowlist(self, schema):
        assert "savePolicy" not in derive_studio_client_allowlist(schema)


class TestStartup:
    def test_create_app_emits_no_warnings(self):
        # agentmesh's package-level DeprecationWarning fires once at import time (already
        # triggered above), so wrapping only create_app() proves the factory itself is clean.
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            create_app(policy_dir="does-not-exist")
        assert caught == [], [str(w.message) for w in caught]

    def test_create_app_with_missing_dir_is_usable(self):
        app = create_app(policy_dir="does-not-exist")
        # The OpenAPI hook validates that every in-schema op carries flags.
        assert app.openapi()["info"]["title"] == "AGT Studio Engine API"

    def test_create_app_reads_env_var(self, monkeypatch, tmp_path):
        target = tmp_path / "env_policies"
        target.mkdir()
        monkeypatch.setenv("AGENTMESH_POLICY_DIR", str(target))
        app = create_app()
        assert app.state.policy_registry.policy_dir == target


class TestPackageExports:
    def test_create_app_is_lazily_exported(self):
        import agentmesh.engine_api as pkg

        assert callable(pkg.create_app)

    def test_unknown_attribute_raises_attribute_error(self):
        import agentmesh.engine_api as pkg

        with pytest.raises(AttributeError, match="no attribute 'does_not_exist'"):
            pkg.does_not_exist
