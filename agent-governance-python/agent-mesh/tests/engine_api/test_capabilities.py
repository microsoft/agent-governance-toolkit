# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for CapabilityFlags, the capability_flags decorator, and allowlist derivation."""

from __future__ import annotations

import pytest

from agentmesh.engine_api import (
    CAPABILITY_EXTENSION_KEY,
    CAPABILITY_FLAGS_ATTR,
    CapabilityFlags,
    capability_flags,
    derive_studio_client_allowlist,
)

# The 12 read-only operations from docs/studio/engine-api-contract.md section 5.2
# (the implemented HTTP operations) plus the single mutating operation.
_READ_ONLY_OPERATION_IDS = [
    "getHealth",
    "listPolicies",
    "getPolicy",
    "validatePolicy",
    "testPolicy",
    "getAuditLog",
    "getTrustScores",
    "getTrustGraph",
    "listAgents",
    "listDecisions",
    "getVersions",
    "getEvents",
]


def _read_only_flags() -> dict[str, bool]:
    return {
        "runtime_mutating": False,
        "user_intent_required": False,
        "read_only_surface": True,
    }


def _mutating_flags() -> dict[str, bool]:
    return {
        "runtime_mutating": True,
        "user_intent_required": True,
        "read_only_surface": False,
    }


class TestCapabilityFlags:
    def test_valid_read_only_combination(self):
        flags = CapabilityFlags(**_read_only_flags())
        assert not flags.runtime_mutating
        assert not flags.user_intent_required
        assert flags.read_only_surface

    def test_valid_mutating_combination(self):
        flags = CapabilityFlags(**_mutating_flags())
        assert flags.runtime_mutating
        assert flags.user_intent_required
        assert not flags.read_only_surface

    def test_mutating_endpoint_may_skip_user_intent(self):
        # The invariant only couples read_only_surface and runtime_mutating;
        # user_intent_required is independent.
        flags = CapabilityFlags(
            runtime_mutating=True,
            user_intent_required=False,
            read_only_surface=False,
        )
        assert not flags.read_only_surface

    def test_invariant_rejects_mutating_marked_read_only(self):
        with pytest.raises(ValueError, match="read-only invariant violated"):
            CapabilityFlags(
                runtime_mutating=True,
                user_intent_required=True,
                read_only_surface=True,
            )

    def test_invariant_rejects_non_mutating_not_read_only(self):
        with pytest.raises(ValueError, match="read-only invariant violated"):
            CapabilityFlags(
                runtime_mutating=False,
                user_intent_required=False,
                read_only_surface=False,
            )

    def test_model_is_frozen(self):
        flags = CapabilityFlags(**_read_only_flags())
        with pytest.raises(Exception):
            flags.runtime_mutating = True

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValueError):
            CapabilityFlags(
                runtime_mutating=False,
                user_intent_required=False,
                read_only_surface=True,
                unexpected=True,
            )


class TestCapabilityFlagsDecorator:
    def test_attaches_validated_flags(self):
        @capability_flags(
            runtime_mutating=False,
            user_intent_required=False,
            read_only_surface=True,
        )
        def endpoint():
            return "ok"

        attached = getattr(endpoint, CAPABILITY_FLAGS_ATTR)
        assert isinstance(attached, CapabilityFlags)
        assert not attached.runtime_mutating
        assert attached.read_only_surface

    def test_returns_original_callable(self):
        def endpoint():
            return "ok"

        decorated = capability_flags(
            runtime_mutating=False,
            user_intent_required=False,
            read_only_surface=True,
        )(endpoint)

        assert decorated is endpoint
        assert decorated() == "ok"

    def test_decoration_raises_on_invariant_violation(self):
        with pytest.raises(ValueError, match="read-only invariant violated"):

            @capability_flags(
                runtime_mutating=True,
                user_intent_required=True,
                read_only_surface=True,
            )
            def endpoint():
                return "ok"


class TestDeriveStudioClientAllowlist:
    def _build_doc(self) -> dict:
        paths: dict = {}
        # 12 read-only GET/POST operations.
        for index, operation_id in enumerate(_READ_ONLY_OPERATION_IDS):
            paths[f"/api/v1/op{index}"] = {
                "get": {
                    "operationId": operation_id,
                    CAPABILITY_EXTENSION_KEY: _read_only_flags(),
                }
            }
        # 1 mutating operation that must be excluded.
        paths["/api/v1/policy/save"] = {
            "post": {
                "operationId": "policy_save",
                CAPABILITY_EXTENSION_KEY: _mutating_flags(),
            }
        }
        return {"openapi": "3.1.0", "paths": paths}

    def test_returns_twelve_read_only_operation_ids(self):
        allowlist = derive_studio_client_allowlist(self._build_doc())
        assert len(allowlist) == 12

    def test_excludes_policy_save(self):
        allowlist = derive_studio_client_allowlist(self._build_doc())
        assert "policy_save" not in allowlist
        assert set(allowlist) == set(_READ_ONLY_OPERATION_IDS)

    def test_output_is_sorted(self):
        allowlist = derive_studio_client_allowlist(self._build_doc())
        assert allowlist == sorted(allowlist)

    def test_empty_document_returns_empty_list(self):
        assert derive_studio_client_allowlist({"paths": {}}) == []

    def test_operations_without_flags_are_ignored(self):
        doc = {
            "paths": {
                "/api/v1/health": {
                    "get": {"operationId": "getHealth", CAPABILITY_EXTENSION_KEY: _read_only_flags()}
                },
                "/api/v1/undocumented": {"get": {"operationId": "noFlags"}},
            }
        }
        assert derive_studio_client_allowlist(doc) == ["getHealth"]

    def test_non_operation_keys_are_ignored(self):
        doc = {
            "paths": {
                "/api/v1/policies": {
                    "parameters": [{"name": "page"}],
                    "get": {
                        "operationId": "listPolicies",
                        CAPABILITY_EXTENSION_KEY: _read_only_flags(),
                    },
                }
            }
        }
        assert derive_studio_client_allowlist(doc) == ["listPolicies"]
