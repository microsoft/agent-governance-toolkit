# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Contract and capability checks independent of the reference route catalog."""

from __future__ import annotations

import copy

import pytest

from agentmesh.engine_api import derive_studio_client_allowlist

from .contract import (
    assert_target_contract,
    assert_target_schema_compatibility,
    canonical_allowlist,
    capability_flags,
    iter_operations,
    operation_key,
    operation_map,
)
from .assertions import assert_api_version


def test_canonical_contract_defines_the_epic_zero_http_baseline(canonical_contract):
    operations = list(iter_operations(canonical_contract))
    assert len(operations) == 12
    assert len({operation.operation_id for operation in operations}) == len(operations)
    assert len({operation_key(operation) for operation in operations}) == len(operations)
    assert canonical_allowlist(canonical_contract)
    assert len(canonical_allowlist(canonical_contract)) == 11
    assert "savePolicy" not in canonical_allowlist(canonical_contract)


def test_target_openapi_matches_canonical_operations(
    canonical_contract, configured_target
):
    assert configured_target.openapi is not None
    assert_target_contract(
        canonical_contract,
        configured_target.openapi,
        require_exact_operations=not configured_target.external,
    )


def test_target_capability_flags_are_complete_and_consistent(
    canonical_contract, configured_target
):
    assert configured_target.openapi is not None
    expected = operation_map(canonical_contract)
    actual = operation_map(configured_target.openapi)
    for operation_id, expected_operation in expected.items():
        assert capability_flags(actual[operation_id]) == capability_flags(expected_operation)


def test_target_allowlist_is_derived_from_canonical_contract(
    canonical_contract, configured_target
):
    assert configured_target.openapi is not None
    target_allowlist = derive_studio_client_allowlist(configured_target.openapi)
    assert set(canonical_allowlist(canonical_contract)).issubset(target_allowlist)
    if not configured_target.external:
        assert target_allowlist == canonical_allowlist(canonical_contract)


def test_target_advertised_schemas_retain_canonical_required_fields(
    canonical_contract, configured_target
):
    if configured_target.external and configured_target.metadata and configured_target.openapi:
        if "responses" not in configured_target.openapi.get("paths", {}).get(
            "/api/v1/health", {}
        ).get("get", {}):
            return
    assert configured_target.openapi is not None
    assert_target_schema_compatibility(canonical_contract, configured_target.openapi)


def test_reserved_and_excluded_surfaces_are_not_callable(configured_target):
    assert configured_target.openapi is not None
    operations = operation_map(configured_target.openapi)
    assert "/api/v1/events" not in {operation.path for operation in operations.values()}
    assert "reloadPolicy" not in operations
    assert "POST /api/v1/policy/reload" not in operations


def test_meta_test_detects_missing_operation(canonical_contract, configured_target):
    assert configured_target.openapi is not None
    broken = copy.deepcopy(configured_target.openapi)
    broken["paths"].pop("/api/v1/health")
    with pytest.raises(AssertionError, match="operation IDs differ"):
        assert_target_contract(canonical_contract, broken, require_exact_operations=True)


def test_meta_test_detects_wrong_capability_flag(canonical_contract, configured_target):
    assert configured_target.openapi is not None
    broken = copy.deepcopy(configured_target.openapi)
    broken["paths"]["/api/v1/policy/save"]["post"]["x-capability-flags"][
        "runtime_mutating"
    ] = False
    with pytest.raises(AssertionError, match="runtime_mutating|flags differ"):
        assert_target_contract(canonical_contract, broken)


def test_meta_test_detects_non_boolean_or_missing_flags(
    canonical_contract, configured_target
):
    assert configured_target.openapi is not None
    missing = copy.deepcopy(configured_target.openapi)
    missing["paths"]["/api/v1/health"]["get"].pop("x-capability-flags")
    with pytest.raises(AssertionError, match="missing x-capability-flags"):
        assert_target_contract(canonical_contract, missing)

    non_boolean = copy.deepcopy(configured_target.openapi)
    non_boolean["paths"]["/api/v1/health"]["get"]["x-capability-flags"]["read_only_surface"] = "true"
    with pytest.raises(AssertionError, match="must all be boolean"):
        assert_target_contract(canonical_contract, non_boolean)


def test_meta_test_detects_schema_required_field_drift(
    canonical_contract, configured_target
):
    assert configured_target.openapi is not None
    broken = copy.deepcopy(configured_target.openapi)
    broken["components"]["schemas"]["HealthResponse"]["required"] = ["status"]
    with pytest.raises(AssertionError, match="omits canonical required fields"):
        assert_target_schema_compatibility(canonical_contract, broken)


def test_meta_test_detects_wrong_api_version(canonical_contract):
    with pytest.raises(AssertionError, match="advertises API"):
        assert_api_version({"api": "2.0.0"}, canonical_contract)
