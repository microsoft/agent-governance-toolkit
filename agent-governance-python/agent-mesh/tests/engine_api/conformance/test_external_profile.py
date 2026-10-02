# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""A shared HTTP smoke assertion for the explicitly configured external target."""

from __future__ import annotations

from .assertions import assert_contract_response


def test_configured_target_health_uses_shared_contract_assertion(
    canonical_contract, configured_target
):
    """Exercise the same transport/schema assertion against local or external targets."""
    response = configured_target.request("GET", "/api/v1/health")
    body = assert_contract_response(response, canonical_contract, "getHealth", 200)
    assert body["status"] in {"ok", "degraded"}
