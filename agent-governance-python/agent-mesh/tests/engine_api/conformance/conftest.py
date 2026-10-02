# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Fixtures for the independent Engine API conformance profile."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentmesh.engine_api import create_app

from .contract import load_contract
from .target import external_target_from_environment, metadata_to_openapi, reference_target


@pytest.fixture(scope="session")
def canonical_contract() -> dict:
    """Load the checked-in canonical OpenAPI document once per test session."""
    return load_contract()


@pytest.fixture
def configured_target(app):
    """Use an explicitly configured external target, otherwise the reference adapter."""
    target = (
        external_target_from_environment()
        if os.getenv("AGT_ENGINE_API_URL")
        else reference_target(app)
    )
    if target.openapi is None and target.metadata is not None:
        target.openapi = metadata_to_openapi(target.metadata)
    try:
        yield target
    finally:
        target.close()


@pytest.fixture
def disabled_client(policy_dir: Path):
    """Build the isolated default-disabled save profile."""
    client = TestClient(create_app(policy_dir=str(policy_dir), enable_policy_save=False))
    try:
        yield client
    finally:
        client.close()
