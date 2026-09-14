# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for placeholder Engine API backend signalling."""

from __future__ import annotations

import pytest


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/agents",
        "/api/v1/audit/log",
        "/api/v1/decisions",
        "/api/v1/trust/scores",
        "/api/v1/trust/graph",
    ],
)
def test_placeholder_routes_signal_backend_status(client, path: str) -> None:
    response = client.get(path)

    assert response.status_code == 200
    assert response.headers["X-AGT-Backend-Status"] == "placeholder"


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/health",
        "/api/v1/policies",
    ],
)
def test_non_placeholder_routes_do_not_signal_placeholder_status(client, path: str) -> None:
    response = client.get(path)

    assert response.status_code == 200
    assert "X-AGT-Backend-Status" not in response.headers
