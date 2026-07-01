# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Shared fixtures for the Engine API reference adapter tests.

All adapter tests need FastAPI (and httpx for ``TestClient``); the whole package is skipped
when FastAPI is not installed. The :func:`client` fixture builds a fresh app over a temporary
policy directory seeded with one YAML and one JSON policy so the policy routes have real data.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from agentmesh.engine_api import create_app  # noqa: E402

# A YAML policy with name, description, and a single rule -> rules_count == 1.
_ALPHA_YAML = """\
version: "1.0"
name: Alpha Policy
description: First sample policy
rules:
  - name: allow-reads
    condition:
      field: action
      operator: eq
      value: read
    action: allow
    priority: 10
defaults:
  action: deny
"""

# A JSON policy with two rules and no description -> rules_count == 2, description None.
_BETA_JSON = {
    "version": "1.0",
    "name": "Beta Policy",
    "rules": [
        {"name": "r1", "condition": {"field": "a", "operator": "eq", "value": 1}, "action": "allow"},
        {"name": "r2", "condition": {"field": "b", "operator": "eq", "value": 2}, "action": "deny"},
    ],
}


@pytest.fixture
def policy_dir(tmp_path: Path) -> Path:
    """A temp policy directory seeded with two policies (one YAML, one JSON)."""
    (tmp_path / "alpha.yaml").write_text(_ALPHA_YAML, encoding="utf-8")
    (tmp_path / "beta.json").write_text(json.dumps(_BETA_JSON), encoding="utf-8")
    return tmp_path


@pytest.fixture
def app(policy_dir: Path):
    """A fully wired app over the seeded policy directory."""
    return create_app(policy_dir=str(policy_dir))


@pytest.fixture
def client(app) -> TestClient:
    """A ``TestClient`` over the seeded app (server exceptions surface by default)."""
    return TestClient(app)


@pytest.fixture
def empty_app(tmp_path: Path):
    """An app over an empty (but existing) policy directory."""
    empty = tmp_path / "empty"
    empty.mkdir()
    return create_app(policy_dir=str(empty))


@pytest.fixture
def empty_client(empty_app) -> TestClient:
    """A ``TestClient`` over an app with no policies loaded."""
    return TestClient(empty_app)
