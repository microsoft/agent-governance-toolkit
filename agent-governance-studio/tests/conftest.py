# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Real installed runtime fixtures and independent canonical assertions."""

import importlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent_governance_studio.application import create_sidecar
from agent_governance_studio.config import Configuration

ROOT = Path(__file__).resolve().parents[2]
POLICY = """version: '1.0'
name: Alpha
rules:
  - name: allow-read
    condition: {field: action, operator: eq, value: read}
    action: allow
"""


@pytest.fixture(scope="session")
def slow_opa(tmp_path_factory):
    executable = tmp_path_factory.mktemp("slow-native") / ("slow.exe" if os.name == "nt" else "slow")
    subprocess.run(
        ["rustc", str(Path(__file__).parent / "fixtures" / "slow_opa.rs"), "-o", str(executable)],
        check=True, capture_output=True, timeout=60,
    )
    return executable


@pytest.fixture(scope="session")
def canonical():
    location = ROOT / "agent-governance-python" / "agent-mesh" / "tests" / "engine_api" / "conformance"
    spec = importlib.util.spec_from_file_location(
        "_studio_canonical", location / "__init__.py", submodule_search_locations=[str(location)]
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return (
        importlib.import_module("_studio_canonical.contract"),
        importlib.import_module("_studio_canonical.assertions"),
    )


@pytest.fixture
def policy_root(tmp_path):
    root = tmp_path / "policies"
    root.mkdir()
    (root / "alpha.yaml").write_text(POLICY, encoding="utf-8")
    (root / "beta.json").write_text(json.dumps({"name": "Beta", "rules": []}), encoding="utf-8")
    replay = root / "replay"
    replay.mkdir()
    (replay / "policy").mkdir()
    (replay / "manifest.yaml").write_text(
        "agent_control_specification_version: 0.4.0-alpha.1\n"
        "metadata:\n  name: studio-test\nextends: []\npolicies:\n"
        "  smoke:\n    type: rego\n    bundle: ./policy\n"
        "    query: data.agent_control_specification.smoke.verdict\n"
        "intervention_points:\n  input:\n    policy_target: $.input\n"
        "    policy_target_kind: user_input\n    policy:\n      id: smoke\n"
        "      query: data.agent_control_specification.smoke.input_verdict\n"
        "tools: {}\nannotators: {}\n", encoding="utf-8",
    )
    (replay / "policy" / "smoke.rego").write_text(
        'package agent_control_specification.smoke\n'
        'default input_verdict := {"decision": "allow"}\n', encoding="utf-8",
    )
    return root


@pytest.fixture
def app(policy_root):
    return create_sidecar(Configuration(policy_dir=policy_root))


@pytest.fixture
def client(app):
    with TestClient(
        app, base_url="http://127.0.0.1:8080",
        headers={"Origin": "http://127.0.0.1:8080", "X-AGT-Studio-Request": "1"},
        client=("127.0.0.1", 12345),
    ) as client:
        yield client
