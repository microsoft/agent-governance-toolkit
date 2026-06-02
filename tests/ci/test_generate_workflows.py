# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the deterministic CI workflow generator.

These tests guard the properties that make generated workflows safe to trust:
determinism, full SHA pinned actions, least privilege permissions, a DO NOT EDIT
banner, and that the committed YAML matches the manifest (no drift). They also
exercise the fail closed validators on malformed manifests.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GENERATOR_PATH = REPO_ROOT / "scripts" / "ci" / "generate_workflows.py"

USES_RE = re.compile(r"uses:\s+(\S+)")
SHA_PIN_RE = re.compile(r"^[^@]+@[0-9a-f]{40}$")


def _load_generator():
    spec = importlib.util.spec_from_file_location("generate_workflows", GENERATOR_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


gen = _load_generator()


def test_build_outputs_includes_policy_engine_workflow():
    outputs = gen.build_outputs()
    names = {path.name for path in outputs}
    assert "policy-engine-ci.yml" in names


def test_generation_is_deterministic():
    first = gen.build_outputs()
    second = gen.build_outputs()
    assert {p.name: c for p, c in first.items()} == {p.name: c for p, c in second.items()}


def test_every_generated_action_is_sha_pinned():
    for _path, content in gen.build_outputs().items():
        for ref in USES_RE.findall(content):
            assert SHA_PIN_RE.match(ref), f"action not SHA pinned: {ref}"


def test_generated_workflows_have_banner_and_least_privilege():
    for _path, content in gen.build_outputs().items():
        assert content.startswith("# DO NOT EDIT."), "missing generated banner"
        assert "permissions:\n  contents: read\n" in content


def test_generated_opa_downloads_verify_checksum():
    for _path, content in gen.build_outputs().items():
        if "openpolicyagent.org/downloads" in content:
            assert "sha256sum -c -" in content
            assert gen.OPA_LINUX_AMD64_SHA256 in content


def test_policy_engine_python_job_uses_pinned_tooling():
    content = gen.build_outputs()[REPO_ROOT / ".github" / "workflows" / "policy-engine-ci.yml"]
    assert "python -m pip install --upgrade pip==24.3.1" in content
    assert "pip install maturin==1.8.7" in content
    assert "pytest==9.0.3" in content
    assert "pip install ./sdk/python ./generator pytest" not in content


def test_committed_yaml_matches_manifest():
    # The committed workflow must equal the freshly rendered output, i.e. the
    # same invariant the CI --check job enforces.
    drift = []
    for path, content in gen.build_outputs().items():
        if not path.exists() or path.read_text(encoding="utf-8") != content:
            drift.append(str(path.relative_to(REPO_ROOT)))
    assert not drift, f"committed workflows drift from manifest: {drift}. Run --write."


def test_check_mode_passes_on_committed_tree():
    assert gen.main(["--check"]) == 0


def test_unpinned_action_is_rejected(tmp_path):
    bad = tmp_path / "actions.toml"
    bad.write_text('[checkout]\nuses = "actions/checkout@v4"\ncomment = "v4"\n', encoding="utf-8")
    with pytest.raises(gen.GenerationError):
        gen._load_actions(bad)


def test_output_outside_workflows_dir_is_rejected():
    actions = gen._load_actions(gen.ACTIONS_PATH)
    workflow = {
        "name": "x",
        "output": "elsewhere/x.yml",
        "job": [{"id": "a", "step": [{"name": "n", "run": "echo hi"}]}],
    }
    with pytest.raises(gen.GenerationError):
        gen.render_workflow(workflow, actions)


def test_unknown_toolchain_is_rejected():
    actions = gen._load_actions(gen.ACTIONS_PATH)
    workflow = {
        "name": "x",
        "output": ".github/workflows/x.yml",
        "job": [{"id": "a", "toolchains": ["haskell"], "step": [{"name": "n", "run": "echo hi"}]}],
    }
    with pytest.raises(gen.GenerationError):
        gen.render_workflow(workflow, actions)


def test_unknown_action_key_is_rejected():
    actions = gen._load_actions(gen.ACTIONS_PATH)
    workflow = {
        "name": "x",
        "output": ".github/workflows/x.yml",
        "job": [{"id": "a", "toolchains": ["python"], "step": [{"name": "n", "uses": "missing-action"}]}],
    }
    with pytest.raises(gen.GenerationError):
        gen.render_workflow(workflow, actions)
