# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for manifest-resolution IO hardening."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

import pytest
import yaml

import agt.manifest_resolution.build as build
from agt.manifest_resolution import ResolutionError, ResolutionReason


def _legacy_binding() -> dict[str, dict[str, Any]]:
    return {
        "pre_tool_call": {
            "policy_target": "$.tool_call.args",
            "policy_target_kind": "tool_args",
            "tool_name_from": "$.tool_call.name",
            "policy": {"id": "agt_legacy_rules"},
        }
    }


def _deny_rule() -> dict[str, Any]:
    return {
        "name": "deny-bash",
        "condition": {"field": "tool_name", "operator": "eq", "value": "bash"},
        "action": "deny",
        "priority": 10,
        "message": "blocked",
    }


def _write_governance(
    root: Path,
    rules: list[dict[str, Any]],
    intervention_points: dict[str, Any] | None,
) -> None:
    doc: dict[str, Any] = {"rules": rules}
    if intervention_points is not None:
        doc["intervention_points"] = intervention_points
    (root / "governance.yaml").write_text(
        yaml.safe_dump(doc),
        encoding="utf-8",
    )


def _assert_invalid_governance(exc: pytest.ExceptionInfo[ResolutionError]) -> None:
    assert exc.value.reason == ResolutionReason.INVALID_GOVERNANCE


def test_load_yaml_wraps_os_errors(tmp_path: Path) -> None:
    with pytest.raises(ResolutionError) as exc:
        build._load_yaml(tmp_path)

    _assert_invalid_governance(exc)
    assert "failed to read/parse" in exc.value.detail


def test_load_yaml_wraps_unicode_decode_errors(tmp_path: Path) -> None:
    governance = tmp_path / "governance.yaml"
    governance.write_bytes(b"\xff\xfe\x80")

    with pytest.raises(ResolutionError) as exc:
        build._load_yaml(governance)

    _assert_invalid_governance(exc)
    assert "failed to read/parse" in exc.value.detail


def test_materialize_rego_bundle_wraps_replace_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_replace(source: str | Path, destination: str | Path) -> None:
        raise OSError(f"cannot replace {source} -> {destination}")

    monkeypatch.setattr(os, "replace", raise_replace)

    with pytest.raises(ResolutionError) as exc:
        build._materialize_rego_bundle(tmp_path / "bundle", [_deny_rule()])

    _assert_invalid_governance(exc)
    assert "failed to materialize bundle in" in exc.value.detail


def test_materialize_rego_bundle_writes_matching_sha256(tmp_path: Path) -> None:
    policy_dir = build._materialize_rego_bundle(tmp_path / "bundle", [_deny_rule()])

    rego_file = policy_dir / "agt_legacy.rego"
    sidecar = policy_dir / "agt_legacy.rego.sha256"

    assert rego_file.is_file()
    assert sidecar.is_file()

    body = rego_file.read_text(encoding="utf-8")
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    assert sidecar.read_text(encoding="utf-8") == digest


def test_resolve_manifest_defers_bundle_creation_until_binding_validated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    _write_governance(root, [_deny_rule()], intervention_points=None)
    created_dirs: list[Path] = []

    def fake_mkdtemp(prefix: str) -> str:
        path = tmp_path / f"{prefix}{len(created_dirs)}"
        path.mkdir()
        created_dirs.append(path)
        return str(path)

    monkeypatch.setattr(build.tempfile, "mkdtemp", fake_mkdtemp)

    with pytest.raises(ResolutionError) as exc:
        build.resolve_manifest(root, root)

    _assert_invalid_governance(exc)
    assert created_dirs == []
    assert not list(tmp_path.glob("agt_resolved_bundle_*"))


def test_resolve_manifest_removes_owned_bundle_when_materialize_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    _write_governance(root, [_deny_rule()], intervention_points=_legacy_binding())
    created_dirs: list[Path] = []

    def fake_mkdtemp(prefix: str) -> str:
        path = tmp_path / f"{prefix}{len(created_dirs)}"
        path.mkdir()
        created_dirs.append(path)
        return str(path)

    def raise_materialize(bundle_root: Path, rules: list[dict[str, Any]]) -> Path:
        assert rules == [_deny_rule()]
        partial = bundle_root / "policy"
        partial.mkdir(parents=True)
        (partial / "partial.txt").write_text("partial\n", encoding="utf-8")
        raise ResolutionError.invalid_governance("materialization failed")

    monkeypatch.setattr(build.tempfile, "mkdtemp", fake_mkdtemp)
    monkeypatch.setattr(build, "_materialize_rego_bundle", raise_materialize)

    with pytest.raises(ResolutionError) as exc:
        build.resolve_manifest(root, root)

    _assert_invalid_governance(exc)
    assert created_dirs
    assert not created_dirs[0].exists()
