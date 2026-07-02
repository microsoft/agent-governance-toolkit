# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for safe/atomic CLI migration writes."""

from __future__ import annotations

from argparse import Namespace
from pathlib import Path
from typing import Any

import pytest
import yaml

from agt.cli import migrate as migrate_mod


def _write_governance(path: Path, rule_name: str = "deny_dangerous_tool") -> None:
    doc = {
        "rules": [
            {
                "name": rule_name,
                "condition": {
                    "field": "tool_call.name",
                    "operator": "eq",
                    "value": "rm",
                },
                "action": "deny",
                "priority": 10,
                "message": "rm is blocked",
            }
        ],
        "intervention_points": {
            "pre_tool_call": {
                "policy_target": "$.tool_call.args",
                "policy_target_kind": "tool_args",
                "tool_name_from": "$.tool_call.name",
                "policy": {"id": "agt_legacy_rules"},
            }
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def _write_source(path: Path, source: str) -> None:
    path.write_text(source.strip(), encoding="utf-8")


def test_write_chain_rolls_back_backups_when_second_move_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    chain_root = tmp_path / "service"
    first_governance = chain_root / "governance.yaml"
    second_governance = chain_root / "governance.yml"
    _write_governance(first_governance, "deny_first")
    _write_governance(second_governance, "deny_second")
    first_original = first_governance.read_text(encoding="utf-8")
    second_original = second_governance.read_text(encoding="utf-8")

    def fake_resolve_manifest(
        root: Path,
        action_path: Path,
        *,
        bundle_dir: Path,
    ) -> dict[str, Any]:
        assert root == tmp_path.resolve()
        assert action_path == chain_root
        bundle_dir.mkdir(parents=True, exist_ok=True)
        (bundle_dir / "agt_legacy.rego").write_text(
            "package agt.legacy\n",
            encoding="utf-8",
        )
        return {
            "agent_control_specification_version": "1.0.0-agt",
            "metadata": {
                "resolved_from": {
                    "chain": [str(first_governance), str(second_governance)],
                }
            },
            "extends": [],
            "policies": {},
            "intervention_points": {},
        }

    original_replace = Path.replace

    def flaky_replace(self: Path, target: Path) -> Path:
        if self == second_governance:
            raise OSError("simulated second move failure")
        return original_replace(self, target)

    monkeypatch.setattr(migrate_mod, "resolve_manifest", fake_resolve_manifest)
    monkeypatch.setattr(Path, "replace", flaky_replace)

    finding = migrate_mod._migrate_governance_chain(
        chain_root,
        tmp_path,
        write=True,
    )

    assert finding.error is not None
    assert finding.error.startswith("write failed: simulated second move failure")
    assert first_governance.read_text(encoding="utf-8") == first_original
    assert second_governance.read_text(encoding="utf-8") == second_original
    assert not (chain_root / ".governance.yaml.v4-backup").exists()
    assert not (chain_root / ".governance.yml.v4-backup").exists()


def test_migrate_governance_policy_records_mkdir_errors(tmp_path: Path) -> None:
    _write_source(
        tmp_path / "app.py",
        """
from agent_os.integrations.base import GovernancePolicy
policy = GovernancePolicy(name="strict")
""",
    )
    (tmp_path / "policies").write_text("not a directory", encoding="utf-8")

    report = migrate_mod.migrate_project(tmp_path, write=True)

    assert report.governance_policies
    assert any("policy migration failed for app" in err for err in report.errors)
    assert any("policies" in err for err in report.errors)


def test_migrate_governance_policy_records_write_errors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _write_source(
        tmp_path / "worker.py",
        """
from agent_os.integrations.base import GovernancePolicy
policy = GovernancePolicy(name="strict")
""",
    )
    manifest_path = tmp_path / "policies" / "worker.manifest.yaml"
    original_write_text = Path.write_text

    def fail_manifest_write(self: Path, *args: Any, **kwargs: Any) -> int:
        if self == manifest_path:
            raise OSError("simulated manifest write failure")
        return original_write_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", fail_manifest_write)

    report = migrate_mod.migrate_project(tmp_path, write=True)

    assert report.governance_policies
    assert any("policy migration failed for worker" in err for err in report.errors)
    assert any("simulated manifest write failure" in err for err in report.errors)


def test_coerce_bridge_inputs_rejects_bool_for_numeric_fields() -> None:
    inputs = migrate_mod._coerce_bridge_inputs(
        {
            "max_tokens": True,
            "max_tool_calls": True,
            "confidence_threshold": False,
            "require_human_approval": True,
        }
    )

    assert inputs.max_tokens == 0
    assert not isinstance(inputs.max_tokens, bool)
    assert inputs.max_tool_calls == 0
    assert not isinstance(inputs.max_tool_calls, bool)
    assert inputs.confidence_threshold == 0.0
    assert isinstance(inputs.confidence_threshold, float)
    assert inputs.require_human_approval


def test_write_report_failure_warns_after_successful_migration(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    _write_governance(tmp_path / "governance.yaml")
    report_path = tmp_path / "reports" / "MIGRATION.md"
    original_write_text = Path.write_text

    def fail_report_write(self: Path, *args: Any, **kwargs: Any) -> int:
        if self == report_path:
            raise OSError("simulated report write failure")
        return original_write_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", fail_report_write)

    rc = migrate_mod.run_from_args(
        Namespace(
            direction="v4-to-v5",
            project_root=str(tmp_path),
            write=True,
            dry_run=False,
            write_report=str(report_path),
            verbose=False,
        )
    )

    captured = capsys.readouterr()
    assert rc == 0
    assert report_path.parent.is_dir()
    assert "warning: failed to write report" in captured.err
    assert str(report_path) in captured.err
    assert "simulated report write failure" in captured.err
