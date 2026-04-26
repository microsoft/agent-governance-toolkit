# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for batch policy evaluation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from agent_marketplace.batch import (
    BatchResult,
    PluginResult,
    Violation,
    evaluate_batch,
    evaluate_batch_command,
    format_report,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_manifest(directory: Path, name: str, **overrides) -> Path:
    """Create a plugin subdirectory with an agent-plugin.yaml manifest."""
    plugin_dir = directory / name
    plugin_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "name": name,
        "version": "1.0.0",
        "description": "A test plugin for evaluation",
        "author": "test@example.com",
        "plugin_type": "integration",
        "capabilities": ["cap-a"],
        "dependencies": [],
    }
    manifest.update(overrides)
    (plugin_dir / "agent-plugin.yaml").write_text(
        yaml.dump(manifest), encoding="utf-8"
    )
    return plugin_dir


def _write_policy(directory: Path, rules: dict) -> Path:
    """Write a policy YAML file and return its path."""
    policy_path = directory / "policy.yaml"
    policy_path.write_text(yaml.dump({"rules": rules}), encoding="utf-8")
    return policy_path


# ---------------------------------------------------------------------------
# evaluate_batch tests
# ---------------------------------------------------------------------------


class TestEvaluateBatch:
    """Tests for the evaluate_batch function."""

    def test_all_compliant(self, tmp_path: Path) -> None:
        """All plugins pass policy checks."""
        _write_manifest(tmp_path, "plugin-a", signature="abc123")
        _write_manifest(tmp_path, "plugin-b", signature="def456")
        policy = _write_policy(
            tmp_path, {"require_signature": True, "allowed_types": ["integration"]}
        )

        result = evaluate_batch(tmp_path, policy)

        assert result.total == 2
        assert result.compliant == 2
        assert result.non_compliant == 0
        assert all(p.status == "compliant" for p in result.plugins)

    def test_mixed_compliance(self, tmp_path: Path) -> None:
        """Some plugins pass, some fail."""
        _write_manifest(tmp_path, "good-plugin", signature="abc123")
        _write_manifest(tmp_path, "unsigned-plugin")  # no signature
        policy = _write_policy(tmp_path, {"require_signature": True})

        result = evaluate_batch(tmp_path, policy)

        assert result.total == 2
        assert result.compliant == 1
        assert result.non_compliant == 1
        names = {p.name: p.status for p in result.plugins}
        assert names["good-plugin"] == "compliant"
        assert names["unsigned-plugin"] == "non_compliant"

    def test_invalid_manifest(self, tmp_path: Path) -> None:
        """Unparseable manifests are reported as non-compliant."""
        bad_dir = tmp_path / "bad-plugin"
        bad_dir.mkdir()
        # Valid YAML but missing required PluginManifest fields
        (bad_dir / "agent-plugin.yaml").write_text(
            "name: bad-plugin\n", encoding="utf-8"
        )
        policy = _write_policy(tmp_path, {})

        result = evaluate_batch(tmp_path, policy)

        assert result.total == 1
        assert result.non_compliant == 1
        assert result.plugins[0].violations[0].rule == "manifest_parse_error"

    def test_empty_directory(self, tmp_path: Path) -> None:
        """No manifests found produces zero-total result."""
        policy = _write_policy(tmp_path, {})

        result = evaluate_batch(tmp_path, policy)

        assert result.total == 0
        assert result.compliant == 0
        assert result.plugins == []

    def test_severity_counts(self, tmp_path: Path) -> None:
        """by_severity aggregates violation severities correctly."""
        _write_manifest(tmp_path, "p1", capabilities=[])
        _write_manifest(tmp_path, "p2", capabilities=[])
        policy = _write_policy(tmp_path, {"require_capabilities": True})

        result = evaluate_batch(tmp_path, policy)

        assert result.by_severity.get("medium") == 2

    def test_top_violations(self, tmp_path: Path) -> None:
        """top_violations lists rules ordered by frequency."""
        _write_manifest(tmp_path, "p1")
        _write_manifest(tmp_path, "p2")
        policy = _write_policy(
            tmp_path, {"require_signature": True, "require_capabilities": True}
        )

        result = evaluate_batch(tmp_path, policy)

        assert "require_signature" in result.top_violations

    def test_allowed_types_violation(self, tmp_path: Path) -> None:
        """Plugin with a disallowed type fails."""
        _write_manifest(tmp_path, "agent-p", plugin_type="agent")
        policy = _write_policy(tmp_path, {"allowed_types": ["integration"]})

        result = evaluate_batch(tmp_path, policy)

        assert result.non_compliant == 1
        assert result.plugins[0].violations[0].rule == "allowed_types"

    def test_max_dependencies_violation(self, tmp_path: Path) -> None:
        """Plugin exceeding max dependencies fails."""
        deps = [f"dep-{i}>=1.0.0" for i in range(5)]
        _write_manifest(tmp_path, "heavy-plugin", dependencies=deps)
        policy = _write_policy(tmp_path, {"max_dependencies": 2})

        result = evaluate_batch(tmp_path, policy)

        assert result.non_compliant == 1
        assert result.plugins[0].violations[0].rule == "max_dependencies"

    def test_min_description_length(self, tmp_path: Path) -> None:
        """Short descriptions trigger a violation."""
        _write_manifest(tmp_path, "short-desc", description="Hi")
        policy = _write_policy(tmp_path, {"min_description_length": 20})

        result = evaluate_batch(tmp_path, policy)

        assert result.non_compliant == 1
        assert result.plugins[0].violations[0].rule == "min_description_length"


# ---------------------------------------------------------------------------
# format_report tests
# ---------------------------------------------------------------------------


class TestFormatReport:
    """Tests for the format_report function."""

    @staticmethod
    def _sample_result() -> BatchResult:
        return BatchResult(
            total=2,
            compliant=1,
            non_compliant=1,
            by_severity={"high": 1},
            top_violations=["require_signature"],
            plugins=[
                PluginResult(name="good", status="compliant", violations=[]),
                PluginResult(
                    name="bad",
                    status="non_compliant",
                    violations=[
                        Violation(
                            rule="require_signature",
                            severity="high",
                            message="Not signed",
                            remediation="Sign it",
                        )
                    ],
                ),
            ],
        )

    def test_json_format(self) -> None:
        """JSON output is valid and contains expected fields."""
        output = format_report(self._sample_result(), "json")
        parsed = json.loads(output)

        assert parsed["total"] == 2
        assert parsed["compliant"] == 1
        assert len(parsed["plugins"]) == 2

    def test_markdown_format(self) -> None:
        """Markdown output contains headers, tables, and status icons."""
        output = format_report(self._sample_result(), "markdown")

        assert "# Batch Policy Evaluation Report" in output
        assert "\u2713 good" in output
        assert "\u2717 bad" in output
        assert "`require_signature`" in output

    def test_text_format(self) -> None:
        """Text output contains summary and per-plugin details."""
        output = format_report(self._sample_result(), "text")

        assert "Batch Policy Evaluation Report" in output
        assert "\u2713 good" in output
        assert "\u2717 bad" in output
        assert "require_signature" in output

    def test_unknown_format_raises(self) -> None:
        """Unknown format raises an error."""
        with pytest.raises(Exception):
            format_report(self._sample_result(), "xml")


# ---------------------------------------------------------------------------
# CLI command tests
# ---------------------------------------------------------------------------


class TestCLICommand:
    """Tests for the evaluate-batch CLI command."""

    def test_exit_code_success(self, tmp_path: Path) -> None:
        """Exit code 0 when all plugins are compliant."""
        _write_manifest(tmp_path, "ok-plugin", signature="sig")
        _write_policy(tmp_path, {"require_signature": True})

        runner = CliRunner()
        result = runner.invoke(
            evaluate_batch_command,
            [str(tmp_path), "--policy", str(tmp_path / "policy.yaml")],
        )

        assert result.exit_code == 0

    def test_exit_code_failure(self, tmp_path: Path) -> None:
        """Exit code 1 when violations exist."""
        _write_manifest(tmp_path, "unsigned-plugin")
        _write_policy(tmp_path, {"require_signature": True})

        runner = CliRunner()
        result = runner.invoke(
            evaluate_batch_command,
            [str(tmp_path), "--policy", str(tmp_path / "policy.yaml")],
        )

        assert result.exit_code == 1

    def test_json_output(self, tmp_path: Path) -> None:
        """--format json produces valid JSON."""
        _write_manifest(tmp_path, "test-plugin")
        _write_policy(tmp_path, {})

        runner = CliRunner()
        result = runner.invoke(
            evaluate_batch_command,
            [
                str(tmp_path),
                "--policy",
                str(tmp_path / "policy.yaml"),
                "--format",
                "json",
            ],
        )

        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["total"] == 1

    def test_markdown_output(self, tmp_path: Path) -> None:
        """--format markdown produces a markdown report."""
        _write_manifest(tmp_path, "test-plugin")
        _write_policy(tmp_path, {})

        runner = CliRunner()
        result = runner.invoke(
            evaluate_batch_command,
            [
                str(tmp_path),
                "--policy",
                str(tmp_path / "policy.yaml"),
                "--format",
                "markdown",
            ],
        )

        assert result.exit_code == 0
        assert "# Batch Policy Evaluation Report" in result.output

    def test_output_file(self, tmp_path: Path) -> None:
        """--output writes the report to a file."""
        _write_manifest(tmp_path, "test-plugin")
        _write_policy(tmp_path, {})
        out_file = tmp_path / "report.json"

        runner = CliRunner()
        result = runner.invoke(
            evaluate_batch_command,
            [
                str(tmp_path),
                "--policy",
                str(tmp_path / "policy.yaml"),
                "--format",
                "json",
                "--output",
                str(out_file),
            ],
        )

        assert result.exit_code == 0
        assert out_file.exists()
        parsed = json.loads(out_file.read_text())
        assert parsed["total"] == 1
