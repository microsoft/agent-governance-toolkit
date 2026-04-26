"""Tests for the policy generator CLI."""

from __future__ import annotations

import os
import sys
import textwrap

import pytest
import yaml

# Ensure the package is importable
sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "src"),
)

from agent_os.cli.cmd_policy_gen import (
    TEMPLATE_CHOICES,
    TEMPLATES,
    generate_policy,
    cmd_policy_gen,
)


class TestGeneratePolicy:
    """Unit tests for generate_policy()."""

    @pytest.mark.parametrize("template_name", TEMPLATE_CHOICES)
    def test_generates_valid_yaml(self, template_name: str) -> None:
        result = generate_policy(template_name)
        # Should parse as valid YAML (skip comment lines)
        parsed = yaml.safe_load(result)
        assert isinstance(parsed, dict)
        assert "version" in parsed
        assert "rules" in parsed

    @pytest.mark.parametrize("template_name", TEMPLATE_CHOICES)
    def test_includes_header_comment(self, template_name: str) -> None:
        result = generate_policy(template_name)
        assert f"# AGT Policy — {template_name} template" in result
        assert f"--template {template_name}" in result

    def test_strict_has_default_deny(self) -> None:
        result = generate_policy("strict")
        parsed = yaml.safe_load(result)
        deny_rules = [r for r in parsed["rules"] if r["effect"] == "deny"]
        assert any(r["action"] == "*" for r in deny_rules)

    def test_permissive_allows_all(self) -> None:
        result = generate_policy("permissive")
        parsed = yaml.safe_load(result)
        allow_rules = [r for r in parsed["rules"] if r["effect"] == "allow"]
        assert any(r["action"] == "*" for r in allow_rules)

    def test_strict_has_content_filters(self) -> None:
        result = generate_policy("strict")
        parsed = yaml.safe_load(result)
        assert "content_filters" in parsed
        patterns = parsed["content_filters"]["blocked_patterns"]
        assert len(patterns) >= 2

    def test_unknown_template_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown template"):
            generate_policy("nonexistent")


class TestCmdPolicyGen:
    """Integration tests for the CLI entry point."""

    def test_stdout_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        cmd_policy_gen(["--template", "strict"])
        captured = capsys.readouterr()
        assert "version:" in captured.out
        assert "rules:" in captured.out

    def test_file_output(self, tmp_path: str) -> None:
        out_file = os.path.join(str(tmp_path), "policy.yaml")
        cmd_policy_gen(["--template", "read-only", "-o", out_file])
        assert os.path.exists(out_file)
        with open(out_file, encoding="utf-8") as f:
            parsed = yaml.safe_load(f)
        assert parsed["version"] == "1.0"
        assert any(r["action"] == "read_file" for r in parsed["rules"])

    @pytest.mark.parametrize("template_name", TEMPLATE_CHOICES)
    def test_all_templates_produce_output(
        self, template_name: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        cmd_policy_gen(["--template", template_name])
        captured = capsys.readouterr()
        assert len(captured.out) > 50
