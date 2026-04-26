# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the policy-as-code CLI and JSON Schema validation."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from agent_os.policies.cli import main
from agent_os.policies.schema import (
    PolicyAction,
    PolicyCondition,
    PolicyDefaults,
    PolicyDocument,
    PolicyOperator,
    PolicyRule,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SCHEMA_PATH = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "agent_os"
    / "policies"
    / "policy_schema.json"
)


def _valid_policy_dict() -> dict:
    """Return a minimal valid policy as a plain dict."""
    return {
        "version": "1.0",
        "name": "test-policy",
        "description": "A test policy for CLI validation",
        "rules": [
            {
                "name": "block_dangerous_tool",
                "condition": {
                    "field": "tool_name",
                    "operator": "eq",
                    "value": "rm_rf",
                },
                "action": "deny",
                "priority": 100,
                "message": "Dangerous tool blocked",
            },
            {
                "name": "allow_read",
                "condition": {
                    "field": "tool_name",
                    "operator": "eq",
                    "value": "read_file",
                },
                "action": "allow",
                "priority": 50,
                "message": "Read operations allowed",
            },
        ],
        "defaults": {
            "action": "allow",
            "max_tokens": 4096,
            "max_tool_calls": 10,
            "confidence_threshold": 0.8,
        },
    }


def _write_yaml(path: Path, data: dict) -> Path:
    path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False), encoding="utf-8")
    return path


def _write_json(path: Path, data: dict) -> Path:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# JSON Schema structural tests
# ---------------------------------------------------------------------------


class TestJsonSchema:
    """Verify the JSON Schema file is well-formed and matches the Pydantic models."""

    def test_schema_file_exists(self):
        assert SCHEMA_PATH.exists(), f"Schema file not found at {SCHEMA_PATH}"

    def test_schema_is_valid_json(self):
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        assert schema["$schema"] == "http://json-schema.org/draft-07/schema#"
        assert "definitions" in schema

    def test_schema_defines_all_types(self):
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        defs = schema["definitions"]
        assert "PolicyOperator" in defs
        assert "PolicyAction" in defs
        assert "PolicyCondition" in defs
        assert "PolicyRule" in defs
        assert "PolicyDefaults" in defs

    def test_schema_operators_match_enum(self):
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        schema_ops = set(schema["definitions"]["PolicyOperator"]["enum"])
        pydantic_ops = {op.value for op in PolicyOperator}
        assert schema_ops == pydantic_ops

    def test_schema_actions_match_enum(self):
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        schema_actions = set(schema["definitions"]["PolicyAction"]["enum"])
        pydantic_actions = {a.value for a in PolicyAction}
        assert schema_actions == pydantic_actions


# ---------------------------------------------------------------------------
# validate command
# ---------------------------------------------------------------------------


class TestValidateCommand:
    """Tests for the ``validate`` subcommand."""

    def test_validate_valid_yaml(self, tmp_path, capsys):
        policy_file = _write_yaml(tmp_path / "good.yaml", _valid_policy_dict())
        rc = main(["validate", str(policy_file)])
        assert rc == 0
        assert "OK" in capsys.readouterr().out

    def test_validate_valid_json(self, tmp_path, capsys):
        policy_file = _write_json(tmp_path / "good.json", _valid_policy_dict())
        rc = main(["validate", str(policy_file)])
        assert rc == 0
        assert "OK" in capsys.readouterr().out

    def test_validate_invalid_action(self, tmp_path, capsys):
        data = _valid_policy_dict()
        data["rules"][0]["action"] = "explode"  # invalid action
        policy_file = _write_yaml(tmp_path / "bad.yaml", data)
        rc = main(["validate", str(policy_file)])
        assert rc == 1
        assert "FAIL" in capsys.readouterr().err

    def test_validate_missing_required_field(self, tmp_path, capsys):
        data = _valid_policy_dict()
        del data["rules"][0]["condition"]["field"]  # required field
        policy_file = _write_yaml(tmp_path / "bad2.yaml", data)
        rc = main(["validate", str(policy_file)])
        assert rc == 1

    def test_validate_file_not_found(self, tmp_path, capsys):
        rc = main(["validate", str(tmp_path / "nonexistent.yaml")])
        assert rc == 2
        assert "ERROR" in capsys.readouterr().err

    def test_validate_malformed_yaml(self, tmp_path, capsys):
        bad_file = tmp_path / "malformed.yaml"
        bad_file.write_text("{{{{not: valid: yaml: ::::", encoding="utf-8")
        rc = main(["validate", str(bad_file)])
        assert rc == 2

    def test_validate_minimal_policy(self, tmp_path, capsys):
        """A policy with only required fields should validate."""
        minimal = {"rules": []}
        policy_file = _write_yaml(tmp_path / "minimal.yaml", minimal)
        rc = main(["validate", str(policy_file)])
        assert rc == 0

    def test_validate_invalid_operator(self, tmp_path, capsys):
        data = _valid_policy_dict()
        data["rules"][0]["condition"]["operator"] = "not_a_real_op"
        policy_file = _write_yaml(tmp_path / "bad_op.yaml", data)
        rc = main(["validate", str(policy_file)])
        assert rc == 1


# ---------------------------------------------------------------------------
# test command
# ---------------------------------------------------------------------------


class TestTestCommand:
    """Tests for the ``test`` subcommand."""

    def test_passing_scenarios(self, tmp_path, capsys):
        policy_file = _write_yaml(tmp_path / "policy.yaml", _valid_policy_dict())
        scenarios = {
            "scenarios": [
                {
                    "name": "Block dangerous tool",
                    "context": {"tool_name": "rm_rf"},
                    "expected_allowed": False,
                    "expected_action": "deny",
                },
                {
                    "name": "Allow safe read",
                    "context": {"tool_name": "read_file"},
                    "expected_allowed": True,
                    "expected_action": "allow",
                },
            ]
        }
        scenarios_file = _write_yaml(tmp_path / "scenarios.yaml", scenarios)
        rc = main(["test", str(policy_file), str(scenarios_file)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "2/2 scenarios passed" in out

    def test_failing_scenario(self, tmp_path, capsys):
        policy_file = _write_yaml(tmp_path / "policy.yaml", _valid_policy_dict())
        scenarios = {
            "scenarios": [
                {
                    "name": "Expect wrong result",
                    "context": {"tool_name": "rm_rf"},
                    "expected_allowed": True,  # wrong — policy denies rm_rf
                    "expected_action": "allow",
                },
            ]
        }
        scenarios_file = _write_yaml(tmp_path / "scenarios.yaml", scenarios)
        rc = main(["test", str(policy_file), str(scenarios_file)])
        assert rc == 1
        captured = capsys.readouterr()
        assert "FAIL" in captured.err
        assert "0/1 scenarios passed" in captured.out


    def test_missing_policy_file(self, tmp_path, capsys):
        scenarios_file = _write_yaml(tmp_path / "scenarios.yaml", {"scenarios": [{"name": "x"}]})
        rc = main(["test", str(tmp_path / "missing.yaml"), str(scenarios_file)])
        assert rc == 2

    def test_empty_scenarios(self, tmp_path, capsys):
        policy_file = _write_yaml(tmp_path / "policy.yaml", _valid_policy_dict())
        scenarios_file = _write_yaml(tmp_path / "empty.yaml", {"scenarios": []})
        rc = main(["test", str(policy_file), str(scenarios_file)])
        assert rc == 2


# ---------------------------------------------------------------------------
# diff command
# ---------------------------------------------------------------------------


class TestDiffCommand:
    """Tests for the ``diff`` subcommand."""

    def test_identical_files(self, tmp_path, capsys):
        data = _valid_policy_dict()
        f1 = _write_yaml(tmp_path / "a.yaml", data)
        f2 = _write_yaml(tmp_path / "b.yaml", data)
        rc = main(["diff", str(f1), str(f2)])
        assert rc == 0
        assert "No differences" in capsys.readouterr().out

    def test_rule_added(self, tmp_path, capsys):
        data1 = _valid_policy_dict()
        data2 = _valid_policy_dict()
        data2["rules"].append({
            "name": "new_rule",
            "condition": {"field": "x", "operator": "eq", "value": 1},
            "action": "audit",
            "priority": 10,
        })
        f1 = _write_yaml(tmp_path / "a.yaml", data1)
        f2 = _write_yaml(tmp_path / "b.yaml", data2)
        rc = main(["diff", str(f1), str(f2)])
        assert rc == 1
        out = capsys.readouterr().out
        assert "rule added" in out
        assert "new_rule" in out

    def test_rule_removed(self, tmp_path, capsys):
        data1 = _valid_policy_dict()
        data2 = _valid_policy_dict()
        data2["rules"].pop(0)  # remove first rule
        f1 = _write_yaml(tmp_path / "a.yaml", data1)
        f2 = _write_yaml(tmp_path / "b.yaml", data2)
        rc = main(["diff", str(f1), str(f2)])
        assert rc == 1
        out = capsys.readouterr().out
        assert "rule removed" in out
        assert "block_dangerous_tool" in out

    def test_priority_change(self, tmp_path, capsys):
        data1 = _valid_policy_dict()
        data2 = _valid_policy_dict()
        data2["rules"][0]["priority"] = 999
        f1 = _write_yaml(tmp_path / "a.yaml", data1)
        f2 = _write_yaml(tmp_path / "b.yaml", data2)
        rc = main(["diff", str(f1), str(f2)])
        assert rc == 1
        out = capsys.readouterr().out
        assert "priority" in out
        assert "100" in out
        assert "999" in out

    def test_defaults_change(self, tmp_path, capsys):
        data1 = _valid_policy_dict()
        data2 = _valid_policy_dict()
        data2["defaults"]["max_tokens"] = 8192
        f1 = _write_yaml(tmp_path / "a.yaml", data1)
        f2 = _write_yaml(tmp_path / "b.yaml", data2)
        rc = main(["diff", str(f1), str(f2)])
        assert rc == 1
        out = capsys.readouterr().out
        assert "max_tokens" in out
        assert "4096" in out
        assert "8192" in out

    def test_diff_file_not_found(self, tmp_path, capsys):
        f1 = _write_yaml(tmp_path / "a.yaml", _valid_policy_dict())
        rc = main(["diff", str(f1), str(tmp_path / "nonexistent.yaml")])
        assert rc == 2


# ---------------------------------------------------------------------------
# CLI entry-point edge cases
# ---------------------------------------------------------------------------


class TestCLIEntryPoint:
    """Tests for the main() dispatcher and edge cases."""

    def test_no_command_returns_2(self, capsys):
        rc = main([])
        assert rc == 2

    def test_validate_with_pydantic_model_roundtrip(self, tmp_path, capsys):
        """Ensure a policy created via Pydantic models validates via CLI."""
        doc = PolicyDocument(
            version="1.0",
            name="roundtrip-test",
            rules=[
                PolicyRule(
                    name="r1",
                    condition=PolicyCondition(
                        field="f", operator=PolicyOperator.EQ, value="v"
                    ),
                    action=PolicyAction.ALLOW,
                ),
            ],
            defaults=PolicyDefaults(action=PolicyAction.DENY),
        )
        yaml_path = tmp_path / "roundtrip.yaml"
        doc.to_yaml(yaml_path)
        rc = main(["validate", str(yaml_path)])
        assert rc == 0
        assert "OK" in capsys.readouterr().out
