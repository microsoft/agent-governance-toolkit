# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for AgentConfig validation and file loading."""

import json
import os
import tempfile

import pytest

from agent_os.base_agent import AgentConfig


# ---------------------------------------------------------------------------
# agent_id validation (#120)
# ---------------------------------------------------------------------------


class TestAgentIdValidation:
    """Tests for agent_id format validation."""

    def test_valid_agent_id(self):
        config = AgentConfig(agent_id="my-agent-01")
        assert config.agent_id == "my-agent-01"

    def test_valid_agent_id_all_alpha(self):
        config = AgentConfig(agent_id="myagent")
        assert config.agent_id == "myagent"

    def test_valid_agent_id_numeric_start(self):
        config = AgentConfig(agent_id="1agent")
        assert config.agent_id == "1agent"

    def test_invalid_agent_id_too_short(self):
        with pytest.raises(ValueError, match="Invalid agent_id"):
            AgentConfig(agent_id="ab")

    def test_invalid_agent_id_starts_with_dash(self):
        with pytest.raises(ValueError, match="Invalid agent_id"):
            AgentConfig(agent_id="-bad-id")

    def test_invalid_agent_id_special_chars(self):
        with pytest.raises(ValueError, match="Invalid agent_id"):
            AgentConfig(agent_id="bad_id!")

    def test_invalid_agent_id_underscore(self):
        with pytest.raises(ValueError, match="Invalid agent_id"):
            AgentConfig(agent_id="bad_agent")

    def test_invalid_agent_id_too_long(self):
        with pytest.raises(ValueError, match="Invalid agent_id"):
            AgentConfig(agent_id="a" * 65)

    def test_valid_agent_id_max_length(self):
        config = AgentConfig(agent_id="a" * 64)
        assert len(config.agent_id) == 64

    def test_valid_agent_id_min_length(self):
        config = AgentConfig(agent_id="abc")
        assert config.agent_id == "abc"


# ---------------------------------------------------------------------------
# from_file loading (#121)
# ---------------------------------------------------------------------------


class TestFromFile:
    """Tests for AgentConfig.from_file() classmethod."""

    def test_load_yaml(self, tmp_path):
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text(
            "agent_id: test-agent\npolicies:\n  - read_only\nmetadata:\n  env: dev\n",
            encoding="utf-8",
        )
        config = AgentConfig.from_file(str(yaml_file))
        assert config.agent_id == "test-agent"
        assert config.policies == ["read_only"]
        assert config.metadata == {"env": "dev"}

    def test_load_yml_extension(self, tmp_path):
        yml_file = tmp_path / "config.yml"
        yml_file.write_text("agent_id: yml-agent\n", encoding="utf-8")
        config = AgentConfig.from_file(str(yml_file))
        assert config.agent_id == "yml-agent"

    def test_load_json(self, tmp_path):
        json_file = tmp_path / "config.json"
        data = {"agent_id": "json-agent", "policies": ["no_pii"]}
        json_file.write_text(json.dumps(data), encoding="utf-8")
        config = AgentConfig.from_file(str(json_file))
        assert config.agent_id == "json-agent"
        assert config.policies == ["no_pii"]

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError, match="Config file not found"):
            AgentConfig.from_file("/nonexistent/config.yaml")

    def test_unsupported_format(self, tmp_path):
        txt_file = tmp_path / "config.txt"
        txt_file.write_text("agent_id: test", encoding="utf-8")
        with pytest.raises(ValueError, match="Unsupported config format"):
            AgentConfig.from_file(str(txt_file))

    def test_load_defaults_when_optional_keys_missing(self, tmp_path):
        yaml_file = tmp_path / "minimal.yaml"
        yaml_file.write_text("agent_id: minimal-agent\n", encoding="utf-8")
        config = AgentConfig.from_file(str(yaml_file))
        assert config.policies == []
        assert config.metadata == {}

    def test_load_example_config(self):
        """Verify the bundled example config loads correctly."""
        example = os.path.join(
            os.path.dirname(__file__), "..", "examples", "agent_config.yaml"
        )
        config = AgentConfig.from_file(example)
        assert config.agent_id == "my-example-agent"
        assert "read_only" in config.policies
