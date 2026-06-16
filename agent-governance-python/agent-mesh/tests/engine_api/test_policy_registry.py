# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Unit tests for the filesystem-backed PolicyRegistry."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentmesh.engine_api.policy_registry import PolicyRegistry

_YAML_POLICY = """\
version: "1.0"
name: Alpha
description: alpha desc
rules:
  - name: r1
    condition:
      field: a
      operator: eq
      value: 1
    action: allow
"""

_JSON_POLICY = {
    "version": "1.0",
    "name": "Beta",
    "rules": [
        {"name": "r1", "condition": {"field": "a", "operator": "eq", "value": 1}, "action": "allow"},
        {"name": "r2", "condition": {"field": "b", "operator": "eq", "value": 2}, "action": "deny"},
    ],
}


@pytest.fixture
def registry(tmp_path: Path) -> PolicyRegistry:
    (tmp_path / "alpha.yaml").write_text(_YAML_POLICY, encoding="utf-8")
    (tmp_path / "beta.json").write_text(json.dumps(_JSON_POLICY), encoding="utf-8")
    return PolicyRegistry(tmp_path)


class TestLoadAndList:
    def test_lists_sorted_summaries(self, registry):
        ids = [s.id for s in registry.list_summaries()]
        assert ids == ["alpha", "beta"]

    def test_yaml_summary_metadata(self, registry):
        alpha = next(s for s in registry.list_summaries() if s.id == "alpha")
        assert alpha.name == "Alpha"
        assert alpha.description == "alpha desc"
        assert alpha.format == "yaml"
        assert alpha.source == "alpha.yaml"

    def test_json_summary_without_description(self, registry):
        beta = next(s for s in registry.list_summaries() if s.id == "beta")
        assert beta.name == "Beta"
        assert beta.description is None
        assert beta.format == "json"

    def test_non_policy_files_ignored(self, tmp_path):
        (tmp_path / "readme.txt").write_text("not a policy", encoding="utf-8")
        (tmp_path / "alpha.yaml").write_text(_YAML_POLICY, encoding="utf-8")
        reg = PolicyRegistry(tmp_path)
        assert [s.id for s in reg.list_summaries()] == ["alpha"]

    def test_subdirectories_ignored(self, tmp_path):
        (tmp_path / "nested").mkdir()
        (tmp_path / "alpha.yaml").write_text(_YAML_POLICY, encoding="utf-8")
        reg = PolicyRegistry(tmp_path)
        assert [s.id for s in reg.list_summaries()] == ["alpha"]


class TestGetDetail:
    def test_detail_includes_content_and_rules_count(self, registry):
        detail = registry.get_detail("beta")
        assert detail is not None
        assert detail.rules_count == 2
        assert "Beta" in detail.content
        assert detail.last_modified

    def test_yaml_rules_count(self, registry):
        detail = registry.get_detail("alpha")
        assert detail.rules_count == 1

    def test_unknown_id_returns_none(self, registry):
        assert registry.get_detail("missing") is None


class TestMissingDirectory:
    def test_missing_dir_is_empty(self, tmp_path):
        reg = PolicyRegistry(tmp_path / "does_not_exist")
        assert reg.list_summaries() == []
        assert reg.get_detail("anything") is None


class TestMalformedTolerance:
    def test_malformed_policy_lists_with_id_name_and_zero_rules(self, tmp_path):
        (tmp_path / "broken.yaml").write_text("foo: [1, 2", encoding="utf-8")
        reg = PolicyRegistry(tmp_path)
        summaries = reg.list_summaries()
        assert len(summaries) == 1
        assert summaries[0].id == "broken"
        assert summaries[0].name == "broken"  # falls back to id
        detail = reg.get_detail("broken")
        assert detail.rules_count == 0

    def test_non_mapping_policy_tolerated(self, tmp_path):
        (tmp_path / "scalar.yaml").write_text("just a string", encoding="utf-8")
        reg = PolicyRegistry(tmp_path)
        detail = reg.get_detail("scalar")
        assert detail.name == "scalar"
        assert detail.rules_count == 0

    def test_unreadable_file_is_skipped(self, tmp_path, monkeypatch):
        (tmp_path / "good.yaml").write_text(_YAML_POLICY, encoding="utf-8")
        (tmp_path / "bad.yaml").write_text(_YAML_POLICY, encoding="utf-8")

        from agentmesh.engine_api import policy_registry as pr

        original = Path.read_text

        def _raise_for_bad(self, *args, **kwargs):
            if self.name == "bad.yaml":
                raise OSError("permission denied")
            return original(self, *args, **kwargs)

        monkeypatch.setattr(pr.Path, "read_text", _raise_for_bad)
        reg = PolicyRegistry(tmp_path)
        # The unreadable file is skipped; the readable one still loads.
        assert [s.id for s in reg.list_summaries()] == ["good"]


class TestSave:
    def test_save_writes_file_and_reloads(self, tmp_path):
        reg = PolicyRegistry(tmp_path)
        assert reg.list_summaries() == []
        version = reg.save("gamma", _YAML_POLICY, "yaml")
        assert (tmp_path / "gamma.yaml").exists()
        assert "gamma" in [s.id for s in reg.list_summaries()]
        assert len(version) == 16

    def test_save_json_uses_json_suffix(self, tmp_path):
        reg = PolicyRegistry(tmp_path)
        reg.save("delta", json.dumps(_JSON_POLICY), "json")
        assert (tmp_path / "delta.json").exists()
        assert reg.get_detail("delta").format == "json"

    def test_save_creates_missing_directory(self, tmp_path):
        target = tmp_path / "nope"
        reg = PolicyRegistry(target)
        reg.save("epsilon", _YAML_POLICY, "yaml")
        assert (target / "epsilon.yaml").exists()

    def test_version_is_deterministic_for_same_content(self, tmp_path):
        reg = PolicyRegistry(tmp_path)
        v1 = reg.save("a", _YAML_POLICY, "yaml")
        v2 = reg.save("b", _YAML_POLICY, "yaml")
        assert v1 == v2  # same content -> same content hash

    def test_reload_picks_up_external_changes(self, tmp_path):
        reg = PolicyRegistry(tmp_path)
        (tmp_path / "alpha.yaml").write_text(_YAML_POLICY, encoding="utf-8")
        assert reg.list_summaries() == []  # not seen until reload
        reg.reload()
        assert [s.id for s in reg.list_summaries()] == ["alpha"]

    @pytest.mark.parametrize("bad_id", ["../escape", "nested/child", "../../escape"])
    def test_save_rejects_path_traversal(self, tmp_path, bad_id):
        reg = PolicyRegistry(tmp_path)
        with pytest.raises(ValueError, match="outside the policy directory"):
            reg.save(bad_id, _YAML_POLICY, "yaml")
