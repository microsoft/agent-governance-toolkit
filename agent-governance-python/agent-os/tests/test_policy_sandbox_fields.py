# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Schema tests for the sandbox-related ``PolicyDocument`` fields.

These tests pin the contract that ``ACASandboxProvider`` (and any
future ``SandboxProvider`` backend) relies on:

* ``defaults.network_default`` exists, defaults to ``"deny"``
  (fail-closed), and accepts only ``"allow"`` / ``"deny"``.
* ``defaults.max_cpu`` / ``defaults.max_memory_mb`` /
  ``defaults.timeout_seconds`` are optional and default to ``None``.
* ``network_allowlist`` / ``tool_allowlist`` are list-of-string fields
  with empty defaults.
* YAML round-trip preserves all the new fields exactly.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from agent_os.policies import PolicyDocument
from agent_os.policies.schema import PolicyDefaults


class TestPolicyDefaults:
    def test_defaults_are_fail_closed(self):
        d = PolicyDefaults()
        assert d.network_default == "deny"
        assert d.max_cpu is None
        assert d.max_memory_mb is None
        assert d.timeout_seconds is None

    @pytest.mark.parametrize("value", ["allow", "deny"])
    def test_network_default_accepts_allow_or_deny(self, value):
        d = PolicyDefaults(network_default=value)
        assert d.network_default == value

    @pytest.mark.parametrize("value", ["permit", "block", "DENY", "", None])
    def test_network_default_rejects_other_values(self, value):
        with pytest.raises(ValidationError):
            PolicyDefaults(network_default=value)

    def test_sandbox_caps_are_stored(self):
        d = PolicyDefaults(max_cpu=0.5, max_memory_mb=1024, timeout_seconds=60)
        assert d.max_cpu == 0.5
        assert d.max_memory_mb == 1024
        assert d.timeout_seconds == 60


class TestPolicyDocumentSandboxFields:
    def test_defaults_are_empty(self):
        p = PolicyDocument(name="t")
        assert p.network_allowlist == []
        assert p.tool_allowlist == []
        assert p.defaults.network_default == "deny"

    def test_sandbox_fields_populated_from_dict(self):
        p = PolicyDocument.model_validate(
            {
                "name": "t",
                "network_allowlist": ["pypi.org", "*.github.com"],
                "tool_allowlist": ["read_doc"],
                "defaults": {
                    "max_cpu": 1.0,
                    "max_memory_mb": 2048,
                    "timeout_seconds": 90,
                    "network_default": "deny",
                },
            }
        )
        assert p.network_allowlist == ["pypi.org", "*.github.com"]
        assert p.tool_allowlist == ["read_doc"]
        assert p.defaults.max_cpu == 1.0
        assert p.defaults.max_memory_mb == 2048
        assert p.defaults.timeout_seconds == 90
        assert p.defaults.network_default == "deny"

    def test_yaml_round_trip_preserves_all_fields(self, tmp_path: Path):
        original = PolicyDocument.model_validate(
            {
                "name": "rt",
                "version": "1",
                "network_allowlist": ["a.com"],
                "tool_allowlist": ["t"],
                "defaults": {
                    "action": "allow",
                    "max_cpu": 0.25,
                    "max_memory_mb": 256,
                    "timeout_seconds": 15,
                    "network_default": "allow",
                },
            }
        )
        path = tmp_path / "p.yaml"
        original.to_yaml(path)
        reloaded = PolicyDocument.from_yaml(path)
        assert reloaded.network_allowlist == original.network_allowlist
        assert reloaded.tool_allowlist == original.tool_allowlist
        assert reloaded.defaults.network_default == "allow"
        assert reloaded.defaults.max_cpu == 0.25
        assert reloaded.defaults.max_memory_mb == 256
        assert reloaded.defaults.timeout_seconds == 15

    def test_yaml_without_sandbox_fields_still_loads(self, tmp_path: Path):
        # Backwards compat: older YAML files lack the new fields entirely.
        path = tmp_path / "legacy.yaml"
        path.write_text(
            "name: legacy\nversion: '1'\ndefaults:\n  action: allow\nrules: []\n",
            encoding="utf-8",
        )
        p = PolicyDocument.from_yaml(path)
        assert p.network_allowlist == []
        assert p.tool_allowlist == []
        # Schema default kicks in — fail-closed.
        assert p.defaults.network_default == "deny"
