# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the OpenShell governance skill."""

from __future__ import annotations

import yaml
import pytest
from pathlib import Path

from openshell_agentmesh.skill import GovernanceSkill, PolicyDecision


SAMPLE_POLICY = {
    "apiVersion": "governance.toolkit/v1",
    "rules": [
        {
            "name": "allow-file-read",
            "condition": {"field": "action", "operator": "starts_with", "value": "file:read"},
            "action": "allow",
            "priority": 90,
        },
        {
            "name": "allow-safe-shell",
            "condition": {"field": "action", "operator": "in", "value": ["shell:ls", "shell:python", "shell:git"]},
            "action": "allow",
            "priority": 80,
        },
        {
            "name": "block-dangerous-shell",
            "condition": {"field": "action", "operator": "matches", "value": "shell:(rm|dd|curl)"},
            "action": "deny",
            "priority": 100,
            "message": "Dangerous shell command blocked",
        },
    ],
}


@pytest.fixture
def policy_dir(tmp_path: Path) -> Path:
    policy_file = tmp_path / "test-policy.yaml"
    with open(policy_file, "w", encoding="utf-8") as f:
        yaml.dump(SAMPLE_POLICY, f)
    return tmp_path


class TestGovernanceSkill:
    def test_policy_allow_file_read(self, policy_dir: Path) -> None:
        skill = GovernanceSkill(policy_dir=policy_dir)
        decision = skill.check_policy("file:read:/workspace/main.py")
        assert decision.allowed is True
        assert decision.policy_name == "allow-file-read"

    def test_policy_allow_safe_shell(self, policy_dir: Path) -> None:
        skill = GovernanceSkill(policy_dir=policy_dir)
        decision = skill.check_policy("shell:python")
        assert decision.allowed is True

    def test_policy_deny_dangerous_shell(self, policy_dir: Path) -> None:
        skill = GovernanceSkill(policy_dir=policy_dir)
        decision = skill.check_policy("shell:rm -rf /tmp")
        assert decision.allowed is False
        assert "blocked" in decision.reason.lower()

    def test_policy_default_deny(self, policy_dir: Path) -> None:
        skill = GovernanceSkill(policy_dir=policy_dir)
        decision = skill.check_policy("unknown:action")
        assert decision.allowed is False

    def test_trust_score_default(self) -> None:
        skill = GovernanceSkill()
        assert skill.get_trust_score("did:mesh:unknown") == 1.0

    def test_trust_score_adjust(self) -> None:
        skill = GovernanceSkill()
        skill.adjust_trust("did:mesh:agent1", -0.3)
        assert skill.get_trust_score("did:mesh:agent1") == pytest.approx(0.7)
        skill.adjust_trust("did:mesh:agent1", -0.9)
        assert skill.get_trust_score("did:mesh:agent1") == 0.0

    def test_audit_log(self, policy_dir: Path) -> None:
        skill = GovernanceSkill(policy_dir=policy_dir)
        skill.check_policy("file:read:/test")
        skill.check_policy("shell:rm -rf /")
        log = skill.get_audit_log()
        assert len(log) == 2
        assert log[0]["decision"] == "allow"
        assert log[1]["decision"] == "deny"

    def test_load_policies_count(self, policy_dir: Path) -> None:
        skill = GovernanceSkill()
        count = skill.load_policies(policy_dir)
        assert count == 3

    def test_load_policies_missing_dir(self) -> None:
        with pytest.raises(FileNotFoundError):
            GovernanceSkill(policy_dir=Path("/nonexistent"))

    def test_priority_ordering(self, policy_dir: Path) -> None:
        """Higher priority rules should match first."""
        skill = GovernanceSkill(policy_dir=policy_dir)
        # shell:rm matches both block-dangerous (100) and NOT safe-shell
        decision = skill.check_policy("shell:rm")
        assert decision.allowed is False
        assert decision.policy_name == "block-dangerous-shell"
