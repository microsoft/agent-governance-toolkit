# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the OpenShell governance skill."""
import yaml, pytest
from pathlib import Path
from openshell_agentmesh.skill import GovernanceSkill

SAMPLE_POLICY = {"apiVersion": "governance.toolkit/v1", "rules": [
    {"name": "allow-file-read", "condition": {"field": "action", "operator": "starts_with", "value": "file:read"}, "action": "allow", "priority": 90},
    {"name": "allow-safe-shell", "condition": {"field": "action", "operator": "in", "value": ["shell:ls", "shell:python", "shell:git"]}, "action": "allow", "priority": 80},
    {"name": "block-dangerous-shell", "condition": {"field": "action", "operator": "matches", "value": "shell:(rm|dd|curl)"}, "action": "deny", "priority": 100, "message": "Dangerous shell command blocked"},
]}

@pytest.fixture
def policy_dir(tmp_path):
    with open(tmp_path / "test-policy.yaml", "w", encoding="utf-8") as f:
        yaml.dump(SAMPLE_POLICY, f)
    return tmp_path

class TestGovernanceSkill:
    def test_allow_file_read(self, policy_dir):
        assert GovernanceSkill(policy_dir=policy_dir).check_policy("file:read:/workspace/main.py").allowed
    def test_allow_safe_shell(self, policy_dir):
        assert GovernanceSkill(policy_dir=policy_dir).check_policy("shell:python").allowed
    def test_deny_dangerous(self, policy_dir):
        d = GovernanceSkill(policy_dir=policy_dir).check_policy("shell:rm -rf /tmp")
        assert not d.allowed and "blocked" in d.reason.lower()
    def test_default_deny(self, policy_dir):
        assert not GovernanceSkill(policy_dir=policy_dir).check_policy("unknown:action").allowed
    def test_trust_default(self):
        assert GovernanceSkill().get_trust_score("did:mesh:x") == 1.0
    def test_trust_adjust(self):
        s = GovernanceSkill()
        s.adjust_trust("did:mesh:a", -0.3)
        assert s.get_trust_score("did:mesh:a") == pytest.approx(0.7)
    def test_audit_log(self, policy_dir):
        s = GovernanceSkill(policy_dir=policy_dir)
        s.check_policy("file:read:/test")
        s.check_policy("shell:rm /")
        log = s.get_audit_log()
        assert len(log) == 2 and log[0]["decision"] == "allow" and log[1]["decision"] == "deny"
    def test_load_count(self, policy_dir):
        assert GovernanceSkill().load_policies(policy_dir) == 3
    def test_missing_dir(self):
        with pytest.raises(FileNotFoundError):
            GovernanceSkill(policy_dir=Path("/nonexistent"))
    def test_priority(self, policy_dir):
        d = GovernanceSkill(policy_dir=policy_dir).check_policy("shell:rm")
        assert not d.allowed and d.policy_name == "block-dangerous-shell"
