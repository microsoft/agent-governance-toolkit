# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import yaml, pytest
from pathlib import Path
from openshell_agentmesh.skill import GovernanceSkill

SAMPLE = {"apiVersion": "governance.toolkit/v1", "rules": [{"name": "allow-read", "condition": {"field": "action", "operator": "starts_with", "value": "file:read"}, "action": "allow", "priority": 90},{"name": "allow-shell", "condition": {"field": "action", "operator": "in", "value": ["shell:ls", "shell:python", "shell:git"]}, "action": "allow", "priority": 80},{"name": "block-danger", "condition": {"field": "action", "operator": "matches", "value": "shell:(rm|dd|curl)"}, "action": "deny", "priority": 100, "message": "Blocked"}]}

@pytest.fixture
def policy_dir(tmp_path):
    with open(tmp_path / "p.yaml", "w", encoding="utf-8") as f:
        yaml.dump(SAMPLE, f)
    return tmp_path

class TestSkill:
    def test_allow_read(self, policy_dir):
        assert GovernanceSkill(policy_dir=policy_dir).check_policy("file:read:/workspace/main.py").allowed
    def test_allow_shell(self, policy_dir):
        assert GovernanceSkill(policy_dir=policy_dir).check_policy("shell:python").allowed
    def test_deny(self, policy_dir):
        d = GovernanceSkill(policy_dir=policy_dir).check_policy("shell:rm -rf /")
        assert not d.allowed
    def test_default_deny(self, policy_dir):
        assert not GovernanceSkill(policy_dir=policy_dir).check_policy("unknown").allowed
    def test_trust(self):
        s = GovernanceSkill()
        assert s.get_trust_score("x") == 1.0
        s.adjust_trust("x", -0.3)
        assert s.get_trust_score("x") == pytest.approx(0.7)
    def test_audit(self, policy_dir):
        s = GovernanceSkill(policy_dir=policy_dir)
        s.check_policy("file:read:/t")
        s.check_policy("shell:rm /")
        log = s.get_audit_log()
        assert len(log) == 2 and log[0]["decision"] == "allow"
    def test_load(self, policy_dir):
        assert GovernanceSkill().load_policies(policy_dir) == 3
    def test_missing(self):
        with pytest.raises(FileNotFoundError): GovernanceSkill(policy_dir=Path("/nope"))
    def test_priority(self, policy_dir):
        d = GovernanceSkill(policy_dir=policy_dir).check_policy("shell:rm")
        assert not d.allowed and d.policy_name == "block-danger"
