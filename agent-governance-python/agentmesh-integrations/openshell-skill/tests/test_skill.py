# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import yaml, pytest, json
from pathlib import Path
from openshell_agentmesh.skill import GovernanceSkill
from openshell_agentmesh.cli import main as cli_main

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


class TestTrustThreshold:
    def test_deny_below_threshold(self, policy_dir):
        skill = GovernanceSkill(policy_dir=policy_dir, trust_threshold=0.8)
        skill.adjust_trust("agent-a", -0.5)
        d = skill.check_policy("file:read:/ok", context={"agent_did": "agent-a"})
        assert not d.allowed
        assert "below threshold" in d.reason

    def test_allow_above_threshold(self, policy_dir):
        skill = GovernanceSkill(policy_dir=policy_dir, trust_threshold=0.3)
        d = skill.check_policy("file:read:/ok", context={"agent_did": "fresh-agent"})
        assert d.allowed

    def test_trust_clamp_floor(self):
        s = GovernanceSkill()
        s.adjust_trust("x", -5.0)
        assert s.get_trust_score("x") == 0.0

    def test_trust_clamp_ceiling(self):
        s = GovernanceSkill()
        s.adjust_trust("x", 5.0)
        assert s.get_trust_score("x") == 1.0


class TestEdgeCases:
    def test_empty_yaml_skipped(self, tmp_path):
        (tmp_path / "empty.yaml").write_text("", encoding="utf-8")
        skill = GovernanceSkill(policy_dir=tmp_path)
        assert len(skill._rules) == 0

    def test_yaml_no_rules_key(self, tmp_path):
        (tmp_path / "norules.yaml").write_text("apiVersion: v1\n", encoding="utf-8")
        skill = GovernanceSkill(policy_dir=tmp_path)
        assert len(skill._rules) == 0

    def test_unsupported_operator_no_match(self, policy_dir):
        skill = GovernanceSkill()
        assert not skill._match("nonexistent_op", "value", "value")

    def test_contains_operator(self, policy_dir):
        assert GovernanceSkill._match("contains", "hello world", "world")
        assert not GovernanceSkill._match("contains", "hello", "xyz")

    def test_equals_operator(self):
        assert GovernanceSkill._match("equals", "exact", "exact")
        assert not GovernanceSkill._match("equals", "exact", "other")

    def test_context_field_matching(self, tmp_path):
        policy = {"rules": [{"name": "env-check", "condition": {"field": "environment", "operator": "equals", "value": "production"}, "action": "deny", "message": "Blocked in prod"}]}
        with open(tmp_path / "env.yaml", "w", encoding="utf-8") as f:
            yaml.dump(policy, f)
        skill = GovernanceSkill(policy_dir=tmp_path)
        d = skill.check_policy("any-action", context={"environment": "production"})
        assert not d.allowed and "prod" in d.reason

    def test_audit_log_limit(self):
        skill = GovernanceSkill()
        for i in range(100):
            skill.log_action(f"action-{i}", "allow")
        assert len(skill.get_audit_log(limit=10)) == 10
        assert len(skill.get_audit_log()) == 50

    def test_audit_entry_has_timestamp(self, policy_dir):
        skill = GovernanceSkill(policy_dir=policy_dir)
        skill.check_policy("file:read:/t")
        entry = skill.get_audit_log()[0]
        assert "timestamp" in entry
        assert "T" in entry["timestamp"]

    def test_reload_clears_rules(self, policy_dir):
        skill = GovernanceSkill(policy_dir=policy_dir)
        assert len(skill._rules) == 3
        import tempfile
        with tempfile.TemporaryDirectory() as fresh_dir:
            Path(fresh_dir, "one.yaml").write_text("rules:\n- name: only\n  condition:\n    field: action\n    operator: equals\n    value: test\n  action: allow\n", encoding="utf-8")
            skill.load_policies(Path(fresh_dir))
            assert len(skill._rules) == 1


class TestCLI:
    def test_check_policy_allowed(self, policy_dir, capsys):
        rc = cli_main(["check-policy", "--action", "file:read:/x", "--policy-dir", str(policy_dir)])
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["allowed"] is True

    def test_check_policy_denied(self, policy_dir, capsys):
        rc = cli_main(["check-policy", "--action", "shell:rm /", "--policy-dir", str(policy_dir)])
        assert rc == 1
        out = json.loads(capsys.readouterr().out)
        assert out["allowed"] is False

    def test_invalid_json_context(self, policy_dir, capsys):
        rc = cli_main(["check-policy", "--action", "x", "--context", "{bad", "--policy-dir", str(policy_dir)])
        assert rc == 2
        err = capsys.readouterr().err
        assert "Invalid" in err

    def test_missing_policy_dir(self, capsys):
        rc = cli_main(["check-policy", "--action", "x", "--policy-dir", "/nonexistent/path"])
        assert rc == 2
        err = capsys.readouterr().err
        assert "not found" in err

    def test_trust_score_default(self, capsys):
        rc = cli_main(["trust-score", "--agent-did", "test-agent"])
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["trust_score"] == 1.0

    def test_no_command_prints_help(self, capsys):
        rc = cli_main([])
        assert rc == 1
