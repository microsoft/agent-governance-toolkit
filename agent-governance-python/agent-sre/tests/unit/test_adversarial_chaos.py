# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for adversarial chaos engineering — red-team experiments."""


from agent_sre.chaos.adversarial import (
    BUILTIN_PLAYBOOKS,
    AdversarialPlaybook,
    AdversarialRunner,
    AttackResult,
    AttackTechnique,
    PlaybookResult,
    PlaybookStep,
)
from agent_sre.chaos.engine import (
    ChaosExperiment,
    Fault,
    FaultType,
)
from agent_sre.chaos.library import ChaosLibrary

# ---------------------------------------------------------------------------
# FaultType enum — new adversarial values
# ---------------------------------------------------------------------------

class TestAdversarialFaultTypes:
    def test_prompt_injection_type_exists(self) -> None:
        assert FaultType.PROMPT_INJECTION.value == "prompt_injection"

    def test_policy_bypass_type_exists(self) -> None:
        assert FaultType.POLICY_BYPASS.value == "policy_bypass"

    def test_privilege_escalation_type_exists(self) -> None:
        assert FaultType.PRIVILEGE_ESCALATION.value == "privilege_escalation"

    def test_data_exfiltration_type_exists(self) -> None:
        assert FaultType.DATA_EXFILTRATION.value == "data_exfiltration"

    def test_tool_abuse_type_exists(self) -> None:
        assert FaultType.TOOL_ABUSE.value == "tool_abuse"

    def test_identity_spoofing_type_exists(self) -> None:
        assert FaultType.IDENTITY_SPOOFING.value == "identity_spoofing"


# ---------------------------------------------------------------------------
# Fault factory methods — adversarial
# ---------------------------------------------------------------------------

class TestAdversarialFaultFactories:
    def test_prompt_injection_defaults(self) -> None:
        f = Fault.prompt_injection("agent-1")
        assert f.fault_type == FaultType.PROMPT_INJECTION
        assert f.target == "agent-1"
        assert f.rate == 1.0
        assert f.params["technique"] == "direct_override"

    def test_prompt_injection_custom(self) -> None:
        f = Fault.prompt_injection("agent-1", technique="encoded", rate=0.5)
        assert f.params["technique"] == "encoded"
        assert f.rate == 0.5

    def test_policy_bypass(self) -> None:
        f = Fault.policy_bypass("agent-2", policy_name="data_access")
        assert f.fault_type == FaultType.POLICY_BYPASS
        assert f.params["policy_name"] == "data_access"

    def test_privilege_escalation(self) -> None:
        f = Fault.privilege_escalation("agent-3", target_role="superadmin")
        assert f.fault_type == FaultType.PRIVILEGE_ESCALATION
        assert f.params["target_role"] == "superadmin"

    def test_data_exfiltration(self) -> None:
        f = Fault.data_exfiltration("agent-4", data_type="secrets")
        assert f.fault_type == FaultType.DATA_EXFILTRATION
        assert f.params["data_type"] == "secrets"

    def test_tool_abuse(self) -> None:
        f = Fault.tool_abuse("agent-5", tool_name="file_write")
        assert f.fault_type == FaultType.TOOL_ABUSE
        assert f.params["tool_name"] == "file_write"

    def test_identity_spoofing(self) -> None:
        f = Fault.identity_spoofing("agent-6", spoofed_id="governance-agent")
        assert f.fault_type == FaultType.IDENTITY_SPOOFING
        assert f.params["spoofed_id"] == "governance-agent"

    def test_adversarial_fault_to_dict(self) -> None:
        f = Fault.prompt_injection("agent-1")
        d = f.to_dict()
        assert d["fault_type"] == "prompt_injection"
        assert d["target"] == "agent-1"
        assert d["params"]["technique"] == "direct_override"


# ---------------------------------------------------------------------------
# AttackTechnique and AttackResult enums
# ---------------------------------------------------------------------------

class TestEnums:
    def test_attack_technique_values(self) -> None:
        assert len(AttackTechnique) == 8
        assert AttackTechnique.DIRECT_OVERRIDE.value == "direct_override"
        assert AttackTechnique.MULTI_AGENT_COLLUSION.value == "multi_agent_collusion"

    def test_attack_result_values(self) -> None:
        assert len(AttackResult) == 4
        assert AttackResult.BLOCKED.value == "blocked"
        assert AttackResult.BYPASSED.value == "bypassed"


# ---------------------------------------------------------------------------
# PlaybookStep and AdversarialPlaybook creation
# ---------------------------------------------------------------------------

class TestPlaybookCreation:
    def test_playbook_step(self) -> None:
        step = PlaybookStep(
            name="test-step",
            technique=AttackTechnique.DIRECT_OVERRIDE,
            fault=Fault.prompt_injection("target"),
            expected_result=AttackResult.BLOCKED,
            description="A test step.",
        )
        assert step.name == "test-step"
        assert step.technique == AttackTechnique.DIRECT_OVERRIDE
        assert step.expected_result == AttackResult.BLOCKED

    def test_playbook_creation(self) -> None:
        pb = AdversarialPlaybook(
            playbook_id="test-pb",
            name="Test Playbook",
            description="A test playbook.",
            category="injection",
            severity="high",
            steps=[],
            tags=["test"],
        )
        assert pb.playbook_id == "test-pb"
        assert pb.category == "injection"
        assert pb.tags == ["test"]

    def test_playbook_with_steps(self) -> None:
        step = PlaybookStep(
            name="s1",
            technique=AttackTechnique.ENCODED_INJECTION,
            fault=Fault.prompt_injection("agent", "encoded"),
            expected_result=AttackResult.BLOCKED,
        )
        pb = AdversarialPlaybook(
            playbook_id="pb-1",
            name="PB",
            description="Desc",
            category="injection",
            severity="medium",
            steps=[step],
        )
        assert len(pb.steps) == 1
        assert pb.steps[0].technique == AttackTechnique.ENCODED_INJECTION


# ---------------------------------------------------------------------------
# Built-in playbooks
# ---------------------------------------------------------------------------

class TestBuiltinPlaybooks:
    def test_builtin_count(self) -> None:
        assert len(BUILTIN_PLAYBOOKS) == 5

    def test_builtin_ids(self) -> None:
        ids = {pb.playbook_id for pb in BUILTIN_PLAYBOOKS}
        assert "owasp-prompt-injection" in ids
        assert "owasp-privilege-escalation" in ids
        assert "data-exfiltration-campaign" in ids
        assert "tool-chain-abuse" in ids
        assert "multi-agent-collusion" in ids

    def test_builtin_categories(self) -> None:
        categories = {pb.category for pb in BUILTIN_PLAYBOOKS}
        assert "injection" in categories
        assert "escalation" in categories
        assert "exfiltration" in categories
        assert "collusion" in categories

    def test_each_builtin_has_steps(self) -> None:
        for pb in BUILTIN_PLAYBOOKS:
            assert len(pb.steps) >= 2, f"{pb.playbook_id} must have at least 2 steps"


# ---------------------------------------------------------------------------
# AdversarialRunner
# ---------------------------------------------------------------------------

class TestAdversarialRunner:
    @staticmethod
    def _make_experiment(faults: list[Fault] | None = None) -> ChaosExperiment:
        return ChaosExperiment(
            name="adversarial-test",
            target_agent="test-agent",
            faults=faults or [],
        )

    def test_runner_blocks_when_fault_registered(self) -> None:
        exp = self._make_experiment([Fault.prompt_injection("target")])
        runner = AdversarialRunner(exp)
        pb = BUILTIN_PLAYBOOKS[0]  # owasp-prompt-injection
        result = runner.run_playbook(pb)
        # All injection steps should be blocked
        assert all(passed for _, _, passed in result.step_results)
        assert result.resilience_score == 100.0
        assert result.passed is True

    def test_runner_bypasses_when_no_fault_registered(self) -> None:
        exp = self._make_experiment([])
        runner = AdversarialRunner(exp)
        pb = BUILTIN_PLAYBOOKS[0]  # owasp-prompt-injection
        result = runner.run_playbook(pb)
        assert all(not passed for _, _, passed in result.step_results)
        assert result.resilience_score == 0.0
        assert result.passed is False

    def test_run_all_returns_list(self) -> None:
        exp = self._make_experiment([Fault.prompt_injection("target")])
        runner = AdversarialRunner(exp)
        results = runner.run_all(BUILTIN_PLAYBOOKS)
        assert len(results) == len(BUILTIN_PLAYBOOKS)
        assert all(isinstance(r, PlaybookResult) for r in results)

    def test_partial_defence(self) -> None:
        # Register only prompt injection defence; escalation playbook has
        # mixed techniques so some steps bypass.
        exp = self._make_experiment([
            Fault.prompt_injection("target"),
        ])
        runner = AdversarialRunner(exp)
        # owasp-privilege-escalation has 3 steps: jailbreak (PROMPT_INJECTION
        # mapped), policy_manipulation (POLICY_BYPASS mapped), credential_theft
        # (PRIVILEGE_ESCALATION mapped). Only jailbreak defended.
        pb = BUILTIN_PLAYBOOKS[1]
        result = runner.run_playbook(pb)
        blocked = sum(1 for _, _, passed in result.step_results if passed)
        assert 0 < blocked < len(pb.steps)

    def test_full_defence_across_all_playbooks(self) -> None:
        # Register all adversarial fault types
        exp = self._make_experiment([
            Fault.prompt_injection("t"),
            Fault.policy_bypass("t"),
            Fault.privilege_escalation("t"),
            Fault.data_exfiltration("t"),
            Fault.tool_abuse("t"),
            Fault.identity_spoofing("t"),
        ])
        runner = AdversarialRunner(exp)
        results = runner.run_all(BUILTIN_PLAYBOOKS)
        assert all(r.passed for r in results)
        assert all(r.resilience_score == 100.0 for r in results)


# ---------------------------------------------------------------------------
# PlaybookResult scoring
# ---------------------------------------------------------------------------

class TestPlaybookResultScoring:
    def test_score_all_blocked(self) -> None:
        exp = ChaosExperiment(
            name="t", target_agent="a",
            faults=[Fault.prompt_injection("a")],
        )
        runner = AdversarialRunner(exp)
        result = runner.run_playbook(BUILTIN_PLAYBOOKS[0])
        assert result.resilience_score == 100.0
        assert result.passed is True

    def test_score_none_blocked(self) -> None:
        exp = ChaosExperiment(name="t", target_agent="a", faults=[])
        runner = AdversarialRunner(exp)
        result = runner.run_playbook(BUILTIN_PLAYBOOKS[0])
        assert result.resilience_score == 0.0
        assert result.passed is False

    def test_score_threshold(self) -> None:
        # 70% is passing; verify partial score below 70 fails
        exp = ChaosExperiment(
            name="t", target_agent="a",
            faults=[Fault.prompt_injection("a")],
        )
        runner = AdversarialRunner(exp)
        # owasp-privilege-escalation: 3 steps — only 1/3 blocked (33.3%)
        result = runner.run_playbook(BUILTIN_PLAYBOOKS[1])
        assert result.resilience_score < 70.0
        assert result.passed is False


# ---------------------------------------------------------------------------
# ChaosLibrary adversarial templates
# ---------------------------------------------------------------------------

class TestLibraryAdversarialTemplates:
    def test_adversarial_injection_template_exists(self) -> None:
        lib = ChaosLibrary()
        t = lib.get("adversarial-injection")
        assert t is not None
        assert t.category == "adversarial"
        assert t.severity == "high"

    def test_adversarial_escalation_template_exists(self) -> None:
        lib = ChaosLibrary()
        t = lib.get("adversarial-escalation")
        assert t is not None
        assert t.severity == "critical"

    def test_adversarial_exfiltration_template_exists(self) -> None:
        lib = ChaosLibrary()
        t = lib.get("adversarial-exfiltration")
        assert t is not None
        assert "exfiltration" in t.tags

    def test_list_adversarial_category(self) -> None:
        lib = ChaosLibrary()
        adversarial = lib.list_templates(category="adversarial")
        assert len(adversarial) == 3

    def test_adversarial_category_in_categories(self) -> None:
        lib = ChaosLibrary()
        assert "adversarial" in lib.categories()

    def test_instantiate_adversarial_template(self) -> None:
        lib = ChaosLibrary()
        exp = lib.instantiate("adversarial-injection", "my-agent")
        assert exp is not None
        assert exp.target_agent == "my-agent"
        assert len(exp.faults) == 1
        assert exp.faults[0].fault_type == FaultType.PROMPT_INJECTION
