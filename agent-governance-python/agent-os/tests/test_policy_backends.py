# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for OPA and Cedar policy backends in Agent-OS."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_os.policies.backends import (
    BackendDecision,
    CedarBackend,
    ExternalPolicyBackend,
    OPABackend,
)
from agent_os.policies.evaluator import PolicyDecision, PolicyEvaluator
from agent_os.policies.schema import (
    PolicyAction,
    PolicyCondition,
    PolicyDocument,
    PolicyOperator,
    PolicyRule,
)


# ── OPA Backend Tests ─────────────────────────────────────────


class TestOPABackend:
    """Tests for the built-in OPA/Rego evaluator."""

    SIMPLE_REGO = """
package agentos

default allow = false

allow {
    input.tool_name == "file_read"
}

allow {
    input.role == "admin"
}
"""

    DENY_REGO = """
package agentos

default allow = false
"""

    def test_opa_backend_implements_protocol(self):
        backend = OPABackend(rego_content=self.SIMPLE_REGO)
        assert isinstance(backend, ExternalPolicyBackend)
        assert backend.name == "opa"

    def test_opa_allow_matching_rule(self):
        backend = OPABackend(rego_content=self.SIMPLE_REGO)
        decision = backend.evaluate({"tool_name": "file_read"})
        assert decision.allowed is True
        assert decision.backend == "opa"
        assert decision.error is None

    def test_opa_allow_admin_role(self):
        backend = OPABackend(rego_content=self.SIMPLE_REGO)
        decision = backend.evaluate({"tool_name": "anything", "role": "admin"})
        assert decision.allowed is True

    def test_opa_deny_no_match(self):
        backend = OPABackend(rego_content=self.SIMPLE_REGO)
        decision = backend.evaluate({"tool_name": "file_delete", "role": "user"})
        assert decision.allowed is False

    def test_opa_deny_default_false(self):
        backend = OPABackend(rego_content=self.DENY_REGO)
        decision = backend.evaluate({"tool_name": "anything"})
        assert decision.allowed is False

    def test_opa_evaluation_ms_tracked(self):
        backend = OPABackend(rego_content=self.SIMPLE_REGO)
        decision = backend.evaluate({"tool_name": "file_read"})
        assert decision.evaluation_ms >= 0

    def test_opa_no_content_returns_error(self):
        backend = OPABackend()
        decision = backend.evaluate({"tool_name": "test"})
        assert decision.allowed is False
        assert decision.error is not None

    def test_opa_not_condition(self):
        rego = """
package agentos

default allow = false

allow {
    not input.is_dangerous
}
"""
        backend = OPABackend(rego_content=rego)
        assert backend.evaluate({"is_dangerous": False}).allowed is True
        assert backend.evaluate({"is_dangerous": True}).allowed is False

    def test_opa_ne_condition(self):
        rego = """
package agentos

default allow = false

allow {
    input.tool_name != "file_delete"
}
"""
        backend = OPABackend(rego_content=rego)
        assert backend.evaluate({"tool_name": "file_read"}).allowed is True
        assert backend.evaluate({"tool_name": "file_delete"}).allowed is False

    def test_opa_multiline_rule(self):
        rego = """
package agentos

default allow = false

allow {
    input.role == "analyst"
    input.tool_name == "read_data"
}
"""
        backend = OPABackend(rego_content=rego)
        assert backend.evaluate({"role": "analyst", "tool_name": "read_data"}).allowed is True
        assert backend.evaluate({"role": "analyst", "tool_name": "write_data"}).allowed is False
        assert backend.evaluate({"role": "user", "tool_name": "read_data"}).allowed is False

    def test_opa_custom_package(self):
        rego = """
package custom

default allow = false

allow {
    input.role == "analyst"
}
"""
        backend = OPABackend(rego_content=rego, package="custom")
        decision = backend.evaluate({"role": "analyst"})
        assert decision.allowed is True

    def test_opa_cli_uses_stdin_input_flag_not_dev_stdin(self, monkeypatch):
        """Regression: the CLI invocation must not depend on /dev/stdin
        (which doesn't exist on Windows) and must keep the rego file
        inside a per-invocation TemporaryDirectory rather than a
        umask-controlled NamedTemporaryFile.
        """
        captured: dict[str, object] = {}

        class _FakeProc:
            returncode = 0
            stdout = '{"result":[{"expressions":[{"value":true}]}]}'
            stderr = ""

        def _fake_run(cmd, **kwargs):
            captured["cmd"] = list(cmd)
            captured["kwargs"] = kwargs
            # Confirm the rego file existed during the call
            data_idx = cmd.index("--data")
            captured["rego_existed"] = Path(cmd[data_idx + 1]).is_file()
            captured["rego_content"] = Path(cmd[data_idx + 1]).read_text()
            return _FakeProc()

        from agent_os.policies import backends as backends_mod
        monkeypatch.setattr(backends_mod, "shutil", backends_mod.shutil)
        # Force CLI path: pretend opa is available, no Python opa lib
        monkeypatch.setattr(backends_mod.shutil, "which", lambda name: "/usr/local/bin/opa")
        monkeypatch.setattr(backends_mod.subprocess, "run", _fake_run)

        backend = OPABackend(rego_content=self.SIMPLE_REGO)
        # Force CLI path even if python opa lib is installed
        backend._opa_lib = None  # type: ignore[attr-defined]
        backend._opa_cli_available = True  # type: ignore[attr-defined]

        decision = backend._evaluate_cli({"tool_name": "file_read"})
        assert decision.allowed is True
        cmd = captured["cmd"]
        assert "--stdin-input" in cmd
        assert "/dev/stdin" not in cmd
        assert captured["rego_existed"] is True
        assert "package agentos" in captured["rego_content"]
        # After the with-block exits, the tempdir is cleaned up
        data_idx = cmd.index("--data")
        assert not Path(cmd[data_idx + 1]).exists()


# ── Cedar Backend Tests ───────────────────────────────────────


class TestCedarBackend:
    """Tests for the built-in Cedar evaluator."""

    SIMPLE_POLICY = """
permit(
    principal,
    action == Action::"ReadData",
    resource
);

permit(
    principal,
    action == Action::"ListFiles",
    resource
);

forbid(
    principal,
    action == Action::"DeleteFile",
    resource
);
"""

    PERMIT_ALL = """
permit(
    principal,
    action,
    resource
);
"""

    def test_cedar_backend_implements_protocol(self):
        backend = CedarBackend(policy_content=self.SIMPLE_POLICY)
        assert isinstance(backend, ExternalPolicyBackend)
        assert backend.name == "cedar"

    def test_cedar_permit_matching_action(self):
        backend = CedarBackend(policy_content=self.SIMPLE_POLICY)
        decision = backend.evaluate({"tool_name": "read_data", "agent_id": "a1"})
        assert decision.allowed is True
        assert decision.backend == "cedar"
        assert decision.error is None

    def test_cedar_forbid_matching_action(self):
        backend = CedarBackend(policy_content=self.SIMPLE_POLICY)
        decision = backend.evaluate({"tool_name": "delete_file", "agent_id": "a1"})
        assert decision.allowed is False

    def test_cedar_default_deny_no_match(self):
        backend = CedarBackend(policy_content=self.SIMPLE_POLICY)
        decision = backend.evaluate({"tool_name": "execute_code", "agent_id": "a1"})
        assert decision.allowed is False

    def test_cedar_permit_all_catchall(self):
        backend = CedarBackend(policy_content=self.PERMIT_ALL)
        decision = backend.evaluate({"tool_name": "anything", "agent_id": "a1"})
        assert decision.allowed is True

    def test_cedar_evaluation_ms_tracked(self):
        backend = CedarBackend(policy_content=self.SIMPLE_POLICY)
        decision = backend.evaluate({"tool_name": "read_data", "agent_id": "a1"})
        assert decision.evaluation_ms >= 0

    def test_cedar_no_content_returns_error(self):
        backend = CedarBackend()
        decision = backend.evaluate({"tool_name": "test"})
        assert decision.allowed is False
        assert decision.error is not None

    def test_cedar_list_files_action(self):
        backend = CedarBackend(policy_content=self.SIMPLE_POLICY)
        decision = backend.evaluate({"tool_name": "list_files", "agent_id": "a1"})
        assert decision.allowed is True

    def test_cedar_tool_name_to_action_mapping(self):
        """Verify snake_case tool names map to PascalCase Cedar actions."""
        from agent_os.policies.backends import _tool_to_cedar_action

        assert _tool_to_cedar_action("read_data") == "ReadData"
        assert _tool_to_cedar_action("delete_file") == "DeleteFile"
        assert _tool_to_cedar_action("execute_code") == "ExecuteCode"
        assert _tool_to_cedar_action("list") == "List"

    def test_cedar_parse_statements(self):
        """Verify Cedar statement parsing."""
        from agent_os.policies.backends import _parse_cedar_statements

        stmts = _parse_cedar_statements(self.SIMPLE_POLICY)
        assert len(stmts) == 3
        assert stmts[0]["effect"] == "permit"
        assert stmts[0]["action_constraint"] == 'Action::"ReadData"'
        assert stmts[2]["effect"] == "forbid"
        assert stmts[2]["action_constraint"] == 'Action::"DeleteFile"'


class TestCedarDecisionFromCliOutput:
    """Regression tests for the Cedar CLI decision parser.

    The previous parser used ``"allow" in stdout and "deny" not in stdout``
    on the lowercased output — a substring sniff that gets fooled by
    diagnostic phrases like ``DENY (request disallowed by policy)`` or
    ``ALLOW: caveats reference the deny-list scoping``. The new parser only
    accepts the first non-empty line being a bare ``ALLOW`` or ``DENY``
    token (case-insensitive); anything else returns ``parsed=False`` so the
    caller can fail closed.
    """

    @pytest.mark.parametrize("stdout", [
        "ALLOW\n",
        "ALLOW",
        "allow",
        "  ALLOW  \n",
        "\n\nALLOW\n",  # leading blank lines tolerated
    ])
    def test_recognises_bare_allow_token(self, stdout: str) -> None:
        from agent_os.policies.backends import _cedar_decision_from_cli_output

        allowed, parsed = _cedar_decision_from_cli_output(stdout)
        assert parsed is True
        assert allowed is True

    @pytest.mark.parametrize("stdout", [
        "DENY\n",
        "DENY",
        "deny",
        "  DENY  \n",
        "\n\nDENY\n",
    ])
    def test_recognises_bare_deny_token(self, stdout: str) -> None:
        from agent_os.policies.backends import _cedar_decision_from_cli_output

        allowed, parsed = _cedar_decision_from_cli_output(stdout)
        assert parsed is True
        assert allowed is False

    @pytest.mark.parametrize("stdout,description", [
        ("DENY (request disallowed by policy)\n",
         "first-line adjective phrase: contains 'allow' as substring of 'disallowed'"),
        ("ALLOW: caveats reference the deny-list scoping\n",
         "first-line adjective phrase: contains 'deny' as substring of 'deny-list'"),
        ("", "empty stdout"),
        ("\n\n  \n", "whitespace-only stdout"),
        ("Decision: allow\n", "labelled decision, not a bare token"),
        ("authorization failed\n", "garbage output"),
        ("garbage line 1\nALLOW\n", "first line is garbage; second is ALLOW"),
    ])
    def test_rejects_ambiguous_output(self, stdout: str, description: str) -> None:
        from agent_os.policies.backends import _cedar_decision_from_cli_output

        allowed, parsed = _cedar_decision_from_cli_output(stdout)
        assert parsed is False, description
        assert allowed is False, description


class TestCedarBackendCliPath:
    """End-to-end test that `_evaluate_cli` routes through the new parser
    and fails closed on ambiguous output.
    """

    SIMPLE_POLICY = 'permit(principal, action == Action::"ReadData", resource);'

    def test_cli_allow_decision(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from agent_os.policies import backends as backends_mod

        class _FakeProc:
            stdout = "ALLOW\n"
            stderr = ""

        monkeypatch.setattr(
            backends_mod.subprocess, "run",
            lambda *_a, **_kw: _FakeProc(),
        )
        backend = CedarBackend(policy_content=self.SIMPLE_POLICY)
        decision = backend._evaluate_cli({"tool_name": "read_data", "agent_id": "a1"})
        assert decision.allowed is True
        assert decision.error is None

    def test_cli_deny_decision(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from agent_os.policies import backends as backends_mod

        class _FakeProc:
            stdout = "DENY\n"
            stderr = ""

        monkeypatch.setattr(
            backends_mod.subprocess, "run",
            lambda *_a, **_kw: _FakeProc(),
        )
        backend = CedarBackend(policy_content=self.SIMPLE_POLICY)
        decision = backend._evaluate_cli({"tool_name": "read_data", "agent_id": "a1"})
        assert decision.allowed is False

    def test_cli_fails_closed_on_ambiguous_output(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The old parser flipped the verdict on adjective phrases. The new
        parser refuses to interpret them and fails closed with an explicit
        error.
        """
        from agent_os.policies import backends as backends_mod

        class _FakeProc:
            # Would have classified as ALLOW under the old "allow in output"
            # check because of "disallowed". New behaviour: deny + error.
            stdout = "DENY (request disallowed by policy)\n"
            stderr = ""

        monkeypatch.setattr(
            backends_mod.subprocess, "run",
            lambda *_a, **_kw: _FakeProc(),
        )
        backend = CedarBackend(policy_content=self.SIMPLE_POLICY)
        decision = backend._evaluate_cli({"tool_name": "read_data", "agent_id": "a1"})
        assert decision.allowed is False
        assert decision.error == "unrecognised cedar CLI output"


# ── PolicyEvaluator Integration Tests ─────────────────────────


class TestPolicyEvaluatorWithBackends:
    """Tests for PolicyEvaluator with external backends."""

    def _make_yaml_policy(self, tool: str, action: PolicyAction) -> PolicyDocument:
        return PolicyDocument(
            name="test-yaml",
            rules=[
                PolicyRule(
                    name="yaml-rule",
                    condition=PolicyCondition(
                        field="tool_name",
                        operator=PolicyOperator.EQ,
                        value=tool,
                    ),
                    action=action,
                    priority=100,
                ),
            ],
        )

    def test_yaml_takes_precedence_over_opa(self):
        """YAML rules are checked before OPA backends."""
        evaluator = PolicyEvaluator(
            policies=[self._make_yaml_policy("file_read", PolicyAction.DENY)]
        )
        evaluator.load_rego(rego_content="""
package agentos
default allow = true
""")
        decision = evaluator.evaluate({"tool_name": "file_read"})
        assert decision.allowed is False
        assert decision.matched_rule == "yaml-rule"

    def test_opa_backend_consulted_when_no_yaml_match(self):
        """OPA backend is consulted when no YAML rule matches."""
        evaluator = PolicyEvaluator(
            policies=[self._make_yaml_policy("file_read", PolicyAction.DENY)]
        )
        evaluator.load_rego(rego_content="""
package agentos
default allow = false
allow {
    input.tool_name == "web_search"
}
""")
        decision = evaluator.evaluate({"tool_name": "web_search"})
        assert decision.allowed is True
        assert "opa" in decision.audit_entry.get("backend", "opa")

    def test_cedar_backend_consulted_when_no_yaml_match(self):
        """Cedar backend is consulted when no YAML rule matches."""
        evaluator = PolicyEvaluator(
            policies=[self._make_yaml_policy("file_read", PolicyAction.DENY)]
        )
        evaluator.load_cedar(policy_content="""
permit(
    principal,
    action == Action::"WebSearch",
    resource
);
""")
        decision = evaluator.evaluate({"tool_name": "web_search"})
        assert decision.allowed is True
        assert "cedar" in decision.audit_entry.get("backend", "cedar")

    def test_multiple_backends_checked_in_order(self):
        """Backends are checked in registration order."""
        evaluator = PolicyEvaluator()

        # OPA denies everything
        evaluator.load_rego(rego_content="""
package agentos
default allow = false
""")
        # Cedar would allow — but OPA runs first
        evaluator.load_cedar(policy_content="""
permit(principal, action, resource);
""")
        decision = evaluator.evaluate({"tool_name": "anything"})
        assert decision.allowed is False

    def test_backend_decision_includes_audit_entry(self):
        """Backend decisions include audit information."""
        evaluator = PolicyEvaluator()
        evaluator.load_rego(rego_content="""
package agentos
default allow = true
""")
        decision = evaluator.evaluate({"tool_name": "test"})
        assert "external:opa" in decision.audit_entry.get("policy", "")
        assert "evaluation_ms" in decision.audit_entry

    def test_default_action_when_no_backends(self):
        """Default action applies when no policies or backends match."""
        evaluator = PolicyEvaluator()
        decision = evaluator.evaluate({"tool_name": "anything"})
        assert decision.allowed is True
        assert "default" in decision.reason.lower()

    def test_load_rego_returns_backend(self):
        evaluator = PolicyEvaluator()
        backend = evaluator.load_rego(rego_content="package agentos\ndefault allow = true")
        assert backend.name == "opa"

    def test_load_cedar_returns_backend(self):
        evaluator = PolicyEvaluator()
        backend = evaluator.load_cedar(
            policy_content='permit(principal, action, resource);'
        )
        assert backend.name == "cedar"
