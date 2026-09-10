# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for OPA/Rego policy adapter and PolicyEngine integration."""

import os
import shutil
import subprocess
from unittest.mock import patch

import pytest

from agentmesh.governance.opa import OPAEvaluator, OPADecision
from agentmesh.governance.policy import PolicyEngine

requires_opa = pytest.mark.skipif(
    not shutil.which("opa"), reason="opa CLI not installed"
)


# ── Sample Rego policies ──────────────────────────────────────

BASIC_REGO = """
package agentmesh

default allow = false

allow {
    input.agent.role == "admin"
}

allow {
    input.agent.role == "analyst"
    input.action == "read"
}
"""

PII_REGO = """
package agentmesh

default allow = false

allow {
    not input.data.contains_pii
}

allow {
    input.data.contains_pii
    input.agent.pii_access
}
"""

DENY_REGO = """
package agentmesh

default allow = true

allow {
    input.action != "delete"
}
"""

MULTI_CONDITION_REGO = """
package governance

default allow = false

allow {
    input.agent.role == "operator"
    input.action == "deploy"
    input.env == "staging"
}
"""


# ── OPAEvaluator: built-in evaluator tests ───────────────────

@requires_opa
class TestBuiltinEvaluator:
    """Test the built-in Rego parser (no OPA CLI needed)."""

    def test_admin_allowed(self):
        evaluator = OPAEvaluator(mode="local", rego_content=BASIC_REGO)
        result = evaluator.evaluate("data.agentmesh.allow", {"agent": {"role": "admin"}})
        assert result.allowed is True
        assert result.error is None

    def test_analyst_read_allowed(self):
        evaluator = OPAEvaluator(mode="local", rego_content=BASIC_REGO)
        result = evaluator.evaluate("data.agentmesh.allow", {
            "agent": {"role": "analyst"},
            "action": "read",
        })
        assert result.allowed is True

    def test_analyst_write_denied(self):
        evaluator = OPAEvaluator(mode="local", rego_content=BASIC_REGO)
        result = evaluator.evaluate("data.agentmesh.allow", {
            "agent": {"role": "analyst"},
            "action": "write",
        })
        assert result.allowed is False

    def test_unknown_role_denied(self):
        evaluator = OPAEvaluator(mode="local", rego_content=BASIC_REGO)
        result = evaluator.evaluate("data.agentmesh.allow", {
            "agent": {"role": "intern"},
        })
        assert result.allowed is False

    def test_pii_access_allowed(self):
        evaluator = OPAEvaluator(mode="local", rego_content=PII_REGO)
        result = evaluator.evaluate("data.agentmesh.allow", {
            "data": {"contains_pii": True},
            "agent": {"pii_access": True},
        })
        assert result.allowed is True

    def test_pii_no_access_denied(self):
        evaluator = OPAEvaluator(mode="local", rego_content=PII_REGO)
        result = evaluator.evaluate("data.agentmesh.allow", {
            "data": {"contains_pii": True},
            "agent": {"pii_access": False},
        })
        # Without pii_access, the second rule doesn't match,
        # and contains_pii is truthy so first rule doesn't match either
        assert result.allowed is False

    def test_no_pii_allowed(self):
        evaluator = OPAEvaluator(mode="local", rego_content=PII_REGO)
        result = evaluator.evaluate("data.agentmesh.allow", {
            "data": {"contains_pii": False},
            "agent": {},
        })
        assert result.allowed is True

    def test_not_equal_condition(self):
        evaluator = OPAEvaluator(mode="local", rego_content=DENY_REGO)
        result = evaluator.evaluate("data.agentmesh.allow", {"action": "read"})
        assert result.allowed is True

    def test_multi_condition_match(self):
        evaluator = OPAEvaluator(mode="local", rego_content=MULTI_CONDITION_REGO)
        result = evaluator.evaluate("data.governance.allow", {
            "agent": {"role": "operator"},
            "action": "deploy",
            "env": "staging",
        })
        assert result.allowed is True

    def test_multi_condition_partial_miss(self):
        evaluator = OPAEvaluator(mode="local", rego_content=MULTI_CONDITION_REGO)
        result = evaluator.evaluate("data.governance.allow", {
            "agent": {"role": "operator"},
            "action": "deploy",
            "env": "production",  # not staging
        })
        assert result.allowed is False

    def test_evaluation_timing(self):
        evaluator = OPAEvaluator(mode="local", rego_content=BASIC_REGO)
        result = evaluator.evaluate("data.agentmesh.allow", {"agent": {"role": "admin"}})
        assert result.evaluation_ms >= 0
        assert result.evaluation_ms < 100  # should be well under 100ms

    def test_source_is_local(self):
        evaluator = OPAEvaluator(mode="local", rego_content=BASIC_REGO)
        result = evaluator.evaluate("data.agentmesh.allow", {"agent": {"role": "admin"}})
        assert result.source == "local"


# ── OPADecision model ────────────────────────────────────────

class TestOPADecision:
    def test_default_values(self):
        d = OPADecision(allowed=True)
        assert d.allowed is True
        assert d.error is None
        assert d.source == "local"
        assert d.evaluation_ms == 0.0

    def test_error_decision(self):
        d = OPADecision(allowed=False, error="timeout", source="remote")
        assert d.allowed is False
        assert d.error == "timeout"
        assert d.source == "remote"


# ── PolicyEngine + Rego integration ──────────────────────────

@requires_opa
class TestPolicyEngineRegoIntegration:
    """Test that load_rego works alongside YAML policies."""

    def test_load_rego_returns_evaluator(self):
        engine = PolicyEngine()
        evaluator = engine.load_rego(rego_content=BASIC_REGO)
        assert isinstance(evaluator, OPAEvaluator)

    def test_rego_allows_admin(self):
        engine = PolicyEngine()
        engine.load_rego(rego_content=BASIC_REGO, package="agentmesh")
        decision = engine.evaluate("did:mesh:any", {"agent": {"role": "admin"}})
        assert decision.allowed is True
        assert "OPA/Rego" in decision.reason

    def test_rego_denies_unknown(self):
        engine = PolicyEngine()
        engine.load_rego(rego_content=BASIC_REGO, package="agentmesh")
        decision = engine.evaluate("did:mesh:any", {"agent": {"role": "intern"}})
        assert decision.allowed is False

    def test_yaml_takes_precedence_over_rego(self):
        """YAML rules are evaluated first; if they match, Rego is skipped."""
        engine = PolicyEngine()

        # Load a YAML policy that denies everything for agent "did:mesh:blocked"
        yaml_policy = """
version: "1.0"
name: block-policy
agents:
  - "did:mesh:blocked"
rules:
  - name: block-all
    condition: "action.type == 'read'"
    action: deny
"""
        engine.load_yaml(yaml_policy)

        # Load a Rego policy that would allow admin
        engine.load_rego(rego_content=BASIC_REGO, package="agentmesh")

        # YAML deny should take precedence
        decision = engine.evaluate("did:mesh:blocked", {
            "action": {"type": "read"},
            "agent": {"role": "admin"},
        })
        assert decision.allowed is False
        assert decision.matched_rule == "block-all"

    def test_rego_consulted_when_yaml_no_match(self):
        """If no YAML rule matches, Rego is consulted."""
        engine = PolicyEngine()

        yaml_policy = """
version: "1.0"
name: narrow-policy
agents:
  - "did:mesh:specific"
rules:
  - name: specific-rule
    condition: "action.type == 'deploy'"
    action: deny
"""
        engine.load_yaml(yaml_policy)
        engine.load_rego(rego_content=BASIC_REGO, package="agentmesh")

        # This agent is not targeted by YAML, so Rego is consulted
        decision = engine.evaluate("did:mesh:other", {"agent": {"role": "admin"}})
        assert decision.allowed is True
        assert "OPA/Rego" in decision.reason

    def test_multiple_rego_evaluators(self):
        engine = PolicyEngine()
        engine.load_rego(rego_content=BASIC_REGO, package="agentmesh")
        engine.load_rego(rego_content=MULTI_CONDITION_REGO, package="governance")

        # First evaluator should match admin
        decision = engine.evaluate("did:mesh:any", {"agent": {"role": "admin"}})
        assert decision.allowed is True


# ── Edge cases ────────────────────────────────────────────────

@requires_opa
class TestEdgeCases:
    def test_empty_rego_content(self):
        evaluator = OPAEvaluator(mode="local", rego_content="")
        result = evaluator.evaluate("data.agentmesh.allow", {})
        assert result.allowed is False

    def test_no_rego_no_path(self):
        evaluator = OPAEvaluator(mode="local")
        result = evaluator.evaluate("data.agentmesh.allow", {})
        assert result.allowed is False
        assert result.error is not None

    def test_nonexistent_rego_file(self):
        evaluator = OPAEvaluator(mode="local", rego_path="/nonexistent/policy.rego")
        result = evaluator.evaluate("data.agentmesh.allow", {})
        assert result.allowed is False

    def test_invalid_query_target(self):
        evaluator = OPAEvaluator(mode="local", rego_content=BASIC_REGO)
        # Querying a rule that doesn't exist returns default False
        result = evaluator.evaluate("data.agentmesh.nonexistent", {})
        assert result.allowed is False

    def test_empty_input(self):
        evaluator = OPAEvaluator(mode="local", rego_content=BASIC_REGO)
        result = evaluator.evaluate("data.agentmesh.allow", {})
        assert result.allowed is False

    def test_remote_mode_unreachable(self):
        """Remote mode with no server should fail gracefully."""
        evaluator = OPAEvaluator(mode="remote", opa_url="http://localhost:99999")
        result = evaluator.evaluate("data.agentmesh.allow", {"agent": {"role": "admin"}})
        assert result.allowed is False
        assert result.error is not None


# ── OPAEvaluator: rego_content materialization (no opa needed) ──────
#
# Pure file-handling behaviour, independent of whether opa itself is
# installed: rego_content used to be rewritten to a fresh
# NamedTemporaryFile(delete=False) on every evaluate() call and never
# cleaned up, leaking one 0600 file per governed call for the life of the
# process.


class TestRegoContentMaterialization:
    def test_same_path_reused_across_calls(self):
        evaluator = OPAEvaluator(mode="local", rego_content=BASIC_REGO)
        first = evaluator._rego_file_for_cli()
        second = evaluator._rego_file_for_cli()
        assert first == second
        assert os.path.isfile(first)
        evaluator.close()

    def test_close_removes_the_temp_file(self):
        evaluator = OPAEvaluator(mode="local", rego_content=BASIC_REGO)
        path = evaluator._rego_file_for_cli()
        assert os.path.isfile(path)
        evaluator.close()
        assert not os.path.exists(path)

    def test_rego_path_is_used_directly_no_temp_file_created(self, tmp_path):
        rego_file = tmp_path / "policy.rego"
        rego_file.write_text(BASIC_REGO)
        evaluator = OPAEvaluator(mode="local", rego_path=str(rego_file))
        assert evaluator._rego_file_for_cli() == str(rego_file)
        evaluator.close()
        assert rego_file.exists()  # close() must not remove a caller-owned file


# ── PolicyEngine.load_rego(): fail fast at construction ──────────────
#
# These don't need opa installed: a missing rego_path and a declared
# package that doesn't match `package=` are caught before OPAEvaluator
# (and therefore the opa CLI) ever enters the picture.


class TestLoadRegoValidation:
    def test_missing_source_raises(self):
        engine = PolicyEngine()
        with pytest.raises(ValueError, match="rego_path or rego_content"):
            engine.load_rego()

    def test_missing_path_raises(self):
        engine = PolicyEngine()
        with pytest.raises(FileNotFoundError):
            engine.load_rego(rego_path="/nonexistent/policy.rego")

    def test_package_mismatch_raises(self):
        """BASIC_REGO declares `package agentmesh`; asking for a different
        package means data.<package>.allow could never resolve against it —
        the exact silent-misconfiguration the review flagged."""
        engine = PolicyEngine()
        with pytest.raises(ValueError, match="declares package 'agentmesh'"):
            engine.load_rego(rego_content=BASIC_REGO, package="wrong_package")

    def test_missing_opa_raises(self, monkeypatch):
        """Deterministic regardless of whether opa happens to be installed
        on the machine running this test."""
        monkeypatch.setattr(shutil, "which", lambda _name: None)
        engine = PolicyEngine()
        with pytest.raises(RuntimeError, match="opa CLI not found"):
            engine.load_rego(rego_content=BASIC_REGO, package="agentmesh")

    def test_both_path_and_content_raises(self, tmp_path):
        """rego_path silently won over rego_content at evaluation time
        (OPAEvaluator._rego_file_for_cli prefers rego_path) with no
        indication rego_content was ignored - now a load-time error."""
        rego_file = tmp_path / "policy.rego"
        rego_file.write_text(BASIC_REGO)
        engine = PolicyEngine()
        with pytest.raises(ValueError, match="both rego_path and rego_content"):
            engine.load_rego(rego_path=str(rego_file), rego_content=BASIC_REGO, package="agentmesh")

    def test_empty_rego_path_raises(self):
        """"" is falsy like None; without this check it silently skips
        Rego (govern.py's `is not None` wiring still calls load_rego, but
        used to collapse "" into the "nothing given" branch here too)."""
        engine = PolicyEngine()
        with pytest.raises(ValueError, match="rego_path must not be an empty string"):
            engine.load_rego(rego_path="", package="agentmesh")

    def test_empty_rego_content_raises(self):
        engine = PolicyEngine()
        with pytest.raises(ValueError, match="rego_content must not be an empty string"):
            engine.load_rego(rego_content="", package="agentmesh")

    def test_rego_path_directory_passes_existence_check(self, tmp_path, monkeypatch):
        """A directory of .rego files is a valid `opa eval --data` target
        and worked as rego_path on main; os.path.isfile briefly rejected it
        outright. Deterministic regardless of whether opa is installed: with
        it forced absent, a directory that passed the existence check must
        fail on the *next* check (opa missing), not FileNotFoundError."""
        monkeypatch.setattr(shutil, "which", lambda _name: None)
        engine = PolicyEngine()
        with pytest.raises(RuntimeError, match="opa CLI not found"):
            engine.load_rego(rego_path=str(tmp_path), package="agentmesh")

    @requires_opa
    def test_rego_path_directory_loads_and_evaluates(self, tmp_path):
        (tmp_path / "policy.rego").write_text(BASIC_REGO)
        engine = PolicyEngine()
        evaluator = engine.load_rego(rego_path=str(tmp_path), package="agentmesh")
        assert isinstance(evaluator, OPAEvaluator)
        decision = evaluator.evaluate("data.agentmesh.allow", {"agent": {"role": "admin"}})
        assert decision.allowed is True

    @requires_opa
    def test_matching_package_succeeds(self):
        engine = PolicyEngine()
        evaluator = engine.load_rego(rego_content=BASIC_REGO, package="agentmesh")
        assert isinstance(evaluator, OPAEvaluator)

    @requires_opa
    def test_bad_syntax_raises_at_load_not_at_first_call(self):
        engine = PolicyEngine()
        with pytest.raises(ValueError, match="failed to compile"):
            engine.load_rego(rego_content="package agentmesh\n\nallow { {{{ not rego", package="agentmesh")


# ── PolicyEngine.evaluate(): a Rego evaluator error must deny ───────
#
# A stub evaluator lets this run without opa: it exercises PolicyEngine's
# own branch (opa_result.error is not None -> deny), not OPAEvaluator's
# subprocess plumbing.


class _ErroringEvaluator:
    def evaluate(self, query, input_data):
        return OPADecision(allowed=True, query=query, source="local", error="opa eval timed out")


class TestRegoErrorFailsClosed:
    def test_evaluator_error_denies_rather_than_falling_through_to_default_allow(self):
        engine = PolicyEngine()
        allow_all_yaml = """
apiVersion: governance.toolkit/v1
name: allow-all
default_action: allow
rules: []
"""
        engine.load_yaml(allow_all_yaml)
        engine._rego_evaluators.append(("agentmesh", _ErroringEvaluator()))

        decision = engine.evaluate("did:mesh:any", {"action": {"type": "read"}})

        # Before the fix this fell through past the broken evaluator to the
        # allow-all YAML default and executed with no record of the error.
        assert decision.allowed is False
        assert "opa eval timed out" in decision.reason


# ── OPAEvaluator: compile errors must not report an empty reason ────
#
# opa prints parse/compile errors as JSON to stdout with stderr empty
# (exit 2); only runtime/usage errors go to stderr. Reporting stderr alone
# left compile errors with an empty ("opa eval failed: ") reason. Mocking
# subprocess.run makes this deterministic regardless of whether opa is
# actually installed.


class TestCompileErrorMessage:
    def test_stdout_used_when_stderr_is_empty(self, monkeypatch):
        monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/opa")
        evaluator = OPAEvaluator(mode="local", rego_content=BASIC_REGO)

        fake_proc = subprocess.CompletedProcess(
            args=["opa"], returncode=2, stdout='{"errors": ["1 error occurred: policy.rego:3: rego_parse_error"]}', stderr="",
        )
        with patch("agentmesh.governance.opa.subprocess.run", return_value=fake_proc):
            decision = evaluator.evaluate("true", {})

        assert decision.error is not None
        assert "rego_parse_error" in decision.error
        evaluator.close()

    def test_stderr_preferred_when_present(self, monkeypatch):
        monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/opa")
        evaluator = OPAEvaluator(mode="local", rego_content=BASIC_REGO)

        fake_proc = subprocess.CompletedProcess(
            args=["opa"], returncode=1, stdout="", stderr="usage: opa eval ...",
        )
        with patch("agentmesh.governance.opa.subprocess.run", return_value=fake_proc):
            decision = evaluator.evaluate("true", {})

        assert decision.error is not None
        assert "usage: opa eval" in decision.error
        evaluator.close()
