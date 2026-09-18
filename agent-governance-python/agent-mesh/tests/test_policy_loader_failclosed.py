# Copyright (c) Microsoft Corporation. Licensed under the MIT License.
"""Regression tests for issue #3538 / review feedback on PR #3660.

The sidecar (``agentmesh.server.sidecar``) and policy server
(``agentmesh.server.policy_server``) load every ``*.yaml``/``*.json`` file from a
configured directory. Previously a file that failed to load was logged at
warning level and skipped, so the server served decisions without it; if the
dropped file was a deny and a broader allow also loaded, the effective outcome
flipped to allow (fail-open by absence).

Per review feedback on #3660 strict fail-closed is now **opt-in** (default off)
so a shipped deployment carrying one unparseable policy file keeps serving a
degraded set instead of crash-looping:

  * sidecar  — primary ``AGT_POLICY_STRICT`` (matches ``AGT_POLICY_DIR``);
  * policy_server — primary ``AGENTMESH_POLICY_STRICT`` (matches
    ``AGENTMESH_POLICY_DIR``);
  * both accept the other name as an alias, and both fail closed when the
    policy directory is missing/unavailable (not just on a per-file parse
    error). A governance-shaped file (top-level ``kind``/``apiVersion``) or a
    rule-less trust policy is treated as a load failure rather than being
    silently accepted as an empty trust policy.
"""

from __future__ import annotations

import pytest

_VALID_POLICY = (
    "name: test-policy\n"
    "version: '1.0'\n"
    "rules:\n"
    "  - name: deny-shell\n"
    "    condition: \"action == 'shell.execute'\"\n"
    "    action: deny\n"
)

# Unclosed flow sequence: yaml.safe_load raises, so this parses as neither a
# governance policy nor a trust policy.
_BAD_POLICY = "policy: [1, 2\n"

# Unterminated object: json.loads raises, so load_json rejects it. The JSON
# branch has no trust fallback, so this drives the failure handler directly.
_BAD_JSON = '{"policy": [1, 2\n'

# Governance-shaped file with an unsupported apiVersion. It fails governance
# parsing (apiVersion not recognised) but, because it carries a top-level
# ``name``, it satisfies the permissive TrustPolicy schema as a rule-less trust
# policy. Before the fix the trust fallback silently accepted it, quietly
# dropping a governance policy. It must now be treated as a load failure.
_GOVERNANCE_SHAPED = (
    "apiVersion: agentmesh.io/v1alpha1\n"
    "kind: GovernancePolicy\n"
    "name: default\n"
    "rules: []\n"
)

# Governance document with NO top-level kind/apiVersion but a non-empty, string
# -condition ``rules`` list, made to fail governance parsing via an invalid
# rate-limit. Its rules use string conditions, which the trust schema (which
# requires a structured TrustCondition mapping per rule) cannot accept — so it
# must be routed to the load-failure handler, not misclassified as trust.
_GOVERNANCE_RULES_BAD_LIMIT = (
    "name: gov-with-bad-limit\n"
    "rules:\n"
    "  - name: r1\n"
    "    condition: \"action == 'file.read'\"\n"
    "    action: deny\n"
    "    limit: not-a-valid-rate-limit\n"
)


def _write(dir_path, name, content):
    (dir_path / name).write_text(content)


@pytest.fixture(autouse=True)
def _clear_strict_env(monkeypatch):
    """Start every test hermetic: neither strict toggle set (both are honoured
    by each component now, so a leaked alias would otherwise flip behaviour)."""
    monkeypatch.delenv("AGT_POLICY_STRICT", raising=False)
    monkeypatch.delenv("AGENTMESH_POLICY_STRICT", raising=False)


class TestSidecarLoaderFailClosed:
    """sidecar uses main's PolicyLoadGeneration model; strict is opt-in."""

    @staticmethod
    def _sidecar():
        import agentmesh.server.sidecar as sidecar

        return sidecar

    def test_default_serves_degraded_without_raising(self, tmp_path, monkeypatch):
        # (a) With no env set, an unloadable file must NOT raise: the loader
        # publishes a degraded generation and keeps serving.
        _write(tmp_path, "good.yaml", _VALID_POLICY)
        _write(tmp_path, "bad.yaml", _BAD_POLICY)
        monkeypatch.setenv("AGT_POLICY_DIR", str(tmp_path))
        sidecar = self._sidecar()
        gen = sidecar._load_policies()  # must not raise
        assert gen.policies_failed == 1
        assert gen.policies_loaded == 1
        assert gen.policy_set_status == "degraded"
        # The degraded generation is actually published for serving.
        assert sidecar._policy_state[1] is gen

    def test_strict_opt_in_raises_on_unloadable_file(self, tmp_path, monkeypatch):
        # (b) With AGT_POLICY_STRICT set, a directory with an unloadable file
        # must raise so the server refuses to serve a silently weakened set.
        _write(tmp_path, "good.yaml", _VALID_POLICY)
        _write(tmp_path, "bad.yaml", _BAD_POLICY)
        monkeypatch.setenv("AGT_POLICY_DIR", str(tmp_path))
        monkeypatch.setenv("AGT_POLICY_STRICT", "1")
        sidecar = self._sidecar()
        with pytest.raises(RuntimeError, match="strict policy load failed"):
            sidecar._load_policies()

    @pytest.mark.parametrize("value", ["true", "yes", "on", "1"])
    def test_strict_truthy_values_enable_failclosed(
        self, tmp_path, monkeypatch, value
    ):
        _write(tmp_path, "bad.yaml", _BAD_POLICY)
        monkeypatch.setenv("AGT_POLICY_DIR", str(tmp_path))
        monkeypatch.setenv("AGT_POLICY_STRICT", value)
        sidecar = self._sidecar()
        with pytest.raises(RuntimeError):
            sidecar._load_policies()

    def test_agentmesh_alias_enables_strict(self, tmp_path, monkeypatch):
        # An operator running both components can set only AGENTMESH_POLICY_STRICT
        # and still get strict behaviour from the sidecar.
        _write(tmp_path, "bad.yaml", _BAD_POLICY)
        monkeypatch.setenv("AGT_POLICY_DIR", str(tmp_path))
        monkeypatch.setenv("AGENTMESH_POLICY_STRICT", "1")
        sidecar = self._sidecar()
        with pytest.raises(RuntimeError, match="strict policy load failed"):
            sidecar._load_policies()

    def test_blank_strict_env_defaults_off(self, tmp_path, monkeypatch):
        # A blank toggle is treated as unset (off), preserving main's degraded
        # behaviour rather than crash-looping.
        _write(tmp_path, "good.yaml", _VALID_POLICY)
        _write(tmp_path, "bad.yaml", _BAD_POLICY)
        monkeypatch.setenv("AGT_POLICY_DIR", str(tmp_path))
        monkeypatch.setenv("AGT_POLICY_STRICT", "")
        sidecar = self._sidecar()
        gen = sidecar._load_policies()  # must not raise
        assert gen.policies_failed == 1
        assert gen.policy_set_status == "degraded"

    def test_valid_directory_is_complete(self, tmp_path, monkeypatch):
        _write(tmp_path, "good.yaml", _VALID_POLICY)
        monkeypatch.setenv("AGT_POLICY_DIR", str(tmp_path))
        sidecar = self._sidecar()
        gen = sidecar._load_policies()
        assert gen.policies_failed == 0
        assert gen.policies_loaded == 1
        assert gen.policy_set_status == "complete"

    def test_strict_unavailable_directory_raises(self, tmp_path, monkeypatch):
        missing = tmp_path / "does-not-exist"
        monkeypatch.setenv("AGT_POLICY_DIR", str(missing))
        monkeypatch.setenv("AGT_POLICY_STRICT", "1")
        sidecar = self._sidecar()
        with pytest.raises(RuntimeError, match="directory_status=unavailable"):
            sidecar._load_policies()

    def test_missing_directory_default_off_is_degraded(self, tmp_path, monkeypatch):
        # Default (off): a missing dir does not raise; it publishes a degraded,
        # empty generation rather than crash-looping.
        missing = tmp_path / "does-not-exist"
        monkeypatch.setenv("AGT_POLICY_DIR", str(missing))
        sidecar = self._sidecar()
        gen = sidecar._load_policies()  # must not raise
        assert gen.directory_status == "unavailable"
        assert gen.policy_set_status == "degraded"

    def test_strict_failure_preserves_previous_generation(
        self, tmp_path, monkeypatch
    ):
        # A failed strict reload must not swap in a partially loaded generation:
        # the raise happens before the publish, so the previous set stays live.
        good_dir = tmp_path / "good"
        good_dir.mkdir()
        _write(good_dir, "good.yaml", _VALID_POLICY)
        monkeypatch.setenv("AGT_POLICY_DIR", str(good_dir))
        sidecar = self._sidecar()
        prev_gen = sidecar._load_policies()
        prev_engine = sidecar._policy_state[0]
        assert prev_gen.policies_loaded == 1

        bad_dir = tmp_path / "bad"
        bad_dir.mkdir()
        _write(bad_dir, "good.yaml", _VALID_POLICY)
        _write(bad_dir, "bad.yaml", _BAD_POLICY)
        monkeypatch.setenv("AGT_POLICY_DIR", str(bad_dir))
        monkeypatch.setenv("AGT_POLICY_STRICT", "1")
        with pytest.raises(RuntimeError):
            sidecar._load_policies()
        # Not republished: previous generation and engine still serve.
        assert sidecar._policy_state[1] is prev_gen
        assert sidecar._policy_state[0] is prev_engine

    def test_default_reload_reports_degraded(self, tmp_path, monkeypatch):
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient

        _write(tmp_path, "good.yaml", _VALID_POLICY)
        _write(tmp_path, "bad.yaml", _BAD_POLICY)
        monkeypatch.setenv("AGT_POLICY_DIR", str(tmp_path))
        sidecar = self._sidecar()
        app = sidecar.create_sidecar_app()
        resp = TestClient(app).post("/api/v1/policy/reload")
        assert resp.status_code == 200
        body = resp.json()
        assert body["policies_failed"] == 1
        assert body["policy_set_status"] == "degraded"


class TestPolicyServerLoaderFailClosed:
    """policy_server keeps module-global counts; strict is opt-in."""

    @staticmethod
    def _server():
        import agentmesh.server.policy_server as ps

        return ps

    def test_default_off_skips_without_raising(self, tmp_path, monkeypatch):
        # (a) default (no env) does not raise and records the skip.
        _write(tmp_path, "good.yaml", _VALID_POLICY)
        _write(tmp_path, "bad.yaml", _BAD_POLICY)
        ps = self._server()
        monkeypatch.setattr(ps, "POLICY_DIR", str(tmp_path))
        ps._load_policies()  # must not raise
        assert ps._policy_state.skipped_count == 1
        assert ps._policy_state.loaded_count == 1

    def test_strict_opt_in_raises_on_unloadable_file(self, tmp_path, monkeypatch):
        # (b) opt-in strict raises on an unloadable file.
        _write(tmp_path, "good.yaml", _VALID_POLICY)
        _write(tmp_path, "bad.yaml", _BAD_POLICY)
        monkeypatch.setenv("AGENTMESH_POLICY_STRICT", "1")
        ps = self._server()
        monkeypatch.setattr(ps, "POLICY_DIR", str(tmp_path))
        with pytest.raises(RuntimeError, match="bad.yaml"):
            ps._load_policies()

    def test_agt_alias_enables_strict(self, tmp_path, monkeypatch):
        # The sidecar's AGT_POLICY_STRICT is honoured as an alias here too.
        _write(tmp_path, "good.yaml", _VALID_POLICY)
        _write(tmp_path, "bad.yaml", _BAD_POLICY)
        monkeypatch.setenv("AGT_POLICY_STRICT", "1")
        ps = self._server()
        monkeypatch.setattr(ps, "POLICY_DIR", str(tmp_path))
        with pytest.raises(RuntimeError, match="bad.yaml"):
            ps._load_policies()

    def test_strict_missing_directory_raises(self, tmp_path, monkeypatch):
        # A missing policy dir means zero deny rules; strict mode must refuse to
        # start rather than early-returning and serving fail-open.
        missing = tmp_path / "does-not-exist"
        monkeypatch.setenv("AGENTMESH_POLICY_STRICT", "1")
        ps = self._server()
        monkeypatch.setattr(ps, "POLICY_DIR", str(missing))
        with pytest.raises(RuntimeError, match="does not exist"):
            ps._load_policies()

    def test_missing_directory_default_off_returns(self, tmp_path, monkeypatch):
        missing = tmp_path / "does-not-exist"
        ps = self._server()
        monkeypatch.setattr(ps, "POLICY_DIR", str(missing))
        ps._load_policies()  # must not raise

    def test_governance_shaped_file_is_failure_not_trust_accepted(
        self, tmp_path, monkeypatch
    ):
        # (c) A governance-shaped file with a bad apiVersion / zero rules must be
        # a load FAILURE, not a silently accepted empty trust policy. Before the
        # fix this file loaded as a rule-less TrustPolicy, quietly dropping the
        # governance intent.
        _write(tmp_path, "default.yaml", _GOVERNANCE_SHAPED)
        ps = self._server()
        monkeypatch.setattr(ps, "POLICY_DIR", str(tmp_path))
        ps._load_policies()  # default off: does not raise
        assert ps._policy_state.skipped_count == 1
        # The key assertion: it was NOT silently accepted as a trust policy.
        assert ps._policy_state.trust_policies == ()
        assert ps._policy_state.loaded_count == 0

    def test_governance_shaped_file_raises_under_strict(self, tmp_path, monkeypatch):
        _write(tmp_path, "default.yaml", _GOVERNANCE_SHAPED)
        monkeypatch.setenv("AGENTMESH_POLICY_STRICT", "1")
        ps = self._server()
        monkeypatch.setattr(ps, "POLICY_DIR", str(tmp_path))
        with pytest.raises(RuntimeError, match="default.yaml"):
            ps._load_policies()

    def test_governance_rules_file_not_trust_accepted(self, tmp_path, monkeypatch):
        # Residual guard (Codex #4): a governance doc with NO kind/apiVersion but
        # a non-empty, string-condition rules list that fails governance parsing
        # must NOT be misclassified as a trust policy. TrustRule requires a
        # structured TrustCondition mapping per rule, so a string-condition rule
        # set cannot satisfy the trust schema and is routed to the failure
        # handler. Guards against a governance doc masquerading as trust.
        _write(tmp_path, "gov.yaml", _GOVERNANCE_RULES_BAD_LIMIT)
        ps = self._server()
        monkeypatch.setattr(ps, "POLICY_DIR", str(tmp_path))
        ps._load_policies()  # default off: does not raise
        assert ps._policy_state.skipped_count == 1
        assert ps._policy_state.trust_policies == ()
        assert ps._policy_state.loaded_count == 0

    def test_trust_policy_with_rules_loads_via_path(self, tmp_path, monkeypatch):
        # A genuine trust policy (rules present, no governance shape) still loads
        # through the trust fallback, which passes the file PATH — not its text —
        # to TrustPolicy.from_yaml. Reverting to .read_text() would re-break this.
        from agentmesh.governance.trust_policy import (
            TrustCondition,
            TrustPolicy,
            TrustRule,
        )

        tp = TrustPolicy(
            name="trust-1",
            rules=[
                TrustRule(
                    name="min-score",
                    condition=TrustCondition(
                        field="trust_score", operator="gte", value=500
                    ),
                    action="allow",
                )
            ],
        )
        tp.to_yaml(tmp_path / "trust.yaml")
        ps = self._server()
        monkeypatch.setattr(ps, "POLICY_DIR", str(tmp_path))
        ps._load_policies()  # must not raise
        assert len(ps._policy_state.trust_policies) == 1
        assert ps._policy_state.loaded_count == 1

    def test_bad_json_strict_raises(self, tmp_path, monkeypatch):
        _write(tmp_path, "good.yaml", _VALID_POLICY)
        _write(tmp_path, "bad.json", _BAD_JSON)
        monkeypatch.setenv("AGENTMESH_POLICY_STRICT", "1")
        ps = self._server()
        monkeypatch.setattr(ps, "POLICY_DIR", str(tmp_path))
        with pytest.raises(RuntimeError, match="bad.json"):
            ps._load_policies()

    def test_both_parser_errors_reported(self, tmp_path, monkeypatch):
        # A YAML file that parses as neither governance nor trust must name both
        # failures, not just the trust parser's.
        _write(tmp_path, "bad.yaml", _BAD_POLICY)
        monkeypatch.setenv("AGENTMESH_POLICY_STRICT", "1")
        ps = self._server()
        monkeypatch.setattr(ps, "POLICY_DIR", str(tmp_path))
        with pytest.raises(RuntimeError) as excinfo:
            ps._load_policies()
        msg = str(excinfo.value)
        assert "governance" in msg
        assert "trust" in msg

    def test_atomic_publish_single_consistent_snapshot(self, tmp_path, monkeypatch):
        # After a successful load the state is published as ONE immutable snapshot
        # (frozen dataclass) swapped atomically, so a reader that grabs it once
        # sees engine, trust policies, evaluator and counters all from the same
        # load — never a mixed generation.
        _write(tmp_path, "good.yaml", _VALID_POLICY)
        ps = self._server()
        monkeypatch.setattr(ps, "POLICY_DIR", str(tmp_path))
        ps._load_policies()
        state = ps._policy_state
        assert state is ps._policy_state  # a single object, read once
        assert state.loaded_count == 1
        assert state.skipped_count == 0
        assert state.trust_policies == ()
        assert state.engine is not None

    def test_skipped_count_exposed_via_api(self, tmp_path, monkeypatch):
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient

        _write(tmp_path, "good.yaml", _VALID_POLICY)
        _write(tmp_path, "bad.yaml", _BAD_POLICY)
        ps = self._server()
        monkeypatch.setattr(ps, "POLICY_DIR", str(tmp_path))
        ps._load_policies()
        data = TestClient(ps.app).get("/api/v1/policies").json()
        assert data["total_loaded"] == 1
        assert data["skipped"] == 1

    def test_strict_reload_rejected_returns_409_and_keeps_previous(
        self, tmp_path, monkeypatch
    ):
        # Under opt-in strict, a reload that hits a bad file must return 409 (not
        # a bare 500) and keep the previously loaded set serving.
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient

        good_dir = tmp_path / "good"
        good_dir.mkdir()
        _write(good_dir, "good.yaml", _VALID_POLICY)
        monkeypatch.setenv("AGENTMESH_POLICY_STRICT", "1")
        ps = self._server()
        monkeypatch.setattr(ps, "POLICY_DIR", str(good_dir))
        ps._load_policies()
        assert ps._policy_state.loaded_count == 1
        prev_engine = ps._policy_state.engine

        bad_dir = tmp_path / "bad"
        bad_dir.mkdir()
        _write(bad_dir, "good.yaml", _VALID_POLICY)
        _write(bad_dir, "bad.yaml", _BAD_POLICY)
        monkeypatch.setattr(ps, "POLICY_DIR", str(bad_dir))
        resp = TestClient(ps.app).post("/api/v1/policy/reload")
        assert resp.status_code == 409
        assert ps._policy_state.loaded_count == 1
        assert ps._policy_state.engine is prev_engine
