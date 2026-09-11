# Copyright (c) Microsoft Corporation. Licensed under the MIT License.
"""Regression tests for issue #3538 (part 1).

The sidecar (``agentmesh.server.sidecar``) and policy server
(``agentmesh.server.policy_server``) load every ``*.yaml``/``*.json`` file from a
configured directory. Previously a file that failed to load was logged at
warning level and skipped, so the server started and served decisions without
it; if the dropped file was a deny and a broader allow also loaded, the
effective outcome flipped to allow (fail-open by absence). The loaders now fail
closed by default, with an opt-out for best-effort loading that records a
skipped count.
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
    "    reason: 'Shell execution blocked'\n"
)

# Unclosed flow sequence: yaml.safe_load raises, so this parses as neither a
# governance policy nor a trust policy.
_BAD_POLICY = "policy: [1, 2\n"

# Unterminated object: json.loads raises, so load_json rejects it. The JSON
# branch has no trust fallback, so this drives _on_load_failure directly.
_BAD_JSON = '{"policy": [1, 2\n'


def _write(dir_path, name, content):
    (dir_path / name).write_text(content)


class TestSidecarLoaderFailClosed:
    @staticmethod
    def _sidecar():
        import agentmesh.server.sidecar as sidecar

        return sidecar

    def test_strict_default_raises_on_unloadable_file(self, tmp_path, monkeypatch):
        _write(tmp_path, "good.yaml", _VALID_POLICY)
        _write(tmp_path, "bad.yaml", _BAD_POLICY)
        monkeypatch.setenv("AGT_POLICY_DIR", str(tmp_path))
        monkeypatch.delenv("AGT_POLICY_STRICT", raising=False)
        sidecar = self._sidecar()
        with pytest.raises(RuntimeError, match="bad.yaml"):
            sidecar._load_policies()

    def test_nonstrict_skips_and_counts(self, tmp_path, monkeypatch):
        _write(tmp_path, "good.yaml", _VALID_POLICY)
        _write(tmp_path, "bad.yaml", _BAD_POLICY)
        monkeypatch.setenv("AGT_POLICY_DIR", str(tmp_path))
        monkeypatch.setenv("AGT_POLICY_STRICT", "0")
        sidecar = self._sidecar()
        sidecar._load_policies()
        assert sidecar._loaded_count == 1
        assert sidecar._skipped_count == 1

    def test_valid_directory_loads_without_raising(self, tmp_path, monkeypatch):
        _write(tmp_path, "good.yaml", _VALID_POLICY)
        monkeypatch.setenv("AGT_POLICY_DIR", str(tmp_path))
        monkeypatch.delenv("AGT_POLICY_STRICT", raising=False)
        sidecar = self._sidecar()
        sidecar._load_policies()
        assert sidecar._loaded_count == 1
        assert sidecar._skipped_count == 0

    def test_strict_failure_preserves_previous_engine(self, tmp_path, monkeypatch):
        # A failed strict reload must not swap in a partially loaded engine: the
        # previously loaded policy set and count remain intact.
        good_dir = tmp_path / "good"
        good_dir.mkdir()
        _write(good_dir, "good.yaml", _VALID_POLICY)
        monkeypatch.setenv("AGT_POLICY_DIR", str(good_dir))
        monkeypatch.delenv("AGT_POLICY_STRICT", raising=False)
        sidecar = self._sidecar()
        sidecar._load_policies()
        assert sidecar._loaded_count == 1
        prev_engine = sidecar._engine

        bad_dir = tmp_path / "bad"
        bad_dir.mkdir()
        _write(bad_dir, "good.yaml", _VALID_POLICY)
        _write(bad_dir, "bad.yaml", _BAD_POLICY)
        monkeypatch.setenv("AGT_POLICY_DIR", str(bad_dir))
        with pytest.raises(RuntimeError):
            sidecar._load_policies()
        assert sidecar._loaded_count == 1
        assert sidecar._engine is prev_engine

    def test_skipped_count_exposed_via_api(self, tmp_path, monkeypatch):
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient

        _write(tmp_path, "good.yaml", _VALID_POLICY)
        _write(tmp_path, "bad.yaml", _BAD_POLICY)
        monkeypatch.setenv("AGT_POLICY_DIR", str(tmp_path))
        monkeypatch.setenv("AGT_POLICY_STRICT", "0")
        sidecar = self._sidecar()
        app = sidecar.create_sidecar_app()
        sidecar._load_policies()
        data = TestClient(app).get("/api/v1/policies").json()
        assert data["total_loaded"] == 1
        assert data["skipped"] == 1

    def test_bad_json_strict_raises(self, tmp_path, monkeypatch):
        _write(tmp_path, "good.yaml", _VALID_POLICY)
        _write(tmp_path, "bad.json", _BAD_JSON)
        monkeypatch.setenv("AGT_POLICY_DIR", str(tmp_path))
        monkeypatch.delenv("AGT_POLICY_STRICT", raising=False)
        sidecar = self._sidecar()
        with pytest.raises(RuntimeError, match="bad.json"):
            sidecar._load_policies()

    def test_blank_strict_env_stays_strict(self, tmp_path, monkeypatch):
        # A blank toggle must fail closed, not silently enable best-effort.
        _write(tmp_path, "good.yaml", _VALID_POLICY)
        _write(tmp_path, "bad.yaml", _BAD_POLICY)
        monkeypatch.setenv("AGT_POLICY_DIR", str(tmp_path))
        monkeypatch.setenv("AGT_POLICY_STRICT", "")
        sidecar = self._sidecar()
        with pytest.raises(RuntimeError, match="bad.yaml"):
            sidecar._load_policies()

    def test_strict_reload_rejected_returns_409_and_keeps_previous(
        self, tmp_path, monkeypatch
    ):
        # A strict reload that hits a bad file must not 500: the endpoint returns
        # 409 and the previously loaded policy set keeps serving.
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient

        good_dir = tmp_path / "good"
        good_dir.mkdir()
        _write(good_dir, "good.yaml", _VALID_POLICY)
        monkeypatch.delenv("AGT_POLICY_STRICT", raising=False)
        monkeypatch.setenv("AGT_POLICY_DIR", str(good_dir))
        sidecar = self._sidecar()
        app = sidecar.create_sidecar_app()
        sidecar._load_policies()
        assert sidecar._loaded_count == 1
        prev_engine = sidecar._engine

        bad_dir = tmp_path / "bad"
        bad_dir.mkdir()
        _write(bad_dir, "good.yaml", _VALID_POLICY)
        _write(bad_dir, "bad.yaml", _BAD_POLICY)
        monkeypatch.setenv("AGT_POLICY_DIR", str(bad_dir))
        resp = TestClient(app).post("/api/v1/policy/reload")
        assert resp.status_code == 409
        assert sidecar._loaded_count == 1
        assert sidecar._engine is prev_engine


class TestPolicyServerLoaderFailClosed:
    @staticmethod
    def _server():
        import agentmesh.server.policy_server as ps

        return ps

    def test_strict_default_raises_on_unloadable_file(self, tmp_path, monkeypatch):
        _write(tmp_path, "good.yaml", _VALID_POLICY)
        _write(tmp_path, "bad.yaml", _BAD_POLICY)
        monkeypatch.delenv("AGENTMESH_POLICY_STRICT", raising=False)
        ps = self._server()
        # POLICY_DIR is captured at import time; patch the module global.
        monkeypatch.setattr(ps, "POLICY_DIR", str(tmp_path))
        with pytest.raises(RuntimeError, match="bad.yaml"):
            ps._load_policies()

    def test_nonstrict_skips(self, tmp_path, monkeypatch):
        _write(tmp_path, "good.yaml", _VALID_POLICY)
        _write(tmp_path, "bad.yaml", _BAD_POLICY)
        monkeypatch.setenv("AGENTMESH_POLICY_STRICT", "0")
        ps = self._server()
        monkeypatch.setattr(ps, "POLICY_DIR", str(tmp_path))
        ps._load_policies()
        assert ps._skipped_count == 1

    def test_trust_policy_loads_via_path(self, tmp_path, monkeypatch):
        # A trust policy (dict-condition rule) is rejected by the governance
        # parser and must load through the trust fallback, which now passes the
        # file PATH to TrustPolicy.from_yaml. Previously it passed file content,
        # so the trust load failed and, under strict mode, would wrongly refuse
        # to start.
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
        monkeypatch.delenv("AGENTMESH_POLICY_STRICT", raising=False)
        ps = self._server()
        monkeypatch.setattr(ps, "POLICY_DIR", str(tmp_path))
        ps._load_policies()  # must not raise
        assert len(ps._trust_policies) == 1
        assert ps._loaded_count == 1

    def test_bad_json_strict_raises(self, tmp_path, monkeypatch):
        _write(tmp_path, "good.yaml", _VALID_POLICY)
        _write(tmp_path, "bad.json", _BAD_JSON)
        monkeypatch.delenv("AGENTMESH_POLICY_STRICT", raising=False)
        ps = self._server()
        monkeypatch.setattr(ps, "POLICY_DIR", str(tmp_path))
        with pytest.raises(RuntimeError, match="bad.json"):
            ps._load_policies()

    def test_blank_strict_env_stays_strict(self, tmp_path, monkeypatch):
        # A blank toggle must fail closed, not silently enable best-effort.
        _write(tmp_path, "good.yaml", _VALID_POLICY)
        _write(tmp_path, "bad.yaml", _BAD_POLICY)
        monkeypatch.setenv("AGENTMESH_POLICY_STRICT", "")
        ps = self._server()
        monkeypatch.setattr(ps, "POLICY_DIR", str(tmp_path))
        with pytest.raises(RuntimeError, match="bad.yaml"):
            ps._load_policies()

    def test_skipped_count_exposed_via_api(self, tmp_path, monkeypatch):
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient

        _write(tmp_path, "good.yaml", _VALID_POLICY)
        _write(tmp_path, "bad.yaml", _BAD_POLICY)
        monkeypatch.setenv("AGENTMESH_POLICY_STRICT", "0")
        ps = self._server()
        monkeypatch.setattr(ps, "POLICY_DIR", str(tmp_path))
        ps._load_policies()
        data = TestClient(ps.app).get("/api/v1/policies").json()
        assert data["total_loaded"] == 1
        assert data["skipped"] == 1

    def test_both_parser_errors_reported(self, tmp_path, monkeypatch):
        # A YAML file that parses as neither governance nor trust must name both
        # failures, not just the trust parser's, so the diagnostic is not
        # misattributed when the file was meant to be a governance policy.
        _write(tmp_path, "bad.yaml", _BAD_POLICY)
        monkeypatch.delenv("AGENTMESH_POLICY_STRICT", raising=False)
        ps = self._server()
        monkeypatch.setattr(ps, "POLICY_DIR", str(tmp_path))
        with pytest.raises(RuntimeError) as excinfo:
            ps._load_policies()
        msg = str(excinfo.value)
        assert "governance" in msg
        assert "trust" in msg

    def test_strict_reload_rejected_returns_409_and_keeps_previous(
        self, tmp_path, monkeypatch
    ):
        # A strict reload that hits a bad file must not 500: the endpoint returns
        # 409 and the previously loaded policy set keeps serving.
        pytest.importorskip("fastapi")
        from fastapi.testclient import TestClient

        good_dir = tmp_path / "good"
        good_dir.mkdir()
        _write(good_dir, "good.yaml", _VALID_POLICY)
        monkeypatch.delenv("AGENTMESH_POLICY_STRICT", raising=False)
        ps = self._server()
        monkeypatch.setattr(ps, "POLICY_DIR", str(good_dir))
        ps._load_policies()
        assert ps._loaded_count == 1
        prev_engine = ps._engine

        bad_dir = tmp_path / "bad"
        bad_dir.mkdir()
        _write(bad_dir, "good.yaml", _VALID_POLICY)
        _write(bad_dir, "bad.yaml", _BAD_POLICY)
        monkeypatch.setattr(ps, "POLICY_DIR", str(bad_dir))
        resp = TestClient(ps.app).post("/api/v1/policy/reload")
        assert resp.status_code == 409
        assert ps._loaded_count == 1
        assert ps._engine is prev_engine
