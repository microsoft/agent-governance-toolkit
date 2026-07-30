# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for ``CedarlingBackend.evaluate(request)``.

Uses a real Cedarling engine backed by the ``simple-unsigned`` policy store.
Tests are skipped automatically when ``cedarling_python`` native bindings
are not compiled.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from cedarling_agentmesh import CedarlingBackend

_POLICY_STORE = str(
    Path(__file__).resolve().parent / "policy-stores" / "simple-unsigned"
)
_MULTI_ISSUER_POLICY_STORE = str(
    Path(__file__).resolve().parent / "policy-stores" / "simple-multi-issuer"
)

# Pre-generated HS256 JWT (sig validation disabled) with org_id: "some_long_id"
ACCESS_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJib0c4ZGZjNU1LVG4zN283Z3NkQ2V5cUw4THBXUXRnb080MW0xS1p3ZHEwIiwiY29kZSI6ImJmMTkzNGY2LTM5MDUtNDIwYS04Mjk5LTZiMmUzZmZkZGQ2ZSIsImlzcyI6Imh0dHBzOi8vdGVzdC5qYW5zLm9yZyIsInRva2VuX3R5cGUiOiJCZWFyZXIiLCJjbGllbnRfaWQiOiI1YjQ0ODdjNC04ZGIxLTQwOWQtYTY1My1mOTA3YjgwOTQwMzkiLCJhdWQiOiI1YjQ0ODdjNC04ZGIxLTQwOWQtYTY1My1mOTA3YjgwOTQwMzkiLCJhY3IiOiJiYXNpYyIsIng1dCNTMjU2IjoiIiwic2NvcGUiOlsib3BlbmlkIiwicHJvZmlsZSJdLCJvcmdfaWQiOiJzb21lX2xvbmdfaWQiLCJhdXRoX3RpbWUiOjE3MjQ4MzA3NDYsImV4cCI6MTcyNDk0NTk3OCwiaWF0IjoxNzI0ODMyMjU5LCJqdGkiOiJseFRtQ1ZSRlR4T2pKZ3ZFRXBvek1RIiwibmFtZSI6IkRlZmF1bHQgQWRtaW4gVXNlciIsInN0YXR1cyI6eyJzdGF0dXNfbGlzdCI6eyJpZHgiOjIwMSwidXJpIjoiaHR0cHM6Ly90ZXN0LmphbnMub3JnL2phbnMtYXV0aC9yZXN0djEvc3RhdHVzX2xpc3QifX19.7n4vE60lisFLnEFhVwYMOPh5loyLLtPc07sCvaFI-Ik"  # noqa: S105


def _make_engine(policy_store: str | None = None) -> Any:
    cedarling_python = pytest.importorskip("cedarling_python")
    if not hasattr(cedarling_python, "BootstrapConfig"):
        pytest.skip("cedarling-python native bindings not compiled")

    config = cedarling_python.BootstrapConfig({
        "CEDARLING_APPLICATION_NAME": "TestIntegration",
        "CEDARLING_POLICY_STORE_LOCAL_FN": policy_store or _POLICY_STORE,
        "CEDARLING_JWT_SIG_VALIDATION": "disabled",
        "CEDARLING_JWT_STATUS_VALIDATION": "disabled",
        "CEDARLING_LOG_TYPE": "std_out",
        "CEDARLING_LOG_LEVEL": "INFO",
        "CEDARLING_JWT_SIGNATURE_ALGORITHMS_SUPPORTED": ["HS256"],
    })
    return cedarling_python.Cedarling(config)


class TestRequestMapping:
    """Verify AGT context -> Cedar request mapping."""

    @staticmethod
    def _req(**overrides: Any) -> dict:
        ctx = overrides.pop("context", {})
        # _build_request doesn't need a real engine — just a backend instance
        b = CedarlingBackend(cedarling_instance=object(), **overrides)
        return b._build_request(ctx)  # type: ignore[arg-type]

    def test_tool_name_to_pascal_case(self):
        req = self._req(context={"tool_name": "read_data", "agent_id": "a1"})
        assert '"ReadData"' in req["action"]

    def test_single_word_tool(self):
        req = self._req(context={"tool_name": "query", "agent_id": "a"})
        assert '"Query"' in req["action"]

    def test_agent_id_becomes_principal(self):
        req = self._req(context={"tool_name": "call", "agent_id": "agent-42"})
        assert req["principal"]["id"] == "agent-42"

    def test_resource_mapped(self):
        req = self._req(context={"tool_name": "r", "agent_id": "a", "resource": "db-1"})
        assert req["resource"]["id"] == "db-1"

    def test_extra_keys_go_to_context(self):
        req = self._req(context={"tool_name": "read", "agent_id": "a", "env": "prod"})
        assert req["context"]["env"] == "prod"

    def test_defaults_for_missing_keys(self):
        req = self._req(context={})
        assert req["principal"]["id"] == "anonymous"
        assert req["resource"]["id"] == ""

    def test_custom_namespace(self):
        req = self._req(namespace="MyNS", context={"tool_name": "act", "agent_id": "a"})
        assert req["principal"]["type"] == "MyNS::Agent"
        assert req["resource"]["type"] == "MyNS::Resource"
        assert req["action"].startswith("MyNS::Action::")

    def test_action_namespace(self):
        req = self._req(action_namespace="MyAct", context={"tool_name": "act", "agent_id": "a"})
        assert req["action"].startswith("MyAct::")

    def test_custom_entity_types(self):
        req = self._req(
            principal_entity_type="User",
            resource_entity_type="File",
            context={"tool_name": "r", "agent_id": "u1"},
        )
        assert req["principal"]["type"] == "User"
        assert req["resource"]["type"] == "File"

    def test_namespace_and_custom_entity_types(self):
        req = self._req(
            namespace="AGT",
            principal_entity_type="Bot",
            resource_entity_type="Doc",
            context={"tool_name": "read", "agent_id": "b1"},
        )
        assert req["principal"]["type"] == "AGT::Bot"
        assert req["resource"]["type"] == "AGT::Doc"
        assert req["action"].startswith("AGT::Action::")


# =============================================================================
# Integration tests with real Cedarling engine
# =============================================================================


class TestRealCedarling:
    """Integration tests using a real Cedarling engine and real policy store.

    Skipped automatically when ``cedarling_python`` native bindings are absent.
    """

    @pytest.fixture(scope="class")
    def engine(self) -> Any:
        return _make_engine()

    def test_name(self, engine: Any):
        assert CedarlingBackend(cedarling_instance=engine).name == "cedarling"

    def test_allow_with_unsigned(self, engine: Any):
        b = CedarlingBackend(cedarling_instance=engine, auth_type="unsigned", namespace="AGT")
        d = b.evaluate({
            "tool_name": "read_data",
            "agent_id": "agent-42",
            "resource": "doc-1",
            "principal_attributes": {"role": "admin"},
        })
        assert d.allowed is True
        assert d.backend == "cedarling"
        assert d.raw_result is not None
        assert d.raw_result["request_id"] is not None

    def test_deny_when_no_policy_matches(self, engine: Any):
        b = CedarlingBackend(cedarling_instance=engine, auth_type="unsigned", namespace="AGT")
        d = b.evaluate({
            "tool_name": "write",
            "agent_id": "agent-42",
            "resource": "doc-1",
            "principal_attributes": {"role": "admin"},
        })
        assert d.allowed is False

    def test_diagnostics_in_raw_result(self, engine: Any):
        b = CedarlingBackend(cedarling_instance=engine, auth_type="unsigned", namespace="AGT")
        d = b.evaluate({
            "tool_name": "read_data",
            "agent_id": "agent-42",
            "resource": "doc-1",
            "principal_attributes": {"role": "admin"},
        })
        diag = d.raw_result.get("diagnostics")
        assert diag is not None
        assert diag["decision"] == "ALLOW"
        assert any("allow-read" in r for r in diag["reasons"])

    def test_forbid_unsigned(self, engine: Any):
        """forbid policy denies write even with valid principal attributes."""
        b = CedarlingBackend(cedarling_instance=engine, auth_type="unsigned", namespace="AGT")
        d = b.evaluate({
            "tool_name": "write",
            "agent_id": "agent-42",
            "resource": "doc-1",
            "principal_attributes": {"role": "auditor"},
        })
        assert d.allowed is False
        diag = d.raw_result.get("diagnostics") if d.raw_result else None
        if diag:
            assert any("forbid-write" in r for r in diag.get("reasons", []))

    def test_injected_instance_used(self, engine: Any):
        b = CedarlingBackend(
            cedarling_instance=engine,
            bootstrap_config={"CEDARLING_APPLICATION_NAME": "ShouldNotBeUsed"},
            auth_type="unsigned",
            namespace="AGT",
        )
        d = b.evaluate({
            "tool_name": "read",
            "agent_id": "agent-42",
            "resource": "doc-1",
            "principal_attributes": {"role": "admin"},
        })
        assert d.allowed is True

    def test_custom_entity_types(self, engine: Any):
        b = CedarlingBackend(
            cedarling_instance=engine,
            auth_type="unsigned",
            principal_entity_type="Agent",
            resource_entity_type="Resource",
            namespace="AGT",
        )
        d = b.evaluate({
            "tool_name": "read",
            "agent_id": "agent-42",
            "resource": "doc-1",
            "principal_attributes": {"role": "admin"},
        })
        assert d.allowed is True

    def test_timing_populated(self, engine: Any):
        b = CedarlingBackend(cedarling_instance=engine, auth_type="unsigned")
        d = b.evaluate({
            "tool_name": "read",
            "agent_id": "agent-42",
            "resource": "doc-1",
            "principal_attributes": {"role": "admin"},
        })
        assert d.evaluation_ms >= 0


class TestMultiIssuer:
    """Multi-issuer auth tests with a dedicated policy store."""

    @pytest.fixture(scope="class")
    def engine(self) -> Any:
        return _make_engine(policy_store=_MULTI_ISSUER_POLICY_STORE)

    def test_allow_with_valid_token(self, engine: Any):
        """valid access token with matching org_id."""
        b = CedarlingBackend(cedarling_instance=engine, auth_type="multi-issuer", namespace="AGT")
        d = b.evaluate({
            "tool_name": "read_data",
            "agent_id": "agent-42",
            "resource": "doc-1",
            "tokens": {"AGT::Access_Token": ACCESS_TOKEN},
        })
        assert d.allowed is True
        assert d.backend == "cedarling"
        assert d.raw_result is not None
        assert d.raw_result["request_id"] is not None

    def test_multi_issuer_requires_tokens_key(self, engine: Any):
        b = CedarlingBackend(cedarling_instance=engine, auth_type="multi-issuer", namespace="AGT")
        with pytest.raises(ValueError, match="multi-issuer auth requires a 'tokens' key"):
            b.evaluate({
                "tool_name": "read_data",
                "agent_id": "agent-42",
                "resource": "doc-1",
            })

    def test_deny_wrong_action(self, engine: Any):
        b = CedarlingBackend(cedarling_instance=engine, auth_type="multi-issuer", namespace="AGT")
        d = b.evaluate({
            "tool_name": "write",
            "agent_id": "agent-42",
            "resource": "doc-1",
            "tokens": {"AGT::Access_Token": ACCESS_TOKEN},
        })
        assert d.allowed is False

    def test_forbid_multi_issuer(self, engine: Any):
        """forbid policy denies write even with a valid token."""
        b = CedarlingBackend(cedarling_instance=engine, auth_type="multi-issuer", namespace="AGT")
        d = b.evaluate({
            "tool_name": "write",
            "agent_id": "agent-42",
            "resource": "doc-1",
            "tokens": {"AGT::Access_Token": ACCESS_TOKEN},
        })
        assert d.allowed is False
        diag = d.raw_result.get("diagnostics") if d.raw_result else None
        if diag:
            assert any("forbid-write" in r for r in diag.get("reasons", []))

    def test_request_id_in_raw_result(self, engine: Any):
        """raw_result includes request_id on success."""
        b = CedarlingBackend(cedarling_instance=engine, auth_type="multi-issuer", namespace="AGT")
        d = b.evaluate({
            "tool_name": "read_data",
            "agent_id": "agent-42",
            "resource": "doc-1",
            "tokens": {"AGT::Access_Token": ACCESS_TOKEN},
        })
        assert d.raw_result is not None
        assert d.raw_result["request_id"] is not None

    def test_name(self, engine: Any):
        assert CedarlingBackend(cedarling_instance=engine).name == "cedarling"
