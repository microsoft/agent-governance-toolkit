# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for ExternalPolicyBackend protocol, BackendRegistry, and adapters."""

from __future__ import annotations

import pytest

from agentmesh.governance.backend import (
    BackendRegistry,
    ExternalPolicyBackend,
    PolicyDecisionResult,
)
from agentmesh.governance.opa import OPAEvaluator, OPAPolicyBackend
from agentmesh.governance.cedar import CedarEvaluator, CedarPolicyBackend


# ── Sample policies ───────────────────────────────────────────

BASIC_REGO = """
package agentmesh

default allow = false

allow {
    input.agent.role == "admin"
}
"""

BASIC_CEDAR = """
permit(
    principal,
    action == Action::"ReadData",
    resource
);

forbid(
    principal,
    action == Action::"DeleteFile",
    resource
);
"""


# ── PolicyDecisionResult ──────────────────────────────────────


class TestPolicyDecisionResult:
    """Tests for the unified decision dataclass."""

    def test_defaults(self):
        result = PolicyDecisionResult(allowed=True)
        assert result.allowed is True
        assert result.reason == ""
        assert result.backend == ""
        assert result.latency_ms == 0.0
        assert result.raw_response is None

    def test_full_construction(self):
        result = PolicyDecisionResult(
            allowed=False,
            reason="denied by rule X",
            backend="opa",
            latency_ms=1.5,
            raw_response={"some": "data"},
        )
        assert result.allowed is False
        assert result.reason == "denied by rule X"
        assert result.backend == "opa"
        assert result.latency_ms == 1.5
        assert result.raw_response == {"some": "data"}


# ── Protocol conformance ──────────────────────────────────────


class TestProtocolConformance:
    """Verify that adapters satisfy the ExternalPolicyBackend protocol."""

    def test_opa_backend_is_protocol_instance(self):
        backend = OPAPolicyBackend(rego_content=BASIC_REGO)
        assert isinstance(backend, ExternalPolicyBackend)

    def test_cedar_backend_is_protocol_instance(self):
        backend = CedarPolicyBackend(policy_content=BASIC_CEDAR)
        assert isinstance(backend, ExternalPolicyBackend)

    def test_custom_backend_satisfies_protocol(self):
        """A plain class with the right methods satisfies the protocol."""

        class MyBackend:
            @property
            def name(self) -> str:
                return "custom"

            def evaluate(self, action: str, context: dict) -> PolicyDecisionResult:
                return PolicyDecisionResult(allowed=True, backend="custom")

            def healthy(self) -> bool:
                return True

        backend = MyBackend()
        assert isinstance(backend, ExternalPolicyBackend)

    def test_incomplete_class_fails_protocol(self):
        """A class missing methods does not satisfy the protocol."""

        class Incomplete:
            @property
            def name(self) -> str:
                return "bad"

        assert not isinstance(Incomplete(), ExternalPolicyBackend)


# ── OPAPolicyBackend ──────────────────────────────────────────


class TestOPAPolicyBackend:
    """Tests for the OPA adapter."""

    def test_name(self):
        backend = OPAPolicyBackend(rego_content=BASIC_REGO)
        assert backend.name == "opa"

    def test_evaluate_allowed(self):
        backend = OPAPolicyBackend(rego_content=BASIC_REGO)
        result = backend.evaluate("allow", {"agent": {"role": "admin"}})
        assert isinstance(result, PolicyDecisionResult)
        assert result.allowed is True
        assert result.backend == "opa"
        assert result.latency_ms >= 0

    def test_evaluate_denied(self):
        backend = OPAPolicyBackend(rego_content=BASIC_REGO)
        result = backend.evaluate("allow", {"agent": {"role": "guest"}})
        assert result.allowed is False
        assert result.backend == "opa"

    def test_healthy_with_content(self):
        backend = OPAPolicyBackend(rego_content=BASIC_REGO)
        assert backend.healthy() is True

    def test_healthy_without_anything(self):
        backend = OPAPolicyBackend(mode="local")
        # Healthy if opa CLI is available or content exists
        # Without either, still local mode with no content
        result = backend.healthy()
        assert isinstance(result, bool)

    def test_wraps_existing_evaluator(self):
        evaluator = OPAEvaluator(mode="local", rego_content=BASIC_REGO)
        backend = OPAPolicyBackend(evaluator=evaluator)
        result = backend.evaluate("allow", {"agent": {"role": "admin"}})
        assert result.allowed is True

    def test_custom_query_prefix(self):
        rego = """
package custom

default allow = false

allow {
    input.action == "read"
}
"""
        backend = OPAPolicyBackend(
            rego_content=rego,
            query_prefix="data.custom.allow",
        )
        result = backend.evaluate("read", {"action": "read"})
        assert result.allowed is True


# ── CedarPolicyBackend ────────────────────────────────────────


class TestCedarPolicyBackend:
    """Tests for the Cedar adapter."""

    def test_name(self):
        backend = CedarPolicyBackend(policy_content=BASIC_CEDAR)
        assert backend.name == "cedar"

    def test_evaluate_allowed(self):
        backend = CedarPolicyBackend(policy_content=BASIC_CEDAR)
        result = backend.evaluate('Action::"ReadData"', {"agent_did": "did:example:1"})
        assert isinstance(result, PolicyDecisionResult)
        assert result.allowed is True
        assert result.backend == "cedar"
        assert result.latency_ms >= 0

    def test_evaluate_denied(self):
        backend = CedarPolicyBackend(policy_content=BASIC_CEDAR)
        result = backend.evaluate('Action::"DeleteFile"', {"agent_did": "did:example:1"})
        assert result.allowed is False
        assert result.backend == "cedar"

    def test_healthy_with_content(self):
        backend = CedarPolicyBackend(policy_content=BASIC_CEDAR)
        assert backend.healthy() is True

    def test_wraps_existing_evaluator(self):
        evaluator = CedarEvaluator(policy_content=BASIC_CEDAR)
        backend = CedarPolicyBackend(evaluator=evaluator)
        result = backend.evaluate('Action::"ReadData"', {"agent_did": "did:example:1"})
        assert result.allowed is True


# ── BackendRegistry ───────────────────────────────────────────


class TestBackendRegistry:
    """Tests for backend discovery and registration."""

    def setup_method(self):
        BackendRegistry.clear()

    def teardown_method(self):
        BackendRegistry.clear()

    def test_register_and_get(self):
        backend = OPAPolicyBackend(rego_content=BASIC_REGO)
        BackendRegistry.register(backend)
        retrieved = BackendRegistry.get("opa")
        assert retrieved is backend

    def test_register_cedar(self):
        backend = CedarPolicyBackend(policy_content=BASIC_CEDAR)
        BackendRegistry.register(backend)
        retrieved = BackendRegistry.get("cedar")
        assert retrieved is backend

    def test_get_missing_raises(self):
        with pytest.raises(KeyError, match="No backend registered"):
            BackendRegistry.get("nonexistent")

    def test_list_backends(self):
        BackendRegistry.register(OPAPolicyBackend(rego_content=BASIC_REGO))
        BackendRegistry.register(CedarPolicyBackend(policy_content=BASIC_CEDAR))
        names = BackendRegistry.list_backends()
        assert "opa" in names
        assert "cedar" in names

    def test_unregister(self):
        BackendRegistry.register(OPAPolicyBackend(rego_content=BASIC_REGO))
        BackendRegistry.unregister("opa")
        with pytest.raises(KeyError):
            BackendRegistry.get("opa")

    def test_register_invalid_type_raises(self):
        with pytest.raises(TypeError, match="does not implement"):
            BackendRegistry.register("not a backend")  # type: ignore

    def test_register_replaces_existing(self):
        backend1 = OPAPolicyBackend(rego_content=BASIC_REGO)
        backend2 = OPAPolicyBackend(rego_content=BASIC_REGO, query_prefix="data.other.allow")
        BackendRegistry.register(backend1)
        BackendRegistry.register(backend2)
        assert BackendRegistry.get("opa") is backend2

    def test_clear(self):
        BackendRegistry.register(OPAPolicyBackend(rego_content=BASIC_REGO))
        BackendRegistry.clear()
        assert BackendRegistry.list_backends() == []


# ── Integration: end-to-end via registry ──────────────────────


class TestEndToEnd:
    """Integration test: register, discover, evaluate."""

    def setup_method(self):
        BackendRegistry.clear()

    def teardown_method(self):
        BackendRegistry.clear()

    def test_evaluate_through_registry(self):
        BackendRegistry.register(OPAPolicyBackend(rego_content=BASIC_REGO))
        BackendRegistry.register(CedarPolicyBackend(policy_content=BASIC_CEDAR))

        opa = BackendRegistry.get("opa")
        result = opa.evaluate("allow", {"agent": {"role": "admin"}})
        assert result.allowed is True

        cedar = BackendRegistry.get("cedar")
        result = cedar.evaluate('Action::"ReadData"', {"agent_did": "did:mesh:abc"})
        assert result.allowed is True

    def test_all_backends_report_healthy(self):
        BackendRegistry.register(OPAPolicyBackend(rego_content=BASIC_REGO))
        BackendRegistry.register(CedarPolicyBackend(policy_content=BASIC_CEDAR))

        for name in BackendRegistry.list_backends():
            backend = BackendRegistry.get(name)
            assert backend.healthy() is True
