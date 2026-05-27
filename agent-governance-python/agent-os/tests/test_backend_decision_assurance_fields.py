# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for high-assurance fields on ``BackendDecision``.

Verifies that ``proof_artefact`` and ``verification_pointers`` round-trip
through an in-test ``ExternalPolicyBackend`` and land in the resulting
``PolicyDecision.audit_entry`` emitted by ``PolicyEvaluator``.

The new fields are optional and default to empty, so existing
``OPABackend`` and ``CedarBackend`` are unaffected — those backends
construct ``BackendDecision`` instances without them and the audit
entry omits both keys, as today.
"""
from __future__ import annotations

from typing import Any

from agent_os.policies.backends import BackendDecision
from agent_os.policies.evaluator import PolicyEvaluator


class _StubAssuranceBackend:
    """Minimal ``ExternalPolicyBackend`` carrying assurance evidence."""

    name = "stub-smt"

    def evaluate(self, context: dict[str, Any]) -> BackendDecision:
        return BackendDecision(
            allowed=True,
            action="allow",
            reason="constraints discharged",
            backend=self.name,
            proof_artefact="sha256:" + "0" * 64,
            verification_pointers={
                "issuer_pubkey": "https://example.test/.well-known/issuer.pub",
                "policy_registry": "https://example.test/.well-known/policies/",
            },
        )


def test_backend_decision_defaults_are_empty():
    """Existing backends construct without the new fields; defaults must
    be empty so audit consumers see no change."""
    d = BackendDecision(allowed=True, action="allow", reason="ok", backend="x")
    assert d.proof_artefact is None
    assert d.verification_pointers == {}


def test_backend_decision_carries_assurance_fields():
    """When set, the fields round-trip without coercion."""
    d = BackendDecision(
        allowed=True,
        action="allow",
        reason="proven",
        backend="smt",
        proof_artefact="sha256:abcd",
        verification_pointers={"issuer_pubkey": "https://x/"},
    )
    assert d.proof_artefact == "sha256:abcd"
    assert d.verification_pointers["issuer_pubkey"].startswith("https://")


def test_assurance_fields_propagate_into_policy_decision_audit_entry():
    """The evaluator must forward proof_artefact and verification_pointers
    into ``PolicyDecision.audit_entry`` when a backend provides them.

    Without YAML rules loaded, the evaluator falls through to registered
    external backends; this exercises that path end-to-end.
    """
    ev = PolicyEvaluator()
    ev.add_backend(_StubAssuranceBackend())

    decision = ev.evaluate({"tool_name": "lookup_customer", "agent_id": "agent:test"})

    assert decision.allowed is True
    assert decision.action == "allow"
    audit = decision.audit_entry
    assert audit["backend"] == "stub-smt"
    assert audit["proof_artefact"] == "sha256:" + "0" * 64
    assert audit["verification_pointers"]["issuer_pubkey"].startswith("https://")
    assert audit["verification_pointers"]["policy_registry"].endswith("/")


def test_audit_entry_omits_assurance_keys_when_backend_does_not_supply_them():
    """Backends that don't supply the new fields must not introduce
    empty keys into the audit entry — keeps audit records compact and
    backwards-compatible with consumers that key on presence."""

    class _LegacyBackend:
        name = "legacy"

        def evaluate(self, context: dict[str, Any]) -> BackendDecision:
            return BackendDecision(
                allowed=False,
                action="deny",
                reason="legacy denial",
                backend=self.name,
            )

    ev = PolicyEvaluator()
    ev.add_backend(_LegacyBackend())

    decision = ev.evaluate({"tool_name": "x"})

    assert decision.allowed is False
    assert "proof_artefact" not in decision.audit_entry
    assert "verification_pointers" not in decision.audit_entry
