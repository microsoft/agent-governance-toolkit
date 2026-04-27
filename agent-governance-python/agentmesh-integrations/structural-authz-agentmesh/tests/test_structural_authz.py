# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the structural authorization gates AgentMesh adapter."""

import json
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import pytest

from structural_authz_agentmesh import (AgentProfile, AuthzDecision, AuthzGate,
                                        ChainValidationError, DelegationChain,
                                        DelegationLink, TrustArtifact,
                                        TrustGrade, TrustTracker,
                                        generate_keypair)

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519 as _ed25519  # noqa: F401

    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False

requires_crypto = pytest.mark.skipif(
    not _CRYPTO_AVAILABLE,
    reason="cryptography package not installed",
)


def _future(seconds: int = 3600) -> datetime:
    return datetime.now(timezone.utc) + timedelta(seconds=seconds)


def _past(seconds: int = 1) -> datetime:
    return datetime.now(timezone.utc) - timedelta(seconds=seconds)


def _make_agent(
    did: str = "did:authz:alice",
    name: str = "Alice",
    capabilities: Optional[List[str]] = None,
    trust_score: int = 500,
    status: str = "active",
) -> AgentProfile:
    return AgentProfile(
        did=did,
        name=name,
        capabilities=capabilities or ["read", "write"],
        trust_score=trust_score,
        status=status,
    )


def _make_artifact(
    did: str = "did:authz:alice",
    grade: TrustGrade = TrustGrade.TRUSTED,
    scopes: Optional[List[str]] = None,
    expires_at: Optional[datetime] = None,
    issuer_public_key: str = "AAAA",
    signature: str = "BBBB",
) -> TrustArtifact:
    return TrustArtifact(
        did=did,
        grade=grade,
        scopes=scopes or ["read", "write"],
        issued_at=datetime.now(timezone.utc),
        expires_at=expires_at or _future(),
        issuer_public_key=issuer_public_key,
        signature=signature,
    )


class TestTrustGrade:
    def test_all_grades_have_scores(self):
        for grade in TrustGrade:
            score = grade.to_agt_score()
            assert 0 <= score <= 1000

    def test_verified_is_highest(self):
        assert TrustGrade.VERIFIED.to_agt_score() > TrustGrade.TRUSTED.to_agt_score()

    def test_revoked_is_zero(self):
        assert TrustGrade.REVOKED.to_agt_score() == 0

    def test_score_ordering(self):
        order = [
            TrustGrade.REVOKED,
            TrustGrade.UNTRUSTED,
            TrustGrade.RESTRICTED,
            TrustGrade.PROVISIONAL,
            TrustGrade.TRUSTED,
            TrustGrade.VERIFIED,
        ]
        scores = [g.to_agt_score() for g in order]
        assert scores == sorted(scores)

    def test_string_values(self):
        assert TrustGrade("verified") is TrustGrade.VERIFIED
        assert TrustGrade("revoked") is TrustGrade.REVOKED


class TestTrustArtifact:
    def test_not_expired(self):
        artifact = _make_artifact(expires_at=_future())
        assert not artifact.is_expired()

    def test_expired(self):
        artifact = _make_artifact(expires_at=_past())
        assert artifact.is_expired()

    def test_canonical_payload_is_deterministic(self):
        artifact = _make_artifact(scopes=["write", "read"])
        payload1 = artifact.canonical_payload()
        payload2 = artifact.canonical_payload()
        assert payload1 == payload2

    def test_canonical_payload_sorts_scopes(self):
        expiry = _future()
        a1 = _make_artifact(scopes=["write", "read"], expires_at=expiry)
        a2 = _make_artifact(scopes=["read", "write"], expires_at=expiry)
        assert a1.canonical_payload() == a2.canonical_payload()

    def test_canonical_payload_is_valid_json(self):
        artifact = _make_artifact()
        data = json.loads(artifact.canonical_payload())
        assert "did" in data
        assert "grade" in data
        assert "scopes" in data
        assert "expires_at" in data

    def test_round_trip_serialization(self):
        artifact = _make_artifact(
            did="did:authz:bob",
            grade=TrustGrade.VERIFIED,
            scopes=["admin", "read"],
        )
        restored = TrustArtifact.from_dict(artifact.to_dict())
        assert restored.did == artifact.did
        assert restored.grade == artifact.grade
        assert restored.scopes == artifact.scopes
        assert restored.issuer_public_key == artifact.issuer_public_key

    @requires_crypto
    def test_sign_and_verify(self):
        private_b64, public_b64 = generate_keypair()
        artifact = TrustArtifact.sign(
            did="did:authz:alice",
            grade=TrustGrade.TRUSTED,
            scopes=["read"],
            expires_at=_future(),
            private_key_b64=private_b64,
            issuer_public_key_b64=public_b64,
            issuer_id="test-authority",
        )
        assert artifact.verify_signature() is True

    @requires_crypto
    def test_tampered_payload_fails_verification(self):
        private_b64, public_b64 = generate_keypair()
        artifact = TrustArtifact.sign(
            did="did:authz:alice",
            grade=TrustGrade.TRUSTED,
            scopes=["read"],
            expires_at=_future(),
            private_key_b64=private_b64,
            issuer_public_key_b64=public_b64,
        )
        artifact.scopes = ["admin"]  # tamper after signing
        assert artifact.verify_signature() is False

    @requires_crypto
    def test_wrong_key_fails_verification(self):
        private_b64, public_b64 = generate_keypair()
        _, other_public_b64 = generate_keypair()
        artifact = TrustArtifact.sign(
            did="did:authz:alice",
            grade=TrustGrade.TRUSTED,
            scopes=["read"],
            expires_at=_future(),
            private_key_b64=private_b64,
            issuer_public_key_b64=public_b64,
        )
        artifact.issuer_public_key = other_public_b64
        assert artifact.verify_signature() is False


class TestAgentProfile:
    def test_defaults(self):
        a = _make_agent()
        assert a.trust_score == 500
        assert a.is_active
        assert a.status == "active"

    def test_has_capability(self):
        a = _make_agent(capabilities=["read", "exec"])
        assert a.has_capability("read")
        assert not a.has_capability("admin")

    def test_has_all_capabilities(self):
        a = _make_agent(capabilities=["read", "write", "exec"])
        assert a.has_all_capabilities(["read", "write"])
        assert not a.has_all_capabilities(["read", "admin"])

    def test_has_any_capability(self):
        a = _make_agent(capabilities=["read"])
        assert a.has_any_capability(["admin", "read"])
        assert not a.has_any_capability(["admin", "exec"])

    def test_inactive_statuses(self):
        for status in ("suspended", "revoked"):
            a = _make_agent(status=status)
            assert not a.is_active

    def test_to_dict(self):
        a = _make_agent(trust_score=800)
        d = a.to_dict()
        assert d["trust_score"] == 800
        assert d["did"] == a.did


class TestAuthzGate:
    def _gate(self, min_trust: int = 500) -> AuthzGate:
        # verify_signatures=False so tests work without cryptography
        return AuthzGate(min_trust_score=min_trust, verify_signatures=False)

    def test_allowed_trusted_grade(self):
        gate = self._gate()
        agent = _make_agent()
        artifact = _make_artifact(grade=TrustGrade.TRUSTED)
        decision = gate.evaluate(agent, "read data", artifact, required_scopes=["read"])
        assert decision.allowed

    def test_denied_inactive_agent(self):
        gate = self._gate()
        agent = _make_agent(status="revoked")
        artifact = _make_artifact()
        decision = gate.evaluate(agent, "read data", artifact)
        assert not decision.allowed
        assert "revoked" in decision.reason

    def test_denied_did_mismatch(self):
        gate = self._gate()
        agent = _make_agent(did="did:authz:alice")
        artifact = _make_artifact(did="did:authz:bob")
        decision = gate.evaluate(agent, "task", artifact)
        assert not decision.allowed
        assert "does not match" in decision.reason

    def test_denied_expired_artifact(self):
        gate = self._gate()
        agent = _make_agent()
        artifact = _make_artifact(expires_at=_past())
        decision = gate.evaluate(agent, "task", artifact)
        assert not decision.allowed
        assert "expired" in decision.reason

    def test_denied_low_grade(self):
        gate = self._gate(min_trust=600)
        agent = _make_agent()
        artifact = _make_artifact(grade=TrustGrade.RESTRICTED)  # maps to 300
        decision = gate.evaluate(agent, "task", artifact)
        assert not decision.allowed
        assert "below minimum" in decision.reason
        assert decision.artifact_grade == TrustGrade.RESTRICTED

    def test_denied_missing_scope(self):
        gate = self._gate()
        agent = _make_agent()
        artifact = _make_artifact(scopes=["read"])
        decision = gate.evaluate(
            agent, "admin task", artifact, required_scopes=["admin"]
        )
        assert not decision.allowed
        assert "lacks required scopes" in decision.reason

    def test_allowed_no_scope_requirement(self):
        gate = self._gate()
        agent = _make_agent()
        artifact = _make_artifact(grade=TrustGrade.VERIFIED)
        decision = gate.evaluate(agent, "general task", artifact)
        assert decision.allowed

    def test_revoked_grade_always_denied(self):
        gate = self._gate(min_trust=0)
        agent = _make_agent()
        artifact = _make_artifact(grade=TrustGrade.REVOKED)
        decision = gate.evaluate(agent, "task", artifact)
        assert not decision.allowed

    def test_grade_propagated_to_decision(self):
        gate = self._gate()
        agent = _make_agent()
        artifact = _make_artifact(grade=TrustGrade.VERIFIED)
        decision = gate.evaluate(agent, "task", artifact)
        assert decision.artifact_grade == TrustGrade.VERIFIED

    def test_provisional_grade_at_default_threshold(self):
        # PROVISIONAL maps to 500, default min is 500 — should be allowed
        gate = self._gate(min_trust=500)
        agent = _make_agent()
        artifact = _make_artifact(grade=TrustGrade.PROVISIONAL, scopes=["read"])
        decision = gate.evaluate(agent, "task", artifact, required_scopes=["read"])
        assert decision.allowed


class TestDelegationLink:
    def test_not_expired(self):
        link = DelegationLink(
            delegator_did="did:authz:root",
            delegatee_did="did:authz:agent",
            scopes=["read"],
            delegator_public_key="AAAA",
            signature="BBBB",
            expires_at=_future(),
        )
        assert not link.is_expired()

    def test_expired(self):
        link = DelegationLink(
            delegator_did="did:authz:root",
            delegatee_did="did:authz:agent",
            scopes=["read"],
            delegator_public_key="AAAA",
            signature="BBBB",
            expires_at=_past(),
        )
        assert link.is_expired()

    def test_no_expiry_is_not_expired(self):
        link = DelegationLink(
            delegator_did="did:authz:root",
            delegatee_did="did:authz:agent",
            scopes=["read"],
            delegator_public_key="AAAA",
            signature="BBBB",
            expires_at=None,
        )
        assert not link.is_expired()

    def test_canonical_payload_is_deterministic(self):
        link = DelegationLink(
            delegator_did="did:authz:root",
            delegatee_did="did:authz:agent",
            scopes=["write", "read"],
            delegator_public_key="AAAA",
            signature="BBBB",
        )
        assert link.canonical_payload() == link.canonical_payload()

    def test_canonical_payload_sorts_scopes(self):
        link1 = DelegationLink(
            delegator_did="did:authz:root",
            delegatee_did="did:authz:agent",
            scopes=["write", "read"],
            delegator_public_key="AAAA",
            signature="BBBB",
        )
        link2 = DelegationLink(
            delegator_did="did:authz:root",
            delegatee_did="did:authz:agent",
            scopes=["read", "write"],
            delegator_public_key="AAAA",
            signature="BBBB",
        )
        assert link1.canonical_payload() == link2.canonical_payload()

    def test_to_dict(self):
        link = DelegationLink(
            delegator_did="did:authz:root",
            delegatee_did="did:authz:agent",
            scopes=["read"],
            delegator_public_key="AAAA",
            signature="BBBB",
        )
        d = link.to_dict()
        assert d["delegator_did"] == "did:authz:root"
        assert d["scopes"] == ["read"]


class TestDelegationChain:
    # Helper: build a signed link when crypto is available, unsigned when not.
    # Chain validation is tested with crypto; structural tests use verify_signatures=False paths.

    def _unsigned_link(
        self,
        delegator: str,
        delegatee: str,
        scopes: list[str],
        expires_at: Optional[datetime] = None,
    ) -> DelegationLink:
        return DelegationLink(
            delegator_did=delegator,
            delegatee_did=delegatee,
            scopes=scopes,
            delegator_public_key="AAAA",
            signature="BBBB",
            expires_at=expires_at,
        )

    def test_empty_chain_validates(self):
        chain = DelegationChain("did:authz:root", ["read", "write"])
        ok, reason = chain.validate()
        assert ok
        assert reason == ""

    def test_empty_chain_scope_check(self):
        chain = DelegationChain("did:authz:root", ["read"])
        ok, reason = chain.validate(required_scopes=["admin"])
        assert not ok
        assert "admin" in reason

    def test_effective_scopes_root(self):
        chain = DelegationChain("did:authz:root", ["read", "write"])
        assert chain.effective_scopes_for("did:authz:root") == {"read", "write"}

    def test_effective_scopes_unknown_did(self):
        chain = DelegationChain("did:authz:root", ["read"])
        assert chain.effective_scopes_for("did:authz:nobody") == set()

    def test_contiguity_error(self):
        chain = DelegationChain("did:authz:root", ["read"])
        link = self._unsigned_link("did:authz:OTHER", "did:authz:agent", ["read"])
        chain.add_link(link)
        ok, reason = chain.validate()
        assert not ok
        assert "expected delegator" in reason

    def test_circular_delegation_error(self):
        chain = DelegationChain("did:authz:root", ["read"])
        link = self._unsigned_link("did:authz:root", "did:authz:root", ["read"])
        chain.add_link(link)
        ok, reason = chain.validate()
        assert not ok
        assert "circular" in reason

    def test_expired_link_error(self):
        chain = DelegationChain("did:authz:root", ["read"])
        link = self._unsigned_link(
            "did:authz:root", "did:authz:agent", ["read"], expires_at=_past()
        )
        chain.add_link(link)
        ok, reason = chain.validate()
        assert not ok
        assert "expired" in reason

    def test_scope_widening_error(self):
        chain = DelegationChain("did:authz:root", ["read"])
        # delegatee claims scopes not held by delegator
        link = self._unsigned_link(
            "did:authz:root", "did:authz:agent", ["read", "admin"]
        )
        chain.add_link(link)
        ok, reason = chain.validate(verify_signatures=False)
        assert not ok
        assert "exceed" in reason

    @requires_crypto
    def test_signed_chain_validates(self):
        import base64

        from cryptography.hazmat.primitives.asymmetric import \
            ed25519 as _ed_module

        root_priv, root_pub = generate_keypair()

        root_priv_obj = _ed_module.Ed25519PrivateKey.from_private_bytes(
            base64.b64decode(root_priv)
        )

        chain = DelegationChain("did:authz:root", ["read", "write"])
        link = DelegationLink(
            delegator_did="did:authz:root",
            delegatee_did="did:authz:agent",
            scopes=["read"],
            delegator_public_key=root_pub,
            signature="",
            expires_at=_future(),
        )
        sig = root_priv_obj.sign(link.canonical_payload().encode())
        link.signature = base64.b64encode(sig).decode("ascii")
        chain.add_link(link)

        ok, reason = chain.validate(required_scopes=["read"])
        assert ok, reason

    @requires_crypto
    def test_signed_chain_with_gate(self):
        """End-to-end: artifact + delegation chain + AuthzGate."""
        issuer_priv, issuer_pub = generate_keypair()
        root_priv, root_pub = generate_keypair()
        import base64

        from cryptography.hazmat.primitives.asymmetric import \
            ed25519 as _ed_module

        root_priv_obj = _ed_module.Ed25519PrivateKey.from_private_bytes(
            base64.b64decode(root_priv)
        )

        # Root agent receives artifact from external authority
        root_agent = _make_agent(did="did:authz:root", capabilities=["read", "write"])
        artifact = TrustArtifact.sign(
            did="did:authz:root",
            grade=TrustGrade.TRUSTED,
            scopes=["read", "write"],
            expires_at=_future(),
            private_key_b64=issuer_priv,
            issuer_public_key_b64=issuer_pub,
        )

        # Root delegates "read" to a downstream agent
        link = DelegationLink(
            delegator_did="did:authz:root",
            delegatee_did="did:authz:downstream",
            scopes=["read"],
            delegator_public_key=root_pub,
            signature="",
            expires_at=_future(),
        )
        sig = root_priv_obj.sign(link.canonical_payload().encode())
        link.signature = base64.b64encode(sig).decode("ascii")

        chain = DelegationChain("did:authz:root", ["read", "write"])
        chain.add_link(link)

        gate = AuthzGate(min_trust_score=500, verify_signatures=True)
        decision = gate.evaluate(
            root_agent,
            "read task",
            artifact,
            required_scopes=["read"],
            delegation_chain=chain,
        )
        assert decision.allowed


class TestTrustTracker:
    def test_success_reward(self):
        tracker = TrustTracker(success_reward=20)
        agent = _make_agent(trust_score=500)
        new_score = tracker.record_success(agent, "task")
        assert new_score == 520
        assert agent.trust_score == 520

    def test_failure_penalty(self):
        tracker = TrustTracker(failure_penalty=100)
        agent = _make_agent(trust_score=500)
        new_score = tracker.record_failure(agent, "task", "timeout")
        assert new_score == 400
        assert agent.trust_score == 400

    def test_clamp_max(self):
        tracker = TrustTracker(success_reward=100, max_score=1000)
        agent = _make_agent(trust_score=980)
        tracker.record_success(agent)
        assert agent.trust_score == 1000

    def test_clamp_min(self):
        tracker = TrustTracker(failure_penalty=200, min_score=0)
        agent = _make_agent(trust_score=100)
        tracker.record_failure(agent)
        assert agent.trust_score == 0

    def test_history_all(self):
        tracker = TrustTracker()
        a = _make_agent(did="did:authz:a")
        b = _make_agent(did="did:authz:b")
        tracker.record_success(a)
        tracker.record_failure(b)
        assert len(tracker.get_history()) == 2

    def test_history_filtered_by_did(self):
        tracker = TrustTracker()
        a = _make_agent(did="did:authz:a")
        b = _make_agent(did="did:authz:b")
        tracker.record_success(a, "t1")
        tracker.record_failure(b, "t2")
        history = tracker.get_history(did="did:authz:a")
        assert len(history) == 1
        assert history[0]["event"] == "success"

    def test_history_event_shape(self):
        tracker = TrustTracker()
        agent = _make_agent()
        tracker.record_failure(agent, "bad task", "policy violation")
        record = tracker.get_history()[0]
        assert record["event"] == "failure"
        assert record["reason"] == "policy violation"
        assert "old_score" in record
        assert "new_score" in record
        assert "timestamp" in record


class TestIntegration:
    def test_full_authz_lifecycle_no_crypto(self):
        """Full lifecycle without crypto: grade mapping → gate → tracker."""
        gate = AuthzGate(min_trust_score=500, verify_signatures=False)
        tracker = TrustTracker()

        agent = _make_agent(did="did:authz:worker", trust_score=600)
        artifact = _make_artifact(
            did="did:authz:worker",
            grade=TrustGrade.TRUSTED,
            scopes=["read", "write"],
        )

        decision = gate.evaluate(
            agent, "process data", artifact, required_scopes=["read"]
        )
        assert decision.allowed
        tracker.record_success(agent, "process data")
        assert agent.trust_score == 610

        # Restricted grade — denied at min_trust=500 if threshold raised
        artifact_restricted = _make_artifact(
            did="did:authz:worker",
            grade=TrustGrade.RESTRICTED,  # maps to 300
            scopes=["read"],
        )
        gate_strict = AuthzGate(min_trust_score=500, verify_signatures=False)
        decision2 = gate_strict.evaluate(agent, "restricted task", artifact_restricted)
        assert not decision2.allowed
        tracker.record_failure(agent, "restricted task", "grade too low")
        assert agent.trust_score == 560

        # Revoked artifact — always denied regardless of min_trust
        artifact_revoked = _make_artifact(
            did="did:authz:worker", grade=TrustGrade.REVOKED
        )
        gate_permissive = AuthzGate(min_trust_score=0, verify_signatures=False)
        decision3 = gate_permissive.evaluate(agent, "any task", artifact_revoked)
        assert not decision3.allowed

    def test_scope_chain_propagation(self):
        """Delegation chain correctly narrows scopes across two hops."""
        chain = DelegationChain("did:authz:root", ["read", "write", "admin"])

        # First hop: root → middle (drops admin)
        link1 = DelegationLink(
            delegator_did="did:authz:root",
            delegatee_did="did:authz:middle",
            scopes=["read", "write"],
            delegator_public_key="AAAA",
            signature="",
        )
        # Second hop: middle → leaf (drops write)
        link2 = DelegationLink(
            delegator_did="did:authz:middle",
            delegatee_did="did:authz:leaf",
            scopes=["read"],
            delegator_public_key="BBBB",
            signature="",
        )
        chain.add_link(link1)
        chain.add_link(link2)

        # Without signature verification (no crypto), only structural checks run
        # Signatures will fail → validate() returns False due to invalid sig.
        # Test structural scope narrowing logic via effective_scopes_for instead.
        assert chain.effective_scopes_for("did:authz:middle") == {"read", "write"}
        assert chain.effective_scopes_for("did:authz:leaf") == {"read"}
        assert chain.effective_scopes_for("did:authz:root") == {
            "read",
            "write",
            "admin",
        }

    def test_imports(self):
        from structural_authz_agentmesh import (AgentProfile, AuthzGate,
                                                DelegationChain,
                                                DelegationLink, TrustArtifact,
                                                TrustGrade, TrustTracker,
                                                generate_keypair)

        assert all(
            cls is not None
            for cls in [
                AgentProfile,
                AuthzDecision,
                AuthzGate,
                ChainValidationError,
                DelegationChain,
                DelegationLink,
                TrustArtifact,
                TrustGrade,
                TrustTracker,
                generate_keypair,
            ]
        )
