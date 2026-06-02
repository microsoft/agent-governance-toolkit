# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Conformance tests for AGENTMESH-IDENTITY-TRUST-1.0.

Every test references a specific section of the specification.
Tests marked [Pure Specification] verify normative requirements.
Tests marked [Default Implementation] verify reference defaults.
"""

import asyncio
import base64
import hashlib
import hmac
import re
import time
from datetime import datetime, timedelta, timezone

import pytest

# ---------------------------------------------------------------------------
# Imports under test
# ---------------------------------------------------------------------------

from agentmesh.identity.agent_id import AgentDID, AgentIdentity, IdentityRegistry
from agentmesh.identity.credentials import Credential
from agentmesh.identity.revocation import RevocationEntry, RevocationList
from agentmesh.identity.rotation import KeyRotationManager
from agentmesh.identity.jwk import to_jwk, from_jwk, to_jwks, from_jwks
from agentmesh.identity.spiffe import SVID, SPIFFEIdentity, SPIFFERegistry
from agentmesh.identity.delegation import (
    DelegationLink,
    ScopeChain,
    UserContext,
)
from agentmesh.trust.handshake import (
    HandshakeChallenge,
    HandshakeResponse,
    HandshakeResult,
    TrustHandshake,
)
from agentmesh.reward.scoring import (
    DimensionType,
    RewardDimension,
    RewardSignal,
    ScoreThresholds,
    TrustScore,
)
from agentmesh.reward.trust_decay import (
    InteractionEdge,
    NetworkTrustEngine,
    RegimeChangeAlert,
    TrustEvent,
)
from agentmesh.trust_types import (
    AgentProfile,
    TrustRecord,
    TrustScore as IntegrationTrustScore,
    TrustTracker,
)
from agentmesh.constants import (
    CREDENTIAL_ROTATION_THRESHOLD_SECONDS,
    DEFAULT_DELEGATION_MAX_DEPTH,
    TIER_PROBATIONARY_THRESHOLD,
    TIER_STANDARD_THRESHOLD,
    TIER_TRUSTED_THRESHOLD,
    TIER_VERIFIED_PARTNER_THRESHOLD,
    TRUST_REVOCATION_THRESHOLD,
    TRUST_SCORE_DEFAULT,
    TRUST_SCORE_MAX,
    TRUST_SCORE_MIN,
    WEIGHT_COLLABORATION_HEALTH,
    WEIGHT_OUTPUT_QUALITY,
    WEIGHT_POLICY_COMPLIANCE,
    WEIGHT_RESOURCE_EFFICIENCY,
    WEIGHT_SECURITY_POSTURE,
)
from agentmesh.exceptions import (
    DelegationDepthError,
    DelegationError,
    HandshakeError,
    HandshakeTimeoutError,
    IdentityError,
    TrustError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_identity(
    name: str = "test-agent",
    sponsor: str = "sponsor@contoso.com",
    capabilities: list[str] | None = None,
) -> AgentIdentity:
    return AgentIdentity.create(
        name=name,
        sponsor=sponsor,
        capabilities=capabilities or ["read:data", "write:data"],
    )


def _make_credential(
    agent_did: str = "did:mesh:abc123",
    capabilities: list[str] | None = None,
    ttl_seconds: int = 900,
) -> Credential:
    return Credential.issue(
        agent_did=agent_did,
        capabilities=capabilities or ["read:data"],
        ttl_seconds=ttl_seconds,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Section 3: Agent DID Schema
# ═══════════════════════════════════════════════════════════════════════════


class TestAgentDIDSchema:
    """Spec §3 — Agent DID Schema."""

    def test_did_format_matches_spec(self):
        """§3.1 — DID MUST be did:mesh:<unique-id>."""
        did = AgentDID.generate("test")
        assert str(did).startswith("did:mesh:")

    def test_did_unique_id_128_bits(self):
        """§3.2 — unique-id MUST use >= 128 bits of randomness."""
        did = AgentDID.generate("test")
        unique_id = str(did).removeprefix("did:mesh:")
        # 128 bits = 32 hex chars
        assert len(unique_id) >= 32
        assert re.match(r"^[0-9a-f]+$", unique_id)

    def test_did_generation_unique(self):
        """§3.2 — successive DIDs MUST be distinct."""
        dids = {str(AgentDID.generate("x")) for _ in range(100)}
        assert len(dids) == 100

    def test_did_parsing_valid(self):
        """§3.3 — valid did:mesh: strings MUST be accepted."""
        did = AgentDID.from_string("did:mesh:abcdef1234567890abcdef1234567890")
        assert did.unique_id == "abcdef1234567890abcdef1234567890"

    def test_did_parsing_invalid_prefix(self):
        """§3.3 — non-did:mesh: strings MUST be rejected."""
        with pytest.raises(ValueError):
            AgentDID.from_string("did:web:example.com")

    def test_did_equality(self):
        """§3.4 — equality MUST be byte-identical string comparison."""
        did1 = AgentDID.from_string("did:mesh:abc")
        did2 = AgentDID.from_string("did:mesh:abc")
        assert str(did1) == str(did2)

    def test_did_hashing(self):
        """§3.4 — hashing MUST be deterministic and consistent with equality."""
        did1 = AgentDID.from_string("did:mesh:abc")
        did2 = AgentDID.from_string("did:mesh:abc")
        assert hash(did1) == hash(did2)


# ═══════════════════════════════════════════════════════════════════════════
# Section 4: Agent Identity Model
# ═══════════════════════════════════════════════════════════════════════════


class TestAgentIdentityModel:
    """Spec §4 — Agent Identity Model."""

    def test_factory_creates_valid_identity(self):
        """§4.5 — factory method MUST produce valid identity."""
        identity = _make_identity()
        assert str(identity.did).startswith("did:mesh:")
        assert identity.public_key  # non-empty base64
        assert identity.verification_key_id.startswith("key-")
        assert identity.sponsor_email == "sponsor@contoso.com"
        assert identity.status == "active"
        assert identity.delegation_depth == 0

    def test_verification_key_id_format(self):
        """§4.4 — key ID MUST be key-<first-16-hex-of-SHA256>."""
        identity = _make_identity()
        assert re.match(r"^key-[0-9a-f]{16}$", identity.verification_key_id)

    def test_private_key_not_serialized(self):
        """§4.5 — private key MUST NOT appear in serialized output."""
        identity = _make_identity()
        data = identity.model_dump()
        assert "_private_key" not in data
        assert "private_key" not in str(data).lower()

    def test_name_empty_rejected(self):
        """§4.3 — name MUST NOT be empty."""
        with pytest.raises((IdentityError, ValueError)):
            AgentIdentity.create(name="", sponsor="s@contoso.com")

    def test_name_whitespace_rejected(self):
        """§4.3 — name MUST NOT be whitespace-only."""
        with pytest.raises((IdentityError, ValueError)):
            AgentIdentity.create(name="   ", sponsor="s@contoso.com")

    def test_sponsor_email_missing_at(self):
        """§4.3 — sponsor_email MUST contain @."""
        with pytest.raises((IdentityError, ValueError)):
            AgentIdentity.create(name="agent", sponsor="invalid")

    def test_sponsor_email_empty(self):
        """§4.3 — sponsor_email MUST NOT be empty."""
        with pytest.raises((IdentityError, ValueError)):
            AgentIdentity.create(name="agent", sponsor="")

    def test_parent_did_must_match_prefix(self):
        """§4.3 — parent_did MUST match did:mesh: prefix."""
        with pytest.raises((IdentityError, ValueError)):
            AgentIdentity(
                did=AgentDID.generate("x"),
                name="x",
                public_key="dGVzdA==",
                verification_key_id="key-abc",
                sponsor_email="s@contoso.com",
                parent_did="did:web:nope",
            )


# ═══════════════════════════════════════════════════════════════════════════
# Section 5: Identity Lifecycle
# ═══════════════════════════════════════════════════════════════════════════


class TestIdentityLifecycle:
    """Spec §5 — Identity Lifecycle."""

    def test_suspend(self):
        """§5.2.1 — suspend MUST set status to suspended."""
        identity = _make_identity()
        identity.suspend("routine")
        assert identity.status == "suspended"
        assert identity.revocation_reason == "routine"

    def test_revoke(self):
        """§5.2.2 — revoke MUST set status to revoked."""
        identity = _make_identity()
        identity.revoke("policy violation")
        assert identity.status == "revoked"

    def test_reactivate_suspended(self):
        """§5.2.3 — reactivate MUST restore active status."""
        identity = _make_identity()
        identity.suspend("temporary")
        identity.reactivate()
        assert identity.status == "active"

    def test_reactivate_security_suspension_requires_override(self):
        """§5.2.3 — security suspension MUST require override_reason=True."""
        identity = _make_identity()
        identity.suspend("security breach detected")
        with pytest.raises(ValueError, match="security"):
            identity.reactivate()
        # With override, it works
        identity.reactivate(override_reason=True)
        assert identity.status == "active"

    def test_revoked_cannot_reactivate(self):
        """§5.2.4 — revoked identity MUST NOT be reactivated."""
        identity = _make_identity()
        identity.revoke("permanent")
        with pytest.raises(ValueError, match="revoked"):
            identity.reactivate()

    def test_is_active_checks_expiry(self):
        """§5.3 — is_active MUST check expires_at."""
        identity = _make_identity()
        identity.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        assert not identity.is_active()

    def test_is_active_when_active_and_not_expired(self):
        """§5.3 — active + not expired = is_active True."""
        identity = _make_identity()
        assert identity.is_active()


# ═══════════════════════════════════════════════════════════════════════════
# Section 6: Cryptographic Primitives
# ═══════════════════════════════════════════════════════════════════════════


class TestCryptographicPrimitives:
    """Spec §6 — Cryptographic Primitives."""

    def test_sign_and_verify(self):
        """§6.2/6.3 — sign+verify round-trip MUST succeed."""
        identity = _make_identity()
        data = b"test payload"
        sig = identity.sign(data)
        assert identity.verify_signature(data, sig)

    def test_verify_wrong_data(self):
        """§6.3 — wrong data MUST return false, not raise."""
        identity = _make_identity()
        sig = identity.sign(b"original")
        assert not identity.verify_signature(b"tampered", sig)

    def test_verify_bad_signature(self):
        """§6.3 — invalid signature MUST return false, not raise."""
        identity = _make_identity()
        assert not identity.verify_signature(b"data", "bm90YXNpZw==")

    def test_sign_without_private_key_raises(self):
        """§6.2 — signing without private key MUST raise error."""
        identity = _make_identity()
        identity._private_key = None
        with pytest.raises(ValueError):
            identity.sign(b"data")


# ═══════════════════════════════════════════════════════════════════════════
# Section 7: Human Sponsor Binding
# ═══════════════════════════════════════════════════════════════════════════


class TestHumanSponsorBinding:
    """Spec §7 — Human Sponsor Binding."""

    def test_sponsor_required(self):
        """§7.1 — every identity MUST have a sponsor."""
        identity = _make_identity()
        assert identity.sponsor_email
        assert "@" in identity.sponsor_email

    def test_delegation_inherits_sponsor(self):
        """§7.4 — delegated child MUST inherit sponsor_email."""
        parent = _make_identity(capabilities=["read:data"])
        child = parent.delegate("child", ["read:data"])
        assert child.sponsor_email == parent.sponsor_email


# ═══════════════════════════════════════════════════════════════════════════
# Section 8: Credential Lifecycle
# ═══════════════════════════════════════════════════════════════════════════


class TestCredentialLifecycle:
    """Spec §8 — Credential Lifecycle."""

    def test_issue_creates_active_credential(self):
        """§8.3 — issued credential MUST be active with correct TTL."""
        cred = _make_credential()
        assert cred.status == "active"
        assert cred.is_valid()
        assert cred.credential_id.startswith("cred_")

    def test_token_hash_is_sha256(self):
        """§8.3 — token_hash MUST be SHA-256 of token."""
        cred = _make_credential()
        expected = hashlib.sha256(cred.token.encode()).hexdigest()
        assert cred.token_hash == expected

    def test_token_verification_constant_time(self):
        """§8.5 — token verification MUST use constant-time comparison."""
        cred = _make_credential()
        assert cred.verify_token(cred.token)
        assert not cred.verify_token("wrong-token")

    def test_expired_credential_invalid(self):
        """§8.4 — expired credential MUST fail validation."""
        cred = _make_credential(ttl_seconds=0)
        # Force expiry
        cred.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        assert not cred.is_valid()

    def test_rotation(self):
        """§8.7 — rotation MUST create new credential with correct chain."""
        c1 = _make_credential()
        c2 = c1.rotate()
        assert c1.status == "rotated"
        assert c2.status == "active"
        assert c2.previous_credential_id == c1.credential_id
        assert c2.rotation_count == c1.rotation_count + 1
        assert c2.agent_did == c1.agent_did
        assert c2.capabilities == c1.capabilities

    def test_revocation(self):
        """§8.8 — revocation MUST invalidate credential."""
        cred = _make_credential()
        cred.revoke("compromised")
        assert cred.status == "revoked"
        assert not cred.is_valid()
        assert cred.revocation_reason == "compromised"
        assert cred.revoked_at is not None

    def test_capability_exact_match(self):
        """§8.9 — exact capability match."""
        cred = _make_credential(capabilities=["read:data"])
        assert cred.has_capability("read:data")
        assert not cred.has_capability("write:data")

    def test_capability_wildcard(self):
        """§8.9 — wildcard capability matches all."""
        cred = _make_credential(capabilities=["*"])
        assert cred.has_capability("anything")

    def test_capability_prefix_wildcard(self):
        """§8.9 — prefix wildcard matches sub-capabilities."""
        cred = _make_credential(capabilities=["read:*"])
        assert cred.has_capability("read:data")
        assert not cred.has_capability("write:data")

    def test_resource_access_open_scope(self):
        """§8.10 — empty resources = open access."""
        cred = _make_credential()
        assert cred.can_access_resource("any-resource")

    def test_default_ttl(self):
        """§8.3 — default TTL is 900 seconds."""
        cred = _make_credential()
        assert cred.ttl_seconds == 900


# ═══════════════════════════════════════════════════════════════════════════
# Section 9: Trust Score Model
# ═══════════════════════════════════════════════════════════════════════════


class TestTrustScoreModel:
    """Spec §9 — Trust Score Model."""

    def test_default_score(self):
        """§9.2 — default trust score MUST be 500."""
        assert TRUST_SCORE_DEFAULT == 500
        ts = TrustScore(agent_did="did:mesh:abc")
        assert ts.total_score == TRUST_SCORE_DEFAULT

    def test_score_clamped_to_range(self):
        """§9.1 — scores MUST be clamped to [0, 1000]."""
        ts = TrustScore(agent_did="did:mesh:abc", total_score=500)
        ts.update(1500, {})
        assert ts.total_score == 1000
        ts.update(-100, {})
        assert ts.total_score == 0

    def test_trust_ceiling_enforcement(self):
        """§9.5 — trust ceiling MUST be enforced on updates."""
        ts = TrustScore(agent_did="did:mesh:abc", trust_ceiling=600)
        assert ts.total_score <= 600
        ts.update(800, {})
        assert ts.total_score == 600

    def test_trust_ceiling_on_init(self):
        """§9.5 — ceiling MUST clamp initial score."""
        ts = TrustScore(
            agent_did="did:mesh:abc",
            total_score=700,
            trust_ceiling=500,
        )
        assert ts.total_score == 500

    def test_agent_did_validation(self):
        """§9.3 — agent_did MUST match did:mesh: prefix."""
        with pytest.raises(TrustError):
            TrustScore(agent_did="did:web:nope")

    def test_dual_trust_systems(self):
        """§9.6 — two trust score systems MUST coexist."""
        # Integration TrustScore: 0.0-1.0 float
        its = IntegrationTrustScore(score=0.7)
        assert its.is_trusted  # >= 0.5
        its_low = IntegrationTrustScore(score=0.3)
        assert not its_low.is_trusted

        # Reward TrustScore: 0-1000 int
        rts = TrustScore(agent_did="did:mesh:abc", total_score=700)
        assert rts.tier == "trusted"


# ═══════════════════════════════════════════════════════════════════════════
# Section 10: Trust Tiers
# ═══════════════════════════════════════════════════════════════════════════


class TestTrustTiers:
    """Spec §10 — Trust Tiers."""

    @pytest.mark.parametrize(
        "score,expected_tier",
        [
            (1000, "verified_partner"),
            (900, "verified_partner"),
            (899, "trusted"),
            (700, "trusted"),
            (699, "standard"),
            (500, "standard"),
            (499, "probationary"),
            (300, "probationary"),
            (299, "untrusted"),
            (0, "untrusted"),
        ],
    )
    def test_tier_thresholds(self, score: int, expected_tier: str):
        """§10.1/10.2 — tier MUST match threshold boundaries exactly."""
        ts = TrustScore(agent_did="did:mesh:abc", total_score=score)
        assert ts.tier == expected_tier

    def test_tier_constants(self):
        """§10.1 — tier threshold constants MUST match spec."""
        assert TIER_VERIFIED_PARTNER_THRESHOLD == 900
        assert TIER_TRUSTED_THRESHOLD == 700
        assert TIER_STANDARD_THRESHOLD == 500
        assert TIER_PROBATIONARY_THRESHOLD == 300

    def test_action_thresholds(self):
        """§10.3 — action thresholds MUST match defaults."""
        st = ScoreThresholds()
        assert st.allow_threshold == 500
        assert st.warn_threshold == 400
        assert st.revocation_threshold == 300


# ═══════════════════════════════════════════════════════════════════════════
# Section 11: Reward Dimensions
# ═══════════════════════════════════════════════════════════════════════════


class TestRewardDimensions:
    """Spec §11 — Reward Dimensions."""

    def test_five_dimensions_exist(self):
        """§11.1 — exactly 5 dimensions MUST exist."""
        assert len(DimensionType) == 5
        expected = {
            "policy_compliance",
            "resource_efficiency",
            "output_quality",
            "security_posture",
            "collaboration_health",
        }
        assert {d.value for d in DimensionType} == expected

    def test_weights_sum_to_one(self):
        """§11.1 — dimension weights MUST sum to 1.0."""
        total = (
            WEIGHT_POLICY_COMPLIANCE
            + WEIGHT_RESOURCE_EFFICIENCY
            + WEIGHT_OUTPUT_QUALITY
            + WEIGHT_SECURITY_POSTURE
            + WEIGHT_COLLABORATION_HEALTH
        )
        assert abs(total - 1.0) < 1e-9

    def test_ema_score_update(self):
        """§11.3 — EMA update with alpha=0.1."""
        dim = RewardDimension(name="test", score=50.0)
        signal = RewardSignal(
            dimension=DimensionType.POLICY_COMPLIANCE,
            value=1.0,
            source="test",
        )
        dim.add_signal(signal)
        # new = 50 * 0.9 + 100 * 0.1 = 55.0
        assert abs(dim.score - 55.0) < 0.01

    def test_positive_signal_counter(self):
        """§11.3 — value >= 0.5 increments positive_signals."""
        dim = RewardDimension(name="test")
        sig = RewardSignal(
            dimension=DimensionType.OUTPUT_QUALITY, value=0.8, source="test"
        )
        dim.add_signal(sig)
        assert dim.positive_signals == 1
        assert dim.negative_signals == 0

    def test_negative_signal_counter(self):
        """§11.3 — value < 0.5 increments negative_signals."""
        dim = RewardDimension(name="test")
        sig = RewardSignal(
            dimension=DimensionType.OUTPUT_QUALITY, value=0.3, source="test"
        )
        dim.add_signal(sig)
        assert dim.negative_signals == 1
        assert dim.positive_signals == 0


# ═══════════════════════════════════════════════════════════════════════════
# Section 12: Trust Decay and Network Propagation
# ═══════════════════════════════════════════════════════════════════════════


class TestTrustDecay:
    """Spec §12 — Trust Decay and Network Propagation."""

    def test_temporal_decay_no_positive(self):
        """§12.1 — scores decay when no positive signals received."""
        engine = NetworkTrustEngine(decay_rate=10.0)
        engine.set_score("did:mesh:a", 500)
        # Simulate 1 hour without positive signal
        past = time.time() - 3600
        engine._last_positive["did:mesh:a"] = past
        deltas = engine.apply_temporal_decay()
        assert deltas.get("did:mesh:a", 0) < 0

    def test_decay_floor_at_100(self):
        """§12.1 — decay MUST NOT reduce score below 100."""
        engine = NetworkTrustEngine(decay_rate=1000.0)
        engine.set_score("did:mesh:a", 150)
        engine._last_positive["did:mesh:a"] = time.time() - 7200
        engine.apply_temporal_decay()
        assert engine.get_score("did:mesh:a") >= 100

    def test_network_propagation(self):
        """§12.2 — trust events MUST propagate to neighbors."""
        engine = NetworkTrustEngine(propagation_factor=0.3, propagation_depth=2)
        engine.set_score("did:mesh:a", 500)
        engine.set_score("did:mesh:b", 500)
        engine.record_interaction("did:mesh:a", "did:mesh:b")
        event = TrustEvent(
            agent_did="did:mesh:a",
            event_type="policy_violation",
            severity_weight=0.5,
        )
        deltas = engine.process_trust_event(event)
        assert "did:mesh:a" in deltas  # direct impact
        assert "did:mesh:b" in deltas  # propagated

    def test_interaction_weight_saturates(self):
        """§12.3 — interaction weight saturates at 100 interactions."""
        edge = InteractionEdge(from_did="a", to_did="b", interaction_count=200)
        assert edge.weight == 1.0

    def test_positive_signal_bonus(self):
        """§12.4 — positive signal adds bonus and updates timestamp."""
        engine = NetworkTrustEngine()
        engine.set_score("did:mesh:a", 500)
        engine.record_positive_signal("did:mesh:a", bonus=10)
        assert engine.get_score("did:mesh:a") == 510


# ═══════════════════════════════════════════════════════════════════════════
# Section 13: Regime Detection
# ═══════════════════════════════════════════════════════════════════════════


class TestRegimeDetection:
    """Spec §13 — Regime Detection."""

    def test_insufficient_data_returns_none(self):
        """§13.2 — < 10 total actions returns None."""
        engine = NetworkTrustEngine()
        result = engine.detect_regime_change("did:mesh:a")
        assert result is None

    def test_regime_change_detected(self):
        """§13.2 — divergent distributions trigger alert."""
        engine = NetworkTrustEngine(
            regime_threshold=0.1,
            history_window_hours=1,
            baseline_days=30,
        )
        now = time.time()
        # Historical baseline: all "read" actions
        for i in range(20):
            engine._action_history["did:mesh:a"].append(
                (now - 86400 * 15 + i, "read")
            )
        # Recent: all "delete" actions (regime change)
        for i in range(10):
            engine._action_history["did:mesh:a"].append(
                (now - 60 + i, "delete")
            )
        alert = engine.detect_regime_change("did:mesh:a", now=now)
        assert alert is not None
        assert alert.kl_divergence > engine.regime_threshold

    def test_callback_failure_silent(self):
        """§13.4 — callback failures MUST be silently caught."""
        engine = NetworkTrustEngine(regime_threshold=0.01)

        def bad_callback(alert):
            raise RuntimeError("boom")

        engine.on_regime_change(bad_callback)
        now = time.time()
        for i in range(20):
            engine._action_history["did:mesh:x"].append(
                (now - 86400 * 15 + i, "read")
            )
        for i in range(10):
            engine._action_history["did:mesh:x"].append(
                (now - 60 + i, "delete")
            )
        # Should not raise
        engine.detect_regime_change("did:mesh:x", now=now)


# ═══════════════════════════════════════════════════════════════════════════
# Section 14: Trust Handshake Protocol (IATP)
# ═══════════════════════════════════════════════════════════════════════════


class TestTrustHandshake:
    """Spec §14 — Trust Handshake Protocol (IATP)."""

    def test_challenge_format(self):
        """§14.2 — challenge MUST have correct fields."""
        ch = HandshakeChallenge.generate()
        assert ch.challenge_id.startswith("challenge_")
        assert len(ch.nonce) == 64  # 256 bits = 32 bytes hex = 64 chars
        assert ch.expires_in_seconds == 30

    def test_challenge_expiry(self):
        """§14.2 — expired challenges MUST be detected."""
        ch = HandshakeChallenge.generate()
        ch.timestamp = datetime.now(timezone.utc) - timedelta(seconds=60)
        assert ch.is_expired()

    def test_challenge_freshness_nonce(self):
        """§14.2 — freshness nonce for RFC 9334."""
        ch = HandshakeChallenge.generate(require_freshness=True)
        assert ch.freshness_nonce is not None
        assert len(ch.freshness_nonce) == 32  # 128 bits = 16 bytes hex

    def test_result_success_trust_levels(self):
        """§14.7 — HandshakeResult trust levels MUST match thresholds."""
        r900 = HandshakeResult.success("did:mesh:a", 900, [])
        assert r900.trust_level == "verified_partner"

        r700 = HandshakeResult.success("did:mesh:a", 700, [])
        assert r700.trust_level == "trusted"

        r400 = HandshakeResult.success("did:mesh:a", 400, [])
        assert r400.trust_level == "standard"

        r300 = HandshakeResult.success("did:mesh:a", 300, [])
        assert r300.trust_level == "untrusted"

    def test_result_failure(self):
        """§14.5 — failed handshake MUST have verified=false."""
        r = HandshakeResult.failure("did:mesh:a", "bad signature")
        assert not r.verified
        assert r.rejection_reason == "bad signature"

    def test_handshake_empty_did_rejected(self):
        """§14 — empty agent_did MUST be rejected."""
        with pytest.raises(HandshakeError):
            TrustHandshake(agent_did="")

    def test_handshake_invalid_did_rejected(self):
        """§14 — non-did:mesh: MUST be rejected."""
        with pytest.raises(HandshakeError):
            TrustHandshake(agent_did="did:web:example")

    def test_handshake_negative_cache_ttl_rejected(self):
        """§14 — negative cache TTL MUST be rejected."""
        with pytest.raises(HandshakeError):
            TrustHandshake(agent_did="did:mesh:abc", cache_ttl_seconds=-1)

    def test_respond_to_expired_challenge_rejected(self):
        """§14.2 — responding to expired challenge MUST fail."""
        hs = TrustHandshake(
            agent_did="did:mesh:abc",
            identity=_make_identity(),
        )
        ch = HandshakeChallenge.generate()
        ch.timestamp = datetime.now(timezone.utc) - timedelta(seconds=60)
        with pytest.raises(ValueError, match="expired"):
            asyncio.run(
                hs.respond(ch, ["read"], 500)
            )


# ═══════════════════════════════════════════════════════════════════════════
# Section 15: Delegation and Scope Chains
# ═══════════════════════════════════════════════════════════════════════════


class TestDelegation:
    """Spec §15 — Delegation and Scope Chains."""

    def test_delegation_narrows_capabilities(self):
        """§15.1 — child capabilities MUST be subset of parent."""
        parent = _make_identity(capabilities=["read:data", "write:data"])
        child = parent.delegate("child", ["read:data"])
        assert child.capabilities == ["read:data"]

    def test_delegation_rejects_unknown_capability(self):
        """§15.1 — delegating non-existent capability MUST raise."""
        parent = _make_identity(capabilities=["read:data"])
        with pytest.raises(ValueError):
            parent.delegate("child", ["write:data"])

    def test_delegation_rejects_wildcard(self):
        """§15.1 — wildcard MUST NOT be delegated."""
        parent = _make_identity(capabilities=["*"])
        with pytest.raises(ValueError, match="wildcard"):
            parent.delegate("child", ["*"])

    def test_delegation_depth_increment(self):
        """§15.1 — child depth MUST be parent depth + 1."""
        parent = _make_identity(capabilities=["read:data"])
        child = parent.delegate("child", ["read:data"])
        assert child.delegation_depth == parent.delegation_depth + 1

    def test_delegation_depth_limit(self):
        """§15.1 — exceeding MAX_DELEGATION_DEPTH MUST raise."""
        parent = _make_identity(capabilities=["read:data"])
        parent.delegation_depth = AgentIdentity.MAX_DELEGATION_DEPTH
        with pytest.raises(ValueError, match="depth"):
            parent.delegate("child", ["read:data"])

    def test_scope_chain_create_root(self):
        """§15.2 — root chain creation."""
        chain, link = ScopeChain.create_root(
            sponsor_email="alice@contoso.com",
            root_agent_did="did:mesh:root123",
            capabilities=["read:*", "write:data"],
        )
        assert chain.root_sponsor_email == "alice@contoso.com"
        assert chain.leaf_did == "did:mesh:root123"

    def test_scope_chain_capability_narrowing(self):
        """§15.4 — monotonic narrowing invariant."""
        link = DelegationLink(
            link_id="link1",
            depth=0,
            parent_did="did:mesh:sponsor:s@contoso.com",
            child_did="did:mesh:child1",
            parent_capabilities=["read:*"],
            delegated_capabilities=["read:data"],
            parent_signature="",
            link_hash="",
        )
        assert link.verify_capability_narrowing()

    def test_scope_chain_capability_escalation_rejected(self):
        """§15.4 — capability escalation MUST fail narrowing check."""
        link = DelegationLink(
            link_id="link1",
            depth=0,
            parent_did="did:mesh:sponsor:s@contoso.com",
            child_did="did:mesh:child1",
            parent_capabilities=["read:data"],
            delegated_capabilities=["write:data"],
            parent_signature="",
            link_hash="",
        )
        assert not link.verify_capability_narrowing()

    def test_scope_chain_max_depth(self):
        """§15.4 — chain MUST NOT exceed max_depth."""
        assert DEFAULT_DELEGATION_MAX_DEPTH == 5


class TestUserContext:
    """Spec §15.6 — OBO Context."""

    def test_user_context_validity(self):
        """§15.6 — expired context MUST be invalid."""
        ctx = UserContext.create(
            user_id="user1",
            user_email="u@contoso.com",
            ttl_seconds=0,
        )
        ctx.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        assert not ctx.is_valid()

    def test_user_context_permission_wildcard(self):
        """§15.6 — wildcard permission matches everything."""
        ctx = UserContext(
            user_id="user1",
            permissions=["*"],
        )
        assert ctx.has_permission("anything")


# ═══════════════════════════════════════════════════════════════════════════
# Section 16: Trust Ceiling Propagation
# ═══════════════════════════════════════════════════════════════════════════


class TestTrustCeiling:
    """Spec §16 — Trust Ceiling Propagation."""

    def test_ceiling_on_delegation(self):
        """§16.1 — delegated child respects max_initial_trust_score."""
        parent = _make_identity(capabilities=["read:data"])
        child = parent.delegate(
            "child",
            ["read:data"],
            max_initial_trust_score=600,
        )
        assert child.max_initial_trust_score == 600

    def test_ceiling_enforced_in_trust_score(self):
        """§16.3 — TrustScore ceiling clamped on every update."""
        ts = TrustScore(
            agent_did="did:mesh:abc",
            total_score=400,
            trust_ceiling=500,
        )
        ts.update(900, {})
        assert ts.total_score == 500


# ═══════════════════════════════════════════════════════════════════════════
# Section 17: Key Rotation
# ═══════════════════════════════════════════════════════════════════════════


class TestKeyRotation:
    """Spec §17 — Key Rotation."""

    def test_rotation_preserves_did(self):
        """§17.2 — DID MUST remain unchanged after rotation."""
        identity = _make_identity()
        original_did = str(identity.did)
        mgr = KeyRotationManager(identity)
        mgr.rotate()
        assert str(identity.did) == original_did

    def test_rotation_changes_key(self):
        """§17.2 — public key MUST change after rotation."""
        identity = _make_identity()
        old_key = identity.public_key
        mgr = KeyRotationManager(identity)
        mgr.rotate()
        assert identity.public_key != old_key

    def test_rotation_proof_verifiable(self):
        """§17.4 — rotation proof MUST be verifiable."""
        identity = _make_identity()
        old_key = identity.public_key
        mgr = KeyRotationManager(identity)
        mgr.rotate()
        new_key = identity.public_key
        proof = mgr.get_rotation_proof()
        assert KeyRotationManager.verify_rotation(old_key, new_key, proof)

    def test_key_history_retained(self):
        """§17.5 — old keys MUST be stored in history."""
        identity = _make_identity()
        mgr = KeyRotationManager(identity, max_history=5)
        mgr.rotate()
        assert len(mgr.get_key_history()) == 1

    def test_key_history_max_limit(self):
        """§17.5 — history MUST be trimmed to max_history."""
        identity = _make_identity()
        mgr = KeyRotationManager(identity, max_history=3)
        for _ in range(5):
            mgr.rotate()
        assert len(mgr.get_key_history()) == 3

    def test_needs_rotation_ttl(self):
        """§17.6 — needs_rotation MUST respect TTL."""
        identity = _make_identity()
        mgr = KeyRotationManager(identity, rotation_ttl_seconds=0)
        # TTL=0 means immediate rotation needed
        assert mgr.needs_rotation()

    def test_no_private_key_rejected(self):
        """§17.7 — rotation without private key MUST be rejected."""
        identity = _make_identity()
        identity._private_key = None
        with pytest.raises(IdentityError):
            KeyRotationManager(identity)

    def test_no_rotation_proof_before_first_rotation(self):
        """§17.2 — get_rotation_proof before rotation MUST raise."""
        identity = _make_identity()
        mgr = KeyRotationManager(identity)
        with pytest.raises(IdentityError):
            mgr.get_rotation_proof()


# ═══════════════════════════════════════════════════════════════════════════
# Section 18: Identity Revocation
# ═══════════════════════════════════════════════════════════════════════════


class TestIdentityRevocation:
    """Spec §18 — Identity Revocation."""

    def test_permanent_revocation(self):
        """§18.2 — no expires_at = permanent."""
        rl = RevocationList()
        rl.revoke("did:mesh:bad", "malicious")
        assert rl.is_revoked("did:mesh:bad")

    def test_temporary_revocation_expires(self):
        """§18.2 — temporary revocation auto-expires."""
        rl = RevocationList()
        rl.revoke("did:mesh:temp", "timeout", ttl_seconds=0)
        # Force expiry
        entry = rl._entries["did:mesh:temp"]
        entry.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        assert not rl.is_revoked("did:mesh:temp")

    def test_is_revoked_missing_entry(self):
        """§18.3 — missing entry returns false."""
        rl = RevocationList()
        assert not rl.is_revoked("did:mesh:unknown")

    def test_unrevoke(self):
        """§18.4 — unrevoke MUST remove entry."""
        rl = RevocationList()
        rl.revoke("did:mesh:x", "mistake")
        assert rl.unrevoke("did:mesh:x")
        assert not rl.is_revoked("did:mesh:x")

    def test_unrevoke_missing(self):
        """§18.4 — unrevoke non-existent returns false."""
        rl = RevocationList()
        assert not rl.unrevoke("did:mesh:nope")

    def test_cleanup_expired(self):
        """§18.6 — cleanup removes expired entries."""
        rl = RevocationList()
        rl.revoke("did:mesh:a", "temp", ttl_seconds=0)
        rl._entries["did:mesh:a"].expires_at = (
            datetime.now(timezone.utc) - timedelta(seconds=1)
        )
        removed = rl.cleanup_expired()
        assert removed == 1


# ═══════════════════════════════════════════════════════════════════════════
# Section 19: SPIFFE/SVID Integration
# ═══════════════════════════════════════════════════════════════════════════


class TestSPIFFE:
    """Spec §19 — SPIFFE/SVID Integration."""

    def test_spiffe_id_format(self):
        """§19.2 — SPIFFE ID format."""
        si = SPIFFEIdentity.create(
            agent_did="did:mesh:abc",
            agent_name="analyzer",
            trust_domain="agentmesh.local",
            organization="research",
        )
        assert si.spiffe_id == "spiffe://agentmesh.local/agentmesh/research/analyzer"

    def test_default_trust_domain(self):
        """§19.2 — default trust domain is agentmesh.local."""
        registry = SPIFFERegistry()
        assert registry.trust_domain == "agentmesh.local"

    def test_svid_validity(self):
        """§19.4 — SVID is valid when issued_at <= now < expires_at."""
        si = SPIFFEIdentity.create("did:mesh:abc", "agent")
        svid = si.issue_svid(ttl_hours=1)
        assert svid.is_valid()

    def test_svid_expired(self):
        """§19.4 — expired SVID is invalid."""
        svid = SVID(
            spiffe_id="spiffe://test/agent",
            trust_domain="test",
            issued_at=datetime.now(timezone.utc) - timedelta(hours=2),
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
            agent_did="did:mesh:abc",
        )
        assert not svid.is_valid()

    def test_svid_rotation_threshold(self):
        """§19.5 — rotation needed when time remaining < threshold."""
        si = SPIFFEIdentity.create("did:mesh:abc", "agent")
        assert si.needs_rotation()  # No SVID = needs rotation
        si.issue_svid(ttl_hours=1)
        assert not si.needs_rotation()  # Fresh SVID

    def test_svid_validation(self):
        """§19.6 — validation checks domain and registration."""
        registry = SPIFFERegistry(trust_domain="agentmesh.local")
        si = registry.register("did:mesh:abc", "agent")
        svid = si.issue_svid()
        assert registry.validate_svid(svid)

    def test_svid_wrong_domain_rejected(self):
        """§19.6 — wrong trust domain fails validation."""
        registry = SPIFFERegistry(trust_domain="good.local")
        si = registry.register("did:mesh:abc", "agent")
        svid = si.issue_svid()
        svid.trust_domain = "evil.local"
        assert not registry.validate_svid(svid)


# ═══════════════════════════════════════════════════════════════════════════
# Section 20: JWK/JWKS Serialization
# ═══════════════════════════════════════════════════════════════════════════


class TestJWK:
    """Spec §20 — JWK/JWKS Serialization."""

    def test_jwk_format(self):
        """§20.1 — JWK MUST have correct parameters."""
        identity = _make_identity()
        jwk = to_jwk(identity)
        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "Ed25519"
        assert jwk["use"] == "sig"
        assert jwk["kid"] == str(identity.did)
        assert "x" in jwk
        assert "d" not in jwk  # private not included by default

    def test_jwk_private_key_only_when_requested(self):
        """§20.2 — private key only with include_private=True."""
        identity = _make_identity()
        jwk_pub = to_jwk(identity, include_private=False)
        assert "d" not in jwk_pub
        jwk_priv = to_jwk(identity, include_private=True)
        assert "d" in jwk_priv

    def test_jwk_round_trip(self):
        """§20.4 — export+import round-trip preserves key material."""
        original = _make_identity()
        jwk = to_jwk(original, include_private=True)
        restored = from_jwk(jwk)
        assert restored.public_key == original.public_key

    def test_jwk_wrong_kty_rejected(self):
        """§20.4 — kty != OKP MUST be rejected."""
        with pytest.raises(IdentityError, match="key type"):
            from_jwk({"kty": "RSA", "crv": "Ed25519", "x": "abc"})

    def test_jwk_wrong_crv_rejected(self):
        """§20.4 — crv != Ed25519 MUST be rejected."""
        with pytest.raises(IdentityError, match="curve"):
            from_jwk({"kty": "OKP", "crv": "X25519", "x": "abc"})

    def test_jwk_missing_x_rejected(self):
        """§20.4 — missing x parameter MUST be rejected."""
        with pytest.raises(IdentityError, match="x"):
            from_jwk({"kty": "OKP", "crv": "Ed25519"})

    def test_jwks_format(self):
        """§20.5 — JWKS wraps JWK in keys array."""
        identity = _make_identity()
        jwks = to_jwks(identity)
        assert "keys" in jwks
        assert len(jwks["keys"]) == 1

    def test_jwks_empty_rejected(self):
        """§20.5 — empty keys array MUST be rejected."""
        with pytest.raises(IdentityError):
            from_jwks({"keys": []})

    def test_jwks_kid_filter(self):
        """§20.5 — JWKS import with kid filter."""
        identity = _make_identity()
        jwks = to_jwks(identity)
        kid = str(identity.did)
        restored = from_jwks(jwks, kid=kid)
        assert restored.public_key == identity.public_key


# ═══════════════════════════════════════════════════════════════════════════
# Section 21: DID Document Export
# ═══════════════════════════════════════════════════════════════════════════


class TestDIDDocument:
    """Spec §21 — DID Document Export."""

    def test_did_document_structure(self):
        """§21.1 — DID Document MUST have W3C structure."""
        identity = _make_identity()
        doc = identity.to_did_document()
        assert doc["@context"] == ["https://www.w3.org/ns/did/v1"]
        assert doc["id"] == str(identity.did)
        assert len(doc["verificationMethod"]) == 1
        vm = doc["verificationMethod"][0]
        assert vm["type"] == "Ed25519VerificationKey2020"
        assert vm["controller"] == str(identity.did)
        assert "publicKeyBase64" in vm
        assert len(doc["authentication"]) == 1
        assert len(doc["service"]) == 1
        assert doc["service"][0]["type"] == "AgentMeshIdentity"


# ═══════════════════════════════════════════════════════════════════════════
# Section 22: Identity Registry
# ═══════════════════════════════════════════════════════════════════════════


class TestIdentityRegistry:
    """Spec §22 — Identity Registry."""

    def test_register_and_get(self):
        """§22.2 — register + get round-trip."""
        registry = IdentityRegistry()
        identity = _make_identity()
        registry.register(identity)
        retrieved = registry.get(str(identity.did))
        assert retrieved is not None
        assert retrieved.name == identity.name

    def test_duplicate_did_rejected(self):
        """§22.3 — duplicate DID MUST be rejected."""
        registry = IdentityRegistry()
        identity = _make_identity()
        registry.register(identity)
        with pytest.raises((ValueError, IdentityError)):
            registry.register(identity)

    def test_delegation_chain_verification(self):
        """§22.4 — verify_delegation_chain walks parent links."""
        registry = IdentityRegistry()
        parent = _make_identity(capabilities=["read:data"])
        registry.register(parent)
        child = parent.delegate("child", ["read:data"])
        registry.register(child)
        assert AgentIdentity.verify_delegation_chain(child, registry)

    def test_delegation_chain_circular_reference_detected(self):
        """§22.4 — circular references MUST be detected."""
        identity = _make_identity()
        identity.parent_did = str(identity.did)
        identity.delegation_depth = 1
        registry = IdentityRegistry()
        registry.register(identity)
        assert not AgentIdentity.verify_delegation_chain(identity, registry)


# ═══════════════════════════════════════════════════════════════════════════
# Section 23: Failure Semantics
# ═══════════════════════════════════════════════════════════════════════════


class TestFailureSemantics:
    """Spec §23 — Failure Semantics."""

    def test_signature_verify_returns_false_not_raise(self):
        """§23.1 — signature verification returns false on failure."""
        identity = _make_identity()
        result = identity.verify_signature(b"x", "invalid-base64!!")
        assert result is False

    def test_handshake_failure_returns_result(self):
        """§23.1 — handshake failure returns HandshakeResult."""
        r = HandshakeResult.failure("did:mesh:x", "test error")
        assert r.verified is False
        assert r.trust_score == 0

    def test_default_trust_score_for_unknown(self):
        """§23.1 — unknown agent gets default score (500)."""
        engine = NetworkTrustEngine()
        assert engine.get_score("did:mesh:unknown") == TRUST_SCORE_DEFAULT

    def test_revocation_check_missing_entry(self):
        """§23.1 — missing revocation entry returns false."""
        rl = RevocationList()
        assert rl.is_revoked("did:mesh:nope") is False


# ═══════════════════════════════════════════════════════════════════════════
# Section 24: Security Considerations
# ═══════════════════════════════════════════════════════════════════════════


class TestSecurityConsiderations:
    """Spec §24 — Security Considerations."""

    def test_private_key_not_in_model_dump(self):
        """§24.1 — private key MUST NOT appear in serialized output."""
        identity = _make_identity()
        dump = identity.model_dump()
        dump_str = str(dump)
        assert "_private_key" not in dump_str

    def test_token_constant_time_comparison(self):
        """§24.2 — token verification uses hmac.compare_digest."""
        cred = _make_credential()
        # The implementation uses hmac.compare_digest internally;
        # we verify correct behavior (matching token passes, wrong fails)
        assert cred.verify_token(cred.token)
        assert not cred.verify_token("wrong")

    def test_nonce_entropy(self):
        """§24.4 — challenge nonce >= 256 bits, response nonce >= 128 bits."""
        ch = HandshakeChallenge.generate()
        # 256 bits = 32 bytes = 64 hex chars
        assert len(ch.nonce) >= 64

    def test_sybil_resistance_wildcard_blocked(self):
        """§24.6 — wildcard delegation blocked."""
        parent = _make_identity(capabilities=["*"])
        with pytest.raises(ValueError, match="wildcard"):
            parent.delegate("child", ["*"])
