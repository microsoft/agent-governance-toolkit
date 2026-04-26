# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Hypervisor Scenario Integration Tests

Multi-module end-to-end scenarios that exercise the Hypervisor
integration adapters (Nexus, Verification, IATP) together.

Scenarios:
1. Rogue agent detected by Verification → penalized by Hypervisor → reputation loss via Nexus
2. New agent joins → IATP manifest parsed → ring assigned by Nexus score
3. Behavioral drift triggers demotion cascade
4. Trust decay over repeated low-drift violations
5. Full cross-module governance: join → verify → drift → penalize → terminate
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from hypervisor import (
    ConsistencyMode,
    ExecutionRing,
    Hypervisor,
    SessionConfig,
)
from hypervisor.integrations.iatp_adapter import (
    IATPAdapter,
    IATPTrustLevel,
)
from hypervisor.integrations.nexus_adapter import NexusAdapter
from hypervisor.integrations.verification_adapter import (
    DriftCheckResult,
    DriftSeverity,
    DriftThresholds,
    VerificationAdapter,
)

# ---------------------------------------------------------------------------
# Mock Nexus ReputationEngine
# ---------------------------------------------------------------------------


@dataclass
class MockTrustScore:
    """Mimics nexus.reputation.TrustScore."""

    total_score: int
    successful_tasks: int = 0
    failed_tasks: int = 0


class MockReputationEngine:
    """Fake Nexus ReputationEngine for testing."""

    def __init__(self, scores: dict[str, int] | None = None) -> None:
        self._scores: dict[str, int] = scores or {}
        self._outcomes: list[tuple[str, str]] = []
        self._slashes: list[dict[str, Any]] = []

    def set_score(self, agent_did: str, score: int) -> None:
        self._scores[agent_did] = score

    def calculate_trust_score(
        self,
        verification_level: str = "standard",
        history: Any = None,
        capabilities: dict | None = None,
        privacy: dict | None = None,
    ) -> MockTrustScore:
        # Return score based on history which carries agent_did
        agent_did = getattr(history, "agent_did", None) or "unknown"
        raw = self._scores.get(agent_did, 500)
        return MockTrustScore(total_score=raw)

    def record_task_outcome(self, agent_did: str, outcome: str) -> None:
        self._outcomes.append((agent_did, outcome))

    def slash_reputation(
        self,
        agent_did: str,
        reason: str,
        severity: str = "medium",
        evidence_hash: str | None = None,
        trace_id: str | None = None,
        broadcast: bool = True,
    ) -> None:
        self._slashes.append({
            "agent_did": agent_did,
            "reason": reason,
            "severity": severity,
            "evidence_hash": evidence_hash,
        })
        # Reduce score
        current = self._scores.get(agent_did, 500)
        penalty = {"low": 50, "medium": 200, "high": 500, "critical": 900}.get(severity, 200)
        self._scores[agent_did] = max(0, current - penalty)


# ---------------------------------------------------------------------------
# Mock Verification Backend
# ---------------------------------------------------------------------------


@dataclass
class MockVerificationScore:
    """Mimics behavioral verification score."""

    drift_score: float
    explanation: str | None = None


class MockVerificationBackend:
    """Fake Verification verifier for testing."""

    def __init__(self, drift_scores: dict[str, float] | None = None) -> None:
        self._drift_scores: dict[str, float] = drift_scores or {}
        self._default_drift: float = 0.05

    def set_drift(self, key: str, drift: float) -> None:
        self._drift_scores[key] = drift

    def verify_embeddings(
        self,
        embedding_a: Any,
        embedding_b: Any,
        metric: str = "cosine",
        weights: Any = None,
        threshold_profile: str | None = None,
        explain: bool = False,
    ) -> MockVerificationScore:
        # Use embedding_a as agent key for lookup
        key = str(embedding_a)
        drift = self._drift_scores.get(key, self._default_drift)
        return MockVerificationScore(
            drift_score=drift,
            explanation=f"Drift {drift:.2f} for {key}" if explain else None,
        )


# ---------------------------------------------------------------------------
# Helper: history carrier for Nexus
# ---------------------------------------------------------------------------


@dataclass
class AgentHistory:
    agent_did: str


# ---------------------------------------------------------------------------
# Scenario 1: Rogue Agent Detection → Penalty → Nexus Reputation Loss
# ---------------------------------------------------------------------------


class TestRogueAgentScenario:
    """
    Flow: Agent joins → Verification detects drift → Hypervisor slashes → Nexus notified
    """

    @pytest.fixture(autouse=True)
    def setup(self):
        self.hv = Hypervisor()
        self.nexus_engine = MockReputationEngine({
            "did:mesh:good-agent": 850,
            "did:mesh:rogue-agent": 750,
        })
        self.nexus = NexusAdapter(scorer=self.nexus_engine)

        self.verification_backend = MockVerificationBackend()
        self.policy_check = VerificationAdapter(verifier=self.verification_backend)

    @pytest.mark.skip("Feature not available in Public Preview")
    async def test_rogue_detected_slashed_reputation_reduced(self):
        """Full rogue agent lifecycle: join → drift → penalize → nexus penalty."""
        # 1) Resolve sigma from Nexus
        sigma_rogue = self.nexus.resolve_sigma(
            "did:mesh:rogue-agent",
            history=AgentHistory("did:mesh:rogue-agent"),
        )
        assert sigma_rogue == 0.75  # 750 / 1000

        # 2) Create session, join agent
        session = await self.hv.create_session(
            config=SessionConfig(max_participants=5),
            creator_did="did:mesh:admin",
        )
        sid = session.sso.session_id
        ring = await self.hv.join_session(sid, "did:mesh:rogue-agent", sigma_raw=sigma_rogue)
        assert ring == ExecutionRing.RING_2_STANDARD

        await self.hv.activate_session(sid)

        # 3) Verification detects HIGH drift
        self.verification_backend.set_drift("did:mesh:rogue-agent", 0.65)
        drift_result = self.policy_check.check_behavioral_drift(
            agent_did="did:mesh:rogue-agent",
            session_id=sid,
            claimed_embedding="did:mesh:rogue-agent",
            observed_embedding="rogue-output",
        )
        assert drift_result.severity == DriftSeverity.HIGH
        assert drift_result.should_slash is True

        # 4) Penalize via hypervisor
        agent_scores = {"did:mesh:rogue-agent": sigma_rogue}
        slash_result = self.hv.slashing.slash(
            vouchee_did="did:mesh:rogue-agent",
            session_id=sid,
            vouchee_sigma=sigma_rogue,
            risk_weight=0.95,
            reason=f"Verification drift: {drift_result.drift_score:.2f}",
            agent_scores=agent_scores,
        )
        assert slash_result.vouchee_sigma_after == 0.0
        assert agent_scores["did:mesh:rogue-agent"] == 0.0

        # 5) Report to Nexus
        self.nexus.report_slash(
            agent_did="did:mesh:rogue-agent",
            reason="Behavioral drift detected by Verification",
            severity="high",
        )
        # Nexus score should drop 500 (high penalty): 750 → 250
        assert self.nexus_engine._scores["did:mesh:rogue-agent"] == 250

        # 6) Future resolution gives untrusted tier
        new_sigma = self.nexus.resolve_sigma(
            "did:mesh:rogue-agent",
            history=AgentHistory("did:mesh:rogue-agent"),
        )
        assert new_sigma == 0.25  # 250/1000
        cached = self.nexus.get_cached_result("did:mesh:rogue-agent")
        assert cached is not None
        assert cached.tier == "untrusted"  # 250 < 300 threshold

    async def test_clean_agent_passes_verification_check(self):
        """An honest agent produces no drift — no penalty needed."""
        sigma_good = self.nexus.resolve_sigma(
            "did:mesh:good-agent",
            history=AgentHistory("did:mesh:good-agent"),
        )
        assert sigma_good == 0.85

        self.verification_backend.set_drift("did:mesh:good-agent", 0.02)
        result = self.policy_check.check_behavioral_drift(
            agent_did="did:mesh:good-agent",
            session_id="session-1",
            claimed_embedding="did:mesh:good-agent",
            observed_embedding="good-output",
        )
        assert result.passed is True
        assert result.severity == DriftSeverity.NONE
        assert result.should_slash is False


# ---------------------------------------------------------------------------
# Scenario 2: New Agent Joins with IATP Manifest → Nexus Score → Ring
# ---------------------------------------------------------------------------


class TestIATPManifestOnboarding:
    """
    Flow: IATP manifest → IATPAdapter parses → Nexus enriches → ring assigned
    """

    @pytest.fixture(autouse=True)
    def setup(self):
        self.hv = Hypervisor()
        self.iatp = IATPAdapter()
        self.nexus_engine = MockReputationEngine({
            "did:mesh:partner-agent": 950,
            "did:mesh:new-agent": 400,
        })
        self.nexus = NexusAdapter(scorer=self.nexus_engine)

    async def test_verified_partner_gets_ring_1(self):
        """Agent with IATP verified_partner trust → Ring 1 (with consensus)."""
        manifest = {
            "agent_id": "did:mesh:partner-agent",
            "trust_level": "verified_partner",
            "trust_score": 9,
            "actions": [
                {
                    "action_id": "deploy",
                    "name": "Deploy Service",
                    "execute_api": "/deploy",
                    "undo_api": "/rollback",
                    "reversibility": "full",
                },
            ],
            "scopes": ["production", "staging"],
        }

        # Parse manifest
        analysis = self.iatp.analyze_manifest_dict(manifest)
        assert analysis.trust_level == IATPTrustLevel.VERIFIED_PARTNER
        assert analysis.ring_hint == ExecutionRing.RING_1_PRIVILEGED
        assert analysis.sigma_hint == 0.9
        assert analysis.has_reversible_actions is True

        # Enrich with Nexus
        sigma = self.nexus.resolve_sigma(
            "did:mesh:partner-agent",
            history=AgentHistory("did:mesh:partner-agent"),
        )
        assert sigma == 0.95  # 950 / 1000

        # Join session with Nexus-enriched sigma
        session = await self.hv.create_session(
            config=SessionConfig(max_participants=5),
            creator_did="did:mesh:admin",
        )
        ring = await self.hv.join_session(
            session.sso.session_id,
            "did:mesh:partner-agent",
            actions=analysis.actions,
            sigma_raw=sigma,
        )
        # Ring 2 without consensus, but with enriched sigma
        assert ring == ExecutionRing.RING_2_STANDARD  # consensus needed for Ring 1

    async def test_unknown_agent_gets_sandbox(self):
        """Agent with low Nexus score → Ring 3 sandbox."""
        manifest = {
            "agent_id": "did:mesh:new-agent",
            "trust_level": "unknown",
            "trust_score": 3,
            "actions": [
                {
                    "action_id": "read-data",
                    "name": "Read Data",
                    "execute_api": "/read",
                    "reversibility": "full",
                    "is_read_only": True,
                },
            ],
            "scopes": ["readonly"],
        }

        analysis = self.iatp.analyze_manifest_dict(manifest)
        assert analysis.trust_level == IATPTrustLevel.UNKNOWN
        assert analysis.ring_hint == ExecutionRing.RING_3_SANDBOX

        sigma = self.nexus.resolve_sigma(
            "did:mesh:new-agent",
            history=AgentHistory("did:mesh:new-agent"),
        )
        assert sigma == 0.40

        session = await self.hv.create_session(
            config=SessionConfig(),
            creator_did="did:mesh:admin",
        )
        ring = await self.hv.join_session(
            session.sso.session_id,
            "did:mesh:new-agent",
            actions=analysis.actions,
            sigma_raw=sigma,
        )
        assert ring == ExecutionRing.RING_3_SANDBOX

    async def test_non_reversible_actions_force_strong_mode(self):
        """Manifest with non-reversible actions forces Strong consistency."""
        manifest = {
            "agent_id": "did:mesh:admin-agent",
            "trust_level": "trusted",
            "trust_score": 8,
            "actions": [
                {
                    "action_id": "delete-account",
                    "name": "Delete Account",
                    "execute_api": "/delete",
                    "reversibility": "none",
                    "is_read_only": False,
                },
            ],
            "scopes": ["admin"],
        }

        analysis = self.iatp.analyze_manifest_dict(manifest)
        assert analysis.has_non_reversible_actions is True

        session = await self.hv.create_session(
            config=SessionConfig(consistency_mode=ConsistencyMode.EVENTUAL),
            creator_did="did:mesh:admin",
        )
        await self.hv.join_session(
            session.sso.session_id,
            "did:mesh:admin-agent",
            actions=analysis.actions,
            sigma_raw=0.85,
        )
        # Should be forced to Strong mode (SSO tracks mode separately from config)
        assert session.sso.consistency_mode == ConsistencyMode.STRONG


# ---------------------------------------------------------------------------
# Scenario 3: Drift-Triggered Demotion Cascade
# ---------------------------------------------------------------------------


class TestDriftDemotionCascade:
    """
    Flow: Repeated MEDIUM drift → accumulate history → escalate → penalize
    """

    @pytest.fixture(autouse=True)
    def setup(self):
        self.verification_backend = MockVerificationBackend()
        self.drift_events: list[DriftCheckResult] = []
        self.policy_check = VerificationAdapter(
            verifier=self.verification_backend,
            on_drift_detected=lambda r: self.drift_events.append(r),
        )

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_repeated_medium_drift_escalates(self):
        """Multiple MEDIUM drifts accumulate; drift rate tracks correctly."""
        agent = "did:mesh:drifty-agent"
        session = "session-drift"

        # 5 checks: 3 medium drifts, 2 clean
        drifts = [0.35, 0.05, 0.40, 0.10, 0.32]
        for i, d in enumerate(drifts):
            self.verification_backend.set_drift(agent, d)
            self.policy_check.check_behavioral_drift(
                agent_did=agent,
                session_id=session,
                claimed_embedding=agent,
                observed_embedding=f"output-{i}",
                action_id=f"action-{i}",
            )

        # 3 out of 5 should have failed (>= 0.30 medium threshold)
        rate = self.policy_check.get_drift_rate(agent, session)
        assert rate == 0.6  # 3 / 5

        mean_drift = self.policy_check.get_mean_drift_score(agent, session)
        assert 0.20 < mean_drift < 0.30  # average of all 5

        # 3 events triggered the callback
        assert len(self.drift_events) == 3
        assert self.policy_check.total_checks == 5
        assert self.policy_check.total_violations == 3

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_critical_drift_immediate_slash(self):
        """CRITICAL drift immediately signals for penalty."""
        self.verification_backend.set_drift("did:mesh:bad", 0.80)
        result = self.policy_check.check_behavioral_drift(
            agent_did="did:mesh:bad",
            session_id="session-1",
            claimed_embedding="did:mesh:bad",
            observed_embedding="malicious",
        )
        assert result.severity == DriftSeverity.CRITICAL
        assert result.should_slash is True
        assert result.should_demote is False  # penalize > demote


# ---------------------------------------------------------------------------
# Scenario 4: Sponsor Cascade with Nexus Reporting
# ---------------------------------------------------------------------------


class TestVoucherCascadeWithNexus:
    """
    Flow: Agent A sponsors for B → B drifts → both penalized → both reported to Nexus
    """

    @pytest.fixture(autouse=True)
    def setup(self):
        self.hv = Hypervisor()
        self.nexus_engine = MockReputationEngine({
            "did:mesh:sponsor-A": 800,
            "did:mesh:rogue-B": 700,
        })
        self.nexus = NexusAdapter(scorer=self.nexus_engine)

    @pytest.mark.skip("Feature not available in Public Preview")
    async def test_voucher_cascade_with_nexus_penalty(self):
        """Sponsor → penalize → sponsor clipped → both reported to Nexus."""
        # Create session
        session = await self.hv.create_session(
            config=SessionConfig(max_participants=5),
            creator_did="did:mesh:admin",
        )
        sid = session.sso.session_id

        # Join agents
        await self.hv.join_session(sid, "did:mesh:sponsor-A", sigma_raw=0.80)
        await self.hv.join_session(sid, "did:mesh:rogue-B", sigma_raw=0.70)
        await self.hv.activate_session(sid)

        # A sponsors for B
        self.hv.vouching.vouch(
            voucher_did="did:mesh:sponsor-A",
            vouchee_did="did:mesh:rogue-B",
            voucher_sigma=0.80,
            bond_pct=0.50,
            session_id=sid,
        )

        # Penalize B
        agent_scores = {
            "did:mesh:sponsor-A": 0.80,
            "did:mesh:rogue-B": 0.70,
        }
        self.hv.slashing.slash(
            vouchee_did="did:mesh:rogue-B",
            session_id=sid,
            vouchee_sigma=0.70,
            risk_weight=0.80,
            reason="Behavioral drift detected",
            agent_scores=agent_scores,
        )

        # B is blacklisted
        assert agent_scores["did:mesh:rogue-B"] == 0.0
        # A is clipped: 0.80 × (1 - 0.80) = 0.16
        assert agent_scores["did:mesh:sponsor-A"] == pytest.approx(0.16, abs=0.01)

        # Report both to Nexus
        self.nexus.report_slash(
            "did:mesh:rogue-B",
            reason="Primary violation",
            severity="high",
        )
        self.nexus.report_slash(
            "did:mesh:sponsor-A",
            reason="Collateral: vouched for rogue agent",
            severity="low",
        )

        assert self.nexus_engine._scores["did:mesh:rogue-B"] == 200  # 700 - 500
        assert self.nexus_engine._scores["did:mesh:sponsor-A"] == 750  # 800 - 50

        # Verify penalty count in Nexus
        assert len(self.nexus_engine._slashes) == 2


# ---------------------------------------------------------------------------
# Scenario 5: Full Cross-Module Governance Pipeline
# ---------------------------------------------------------------------------


class TestFullGovernancePipeline:
    """
    The complete governance flow across all modules:
    IATP manifest → Nexus trust → Ring assignment → Verification monitoring →
    Drift detected → Penalty → Nexus reputation loss → Session cleanup
    """

    @pytest.fixture(autouse=True)
    def setup(self):
        self.hv = Hypervisor()
        self.nexus_engine = MockReputationEngine({
            "did:mesh:agent-alpha": 820,
        })
        self.nexus = NexusAdapter(scorer=self.nexus_engine)
        self.iatp = IATPAdapter()
        self.verification_backend = MockVerificationBackend()
        self.policy_check = VerificationAdapter(verifier=self.verification_backend)

    @pytest.mark.skip("Feature not available in Public Preview")
    async def test_full_pipeline_join_to_slash_to_terminate(self):
        """Complete cross-module pipeline: manifest → join → drift → penalize → terminate."""
        agent_did = "did:mesh:agent-alpha"

        # === Phase 1: IATP Manifest Parsing ===
        manifest = {
            "agent_id": agent_did,
            "trust_level": "trusted",
            "trust_score": 8,
            "actions": [
                {
                    "action_id": "write-data",
                    "name": "Write Data",
                    "execute_api": "/write",
                    "undo_api": "/undo-write",
                    "reversibility": "full",
                },
                {
                    "action_id": "send-email",
                    "name": "Send Email",
                    "execute_api": "/send",
                    "reversibility": "none",
                },
            ],
            "scopes": ["data", "email"],
        }
        analysis = self.iatp.analyze_manifest_dict(manifest)
        assert analysis.trust_level == IATPTrustLevel.TRUSTED
        assert analysis.has_non_reversible_actions is True

        # === Phase 2: Nexus Trust Enrichment ===
        sigma = self.nexus.resolve_sigma(
            agent_did,
            history=AgentHistory(agent_did),
        )
        assert sigma == 0.82

        # === Phase 3: Session Join with Enriched Data ===
        session = await self.hv.create_session(
            config=SessionConfig(
                consistency_mode=ConsistencyMode.EVENTUAL,
                max_participants=5,
                enable_audit=True,
            ),
            creator_did="did:mesh:admin",
        )
        sid = session.sso.session_id

        ring = await self.hv.join_session(
            sid,
            agent_did,
            actions=analysis.actions,
            sigma_raw=sigma,
        )
        assert ring == ExecutionRing.RING_2_STANDARD
        # Non-reversible action should force Strong mode (SSO, not config)
        assert session.sso.consistency_mode == ConsistencyMode.STRONG

        await self.hv.activate_session(sid)

        # === Phase 4: Verification Behavioral Monitoring ===
        # First check — clean
        self.verification_backend.set_drift(agent_did, 0.05)
        check1 = self.policy_check.check_behavioral_drift(
            agent_did=agent_did,
            session_id=sid,
            claimed_embedding=agent_did,
            observed_embedding="output-1",
            action_id="write-data",
        )
        assert check1.passed is True

        # Second check — HIGH drift (agent compromised?)
        self.verification_backend.set_drift(agent_did, 0.55)
        check2 = self.policy_check.check_behavioral_drift(
            agent_did=agent_did,
            session_id=sid,
            claimed_embedding=agent_did,
            observed_embedding="suspicious-output",
            action_id="send-email",
        )
        assert check2.severity == DriftSeverity.HIGH
        assert check2.should_slash is True

        # === Phase 5: Penalty ===
        agent_scores = {agent_did: sigma}
        slash_result = self.hv.slashing.slash(
            vouchee_did=agent_did,
            session_id=sid,
            vouchee_sigma=sigma,
            risk_weight=0.95,  # non-reversible action
            reason=f"Verification HIGH drift on send-email: {check2.drift_score}",
            agent_scores=agent_scores,
        )
        assert slash_result.vouchee_sigma_after == 0.0
        assert agent_scores[agent_did] == 0.0

        # === Phase 6: Report to Nexus ===
        self.nexus.report_slash(
            agent_did=agent_did,
            reason="Verification behavioral drift on send-email action",
            severity="high",
            evidence_hash="sha256:abc123",
        )
        # 820 - 500 = 320 (probationary)
        assert self.nexus_engine._scores[agent_did] == 320

        # === Phase 7: Terminate Session ===
        # Capture audit delta so audit log root is produced
        from hypervisor.audit.delta import VFSChange
        session.delta_engine.capture(agent_did, [VFSChange(
            path="/sessions/test/penalize-event",
            operation="add",
            content_hash="sha256:penalize-evidence",
            agent_did=agent_did,
        )])
        hash_chain_root = await self.hv.terminate_session(sid)
        assert hash_chain_root is not None  # audit was enabled

        # Verify complete governance trail
        assert len(self.hv.slashing.history) == 1
        assert self.policy_check.total_checks == 2
        assert self.policy_check.total_violations == 1
        assert len(self.nexus_engine._slashes) == 1

    async def test_clean_agent_full_pipeline(self):
        """Pipeline for a well-behaved agent: no penalty, clean termination."""
        agent_did = "did:mesh:agent-alpha"

        sigma = self.nexus.resolve_sigma(
            agent_did,
            history=AgentHistory(agent_did),
        )

        session = await self.hv.create_session(
            config=SessionConfig(enable_audit=True),
            creator_did="did:mesh:admin",
        )
        sid = session.sso.session_id

        await self.hv.join_session(sid, agent_did, sigma_raw=sigma)
        await self.hv.activate_session(sid)

        # All verification checks pass
        for i in range(5):
            self.verification_backend.set_drift(agent_did, 0.02)
            check = self.policy_check.check_behavioral_drift(
                agent_did=agent_did,
                session_id=sid,
                claimed_embedding=agent_did,
                observed_embedding=f"clean-output-{i}",
            )
            assert check.passed is True

        # Report success to Nexus
        self.nexus.report_task_outcome(agent_did, "success")
        assert len(self.nexus_engine._outcomes) == 1

        # Capture at least one delta so audit produces a audit log root
        from hypervisor.audit.delta import VFSChange
        session.delta_engine.capture(agent_did, [VFSChange(
            path="/sessions/test/status",
            operation="add",
            content_hash="sha256:abc",
            agent_did=agent_did,
        )])

        hash_chain_root = await self.hv.terminate_session(sid)
        assert hash_chain_root is not None


# ---------------------------------------------------------------------------
# Scenario 6: Adapter Isolation and Fallback
# ---------------------------------------------------------------------------


class TestAdapterFallbacks:
    """Verify adapters work gracefully when underlying services are unavailable."""

    def test_nexus_adapter_without_scorer(self):
        """NexusAdapter returns default sigma when no scorer is configured."""
        nexus = NexusAdapter()  # no scorer
        sigma = nexus.resolve_sigma("did:mesh:any-agent")
        assert sigma == 0.50  # safe default

    def test_verification_adapter_without_verifier(self):
        """VerificationAdapter returns no-drift when no verifier is configured."""
        policy_check = VerificationAdapter()  # no verifier
        result = policy_check.check_behavioral_drift(
            agent_did="did:mesh:any",
            session_id="session-1",
            claimed_embedding="a",
            observed_embedding="b",
        )
        assert result.passed is True
        assert result.drift_score == 0.0
        assert result.severity == DriftSeverity.NONE

    @pytest.mark.skip("Feature not available in Public Preview")
    async def test_nexus_verify_agent_without_verifier(self):
        """verify_agent is permissive when no verifier configured."""
        nexus = NexusAdapter()
        result = await nexus.verify_agent("did:mesh:any-agent")
        assert result is True

    def test_iatp_adapter_dict_manifest(self):
        """IATPAdapter handles dict manifests for testing."""
        iatp = IATPAdapter()
        analysis = iatp.analyze_manifest_dict({
            "agent_id": "did:mesh:test",
            "trust_level": "standard",
            "trust_score": 5,
            "actions": [],
            "scopes": [],
        })
        assert analysis.sigma_hint == 0.5
        assert analysis.trust_level == IATPTrustLevel.STANDARD
        assert analysis.ring_hint == ExecutionRing.RING_2_STANDARD

    def test_iatp_adapter_unknown_trust_level(self):
        """IATPAdapter handles unknown trust levels gracefully."""
        iatp = IATPAdapter()
        analysis = iatp.analyze_manifest_dict({
            "agent_id": "did:mesh:test",
            "trust_level": "some_new_level",
            "trust_score": 5,
            "actions": [],
            "scopes": [],
        })
        assert analysis.trust_level == IATPTrustLevel.UNKNOWN
        assert analysis.ring_hint == ExecutionRing.RING_3_SANDBOX

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_nexus_cache_invalidation(self):
        """NexusAdapter cache can be invalidated."""
        engine = MockReputationEngine({"did:mesh:a": 800})
        nexus = NexusAdapter(scorer=engine, cache_ttl_seconds=9999)

        # First resolve populates cache
        nexus.resolve_sigma("did:mesh:a", history=AgentHistory("did:mesh:a"))
        assert nexus.get_cached_result("did:mesh:a") is not None

        # Invalidate
        nexus.invalidate_cache("did:mesh:a")
        assert nexus.get_cached_result("did:mesh:a") is None

        # Invalidate all
        nexus.resolve_sigma("did:mesh:a", history=AgentHistory("did:mesh:a"))
        nexus.invalidate_cache()
        assert nexus.get_cached_result("did:mesh:a") is None


# ---------------------------------------------------------------------------
# Scenario 7: Verification Threshold Configuration
# ---------------------------------------------------------------------------


class TestVerificationThresholdConfiguration:
    """Verify custom thresholds change drift severity classification."""

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_custom_strict_thresholds(self):
        """Strict thresholds: lower bars for flagging drift."""
        verifier = MockVerificationBackend()
        verifier.set_drift("agent", 0.12)

        # Default thresholds: 0.12 < 0.15 → NONE
        checker_default = VerificationAdapter(verifier=verifier)
        result = checker_default.check_behavioral_drift(
            "agent", "s1", "agent", "out",
        )
        assert result.severity == DriftSeverity.NONE

        # Strict thresholds: LOW at 0.10
        checker_strict = VerificationAdapter(
            verifier=verifier,
            thresholds=DriftThresholds(low=0.10, medium=0.20, high=0.35, critical=0.50),
        )
        result = checker_strict.check_behavioral_drift(
            "agent", "s1", "agent", "out",
        )
        assert result.severity == DriftSeverity.LOW

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_custom_relaxed_thresholds(self):
        """Relaxed thresholds: higher tolerance for drift."""
        verifier = MockVerificationBackend()
        verifier.set_drift("agent", 0.45)

        # Default: 0.45 < 0.50 → MEDIUM
        checker_default = VerificationAdapter(verifier=verifier)
        result = checker_default.check_behavioral_drift(
            "agent", "s1", "agent", "out",
        )
        assert result.severity == DriftSeverity.MEDIUM

        # Relaxed: MEDIUM at 0.50, so 0.45 is still LOW
        checker_relaxed = VerificationAdapter(
            verifier=verifier,
            thresholds=DriftThresholds(low=0.20, medium=0.50, high=0.70, critical=0.90),
        )
        result = checker_relaxed.check_behavioral_drift(
            "agent", "s1", "agent", "out",
        )
        assert result.severity == DriftSeverity.LOW


# ---------------------------------------------------------------------------
# Scenario 8: Wired Adapters — Hypervisor core with injected adapters
# ---------------------------------------------------------------------------


class TestWiredHypervisor:
    """
    Tests for Hypervisor with adapters wired directly into __init__,
    exercising auto-resolution of sigma, IATP manifest parsing, and
    automatic Verification penalty via verify_behavior().
    """

    @pytest.fixture(autouse=True)
    def setup(self):
        self.nexus_engine = MockReputationEngine({
            "did:mesh:alice": 850,
            "did:mesh:bob": 400,
            "did:mesh:rogue": 750,
        })
        self.verification_backend = MockVerificationBackend()

        from hypervisor.integrations.iatp_adapter import IATPAdapter
        from hypervisor.integrations.nexus_adapter import NexusAdapter
        from hypervisor.integrations.verification_adapter import VerificationAdapter

        self.hv = Hypervisor(
            nexus=NexusAdapter(scorer=self.nexus_engine),
            policy_check=VerificationAdapter(verifier=self.verification_backend),
            iatp=IATPAdapter(),
        )

    async def test_join_with_manifest_auto_parses(self):
        """Providing a manifest dict auto-parses actions and sigma."""
        session = await self.hv.create_session(
            config=SessionConfig(max_participants=5),
            creator_did="did:mesh:admin",
        )
        sid = session.sso.session_id

        manifest = {
            "agent_id": "did:mesh:alice",
            "trust_level": "trusted",
            "trust_score": 8,
            "actions": [
                {
                    "action_id": "read-data",
                    "name": "Read Data",
                    "execute_api": "/read",
                    "reversibility": "full",
                    "is_read_only": True,
                },
            ],
            "scopes": ["data"],
        }

        ring = await self.hv.join_session(
            sid,
            "did:mesh:alice",
            manifest=manifest,
        )
        # sigma_raw=0 → IATP sigma_hint=0.8, but Nexus also resolves
        # Nexus gives 850/1000=0.85, IATP gives 0.8, min(0.8, 0.85)=0.8
        assert ring == ExecutionRing.RING_2_STANDARD
        # Action should be registered
        assert len(session.reversibility.entries) == 1

    async def test_nexus_auto_resolves_sigma_when_zero(self):
        """When sigma_raw=0 and no manifest, Nexus resolves sigma."""
        session = await self.hv.create_session(
            config=SessionConfig(max_participants=5),
            creator_did="did:mesh:admin",
        )
        sid = session.sso.session_id

        ring = await self.hv.join_session(
            sid,
            "did:mesh:alice",
            agent_history=AgentHistory("did:mesh:alice"),
        )
        # Nexus: 850/1000 = 0.85 → Ring 2
        assert ring == ExecutionRing.RING_2_STANDARD

    async def test_nexus_conservative_merge(self):
        """When both sigma_raw and Nexus are available, uses lower (conservative)."""
        session = await self.hv.create_session(
            config=SessionConfig(max_participants=5),
            creator_did="did:mesh:admin",
        )
        sid = session.sso.session_id

        # sigma_raw=0.95, Nexus=0.85 → min=0.85
        ring = await self.hv.join_session(
            sid,
            "did:mesh:alice",
            sigma_raw=0.95,
            agent_history=AgentHistory("did:mesh:alice"),
        )
        assert ring == ExecutionRing.RING_2_STANDARD  # 0.85, not 0.95

    @pytest.mark.skip("Feature not available in Public Preview")
    async def test_verify_behavior_auto_slashes(self):
        """verify_behavior() auto-slashes on HIGH drift."""
        session = await self.hv.create_session(
            config=SessionConfig(max_participants=5),
            creator_did="did:mesh:admin",
        )
        sid = session.sso.session_id

        await self.hv.join_session(sid, "did:mesh:rogue", sigma_raw=0.75)
        await self.hv.activate_session(sid)

        # HIGH drift
        self.verification_backend.set_drift("did:mesh:rogue", 0.60)
        result = await self.hv.verify_behavior(
            session_id=sid,
            agent_did="did:mesh:rogue",
            claimed_embedding="did:mesh:rogue",
            observed_embedding="bad-output",
        )

        assert result is not None
        assert result.should_slash is True
        # Auto-penalty should have fired
        assert len(self.hv.slashing.history) == 1
        # Nexus should have been notified
        assert len(self.nexus_engine._slashes) == 1

    async def test_verify_behavior_no_slash_on_clean(self):
        """verify_behavior() does NOT penalize on clean output."""
        session = await self.hv.create_session(
            config=SessionConfig(max_participants=5),
            creator_did="did:mesh:admin",
        )
        sid = session.sso.session_id

        await self.hv.join_session(sid, "did:mesh:alice", sigma_raw=0.85)
        await self.hv.activate_session(sid)

        self.verification_backend.set_drift("did:mesh:alice", 0.02)
        result = await self.hv.verify_behavior(
            session_id=sid,
            agent_did="did:mesh:alice",
            claimed_embedding="did:mesh:alice",
            observed_embedding="good-output",
        )

        assert result is not None
        assert result.passed is True
        assert len(self.hv.slashing.history) == 0

    async def test_verify_behavior_returns_none_without_verifier(self):
        """Without Verification adapter, verify_behavior returns None."""
        hv_no_verifier = Hypervisor()
        session = await hv_no_verifier.create_session(
            config=SessionConfig(max_participants=5),
            creator_did="did:mesh:admin",
        )
        sid = session.sso.session_id
        await hv_no_verifier.join_session(sid, "did:mesh:alice", sigma_raw=0.85)
        await hv_no_verifier.activate_session(sid)

        result = await hv_no_verifier.verify_behavior(
            session_id=sid,
            agent_did="did:mesh:alice",
            claimed_embedding="a",
            observed_embedding="b",
        )
        assert result is None

    async def test_backward_compat_no_adapters(self):
        """Hypervisor without adapters works exactly as before."""
        hv = Hypervisor()
        session = await hv.create_session(
            config=SessionConfig(max_participants=5),
            creator_did="did:mesh:admin",
        )
        sid = session.sso.session_id

        ring = await hv.join_session(sid, "did:mesh:alice", sigma_raw=0.85)
        assert ring == ExecutionRing.RING_2_STANDARD
        assert hv.nexus is None
        assert hv.policy_check is None
        assert hv.iatp is None
