# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Hypervisor — Top-level orchestrator for multi-agent Shared Sessions.

Composes all submodules (Session, Liability, Rings, Reversibility,
Saga, Audit, Verification) into a unified governance runtime.

Optionally integrates with external trust scoring and behavioral
verification backends when adapters are provided.
"""

from __future__ import annotations

import logging
from typing import Any

from hypervisor.audit.commitment import CommitmentEngine
from hypervisor.audit.delta import DeltaEngine
from hypervisor.audit.gc import EphemeralGC, RetentionPolicy
from hypervisor.liability.slashing import SlashingEngine
from hypervisor.liability.vouching import VouchingEngine
from hypervisor.models import (
    ActionDescriptor,
    ConsistencyMode,
    ExecutionRing,
    SessionConfig,
    SessionState,
)
from hypervisor.reversibility.registry import ReversibilityRegistry
from hypervisor.rings.classifier import ActionClassifier
from hypervisor.rings.enforcer import RingEnforcer
from hypervisor.saga.orchestrator import SagaOrchestrator
from hypervisor.session import SharedSessionObject
from hypervisor.verification.history import TransactionHistoryVerifier

logger = logging.getLogger(__name__)

# States considered inactive (no longer need monitoring)
_INACTIVE_STATES = frozenset({SessionState.ARCHIVED, SessionState.TERMINATING})


class ManagedSession:
    """A session with all its associated engines wired together."""

    __slots__ = ("sso", "reversibility", "delta_engine", "saga")

    def __init__(self, sso: SharedSessionObject) -> None:
        self.sso = sso
        self.reversibility = ReversibilityRegistry(sso.session_id)
        self.delta_engine = DeltaEngine(sso.session_id)
        self.saga = SagaOrchestrator()


class Hypervisor:
    """
    Top-level orchestrator for the Agent Hypervisor.

    Usage (basic — sigma_raw passed directly):
        hv = Hypervisor()
        session = await hv.create_session(config, creator_did="did:mesh:admin")
        await hv.join_session(session.sso.session_id, "did:mesh:agent-1", sigma_raw=0.85)

    Usage (enriched — adapters resolve sigma and parse manifests):
        hv = Hypervisor(
            nexus=trust_adapter,
            policy_check=verification_adapter,
            iatp=manifest_adapter,
        )
    """

    def __init__(
        self,
        retention_policy: RetentionPolicy | None = None,
        max_exposure: float | None = None,
        nexus: Any | None = None,
        policy_check: Any | None = None,
        iatp: Any | None = None,
    ) -> None:
        # Shared engines
        self.vouching = VouchingEngine(max_exposure=max_exposure)
        self.slashing = SlashingEngine(self.vouching)
        self.ring_enforcer = RingEnforcer()
        self.classifier = ActionClassifier()
        self.verifier = TransactionHistoryVerifier()
        self.commitment = CommitmentEngine()
        self.gc = EphemeralGC(retention_policy)

        # Aliases expected by API layer
        self.commitment_engine = self.commitment
        self.history_verifier = self.verifier

        # Integration adapters (optional)
        self.nexus = nexus
        self.policy_check = policy_check
        self.iatp = iatp

        # Active sessions
        self._sessions: dict[str, ManagedSession] = {}
        # Index of session IDs still requiring monitoring (non-archived/terminating)
        self._active_ids: set[str] = set()

    async def create_session(
        self,
        config: SessionConfig,
        creator_did: str,
    ) -> ManagedSession:
        """Create a new Shared Session."""
        sso = SharedSessionObject(config=config, creator_did=creator_did)
        sso.begin_handshake()
        managed = ManagedSession(sso)
        self._sessions[sso.session_id] = managed
        self._active_ids.add(sso.session_id)
        return managed

    async def join_session(
        self,
        session_id: str,
        agent_did: str,
        actions: list[ActionDescriptor] | None = None,
        sigma_raw: float = 0.0,
        manifest: Any | None = None,
        agent_history: Any | None = None,
    ) -> ExecutionRing:
        """
        Join an agent to a session via extended IATP handshake.

        Steps:
        1. Parse IATP manifest (if adapter + manifest provided)
        2. Register actions in Reversibility Registry
        3. Force Strong mode if non-reversible actions exist
        4. Verify DID transaction history
        5. Resolve eff_score (Nexus adapter or raw fallback) and assign ring
        """
        managed = self._get_session(session_id)

        # Step 1: IATP manifest enrichment
        if self.iatp and manifest:
            if isinstance(manifest, dict):
                analysis = self.iatp.analyze_manifest_dict(manifest)
            else:
                analysis = self.iatp.analyze_manifest(manifest)
            # Use manifest actions if none explicitly provided
            if not actions:
                actions = analysis.actions
            # Use IATP sigma hint as fallback
            if sigma_raw == 0.0:
                sigma_raw = analysis.sigma_hint
            logger.debug("IATP manifest parsed for %s: ring_hint=%s", agent_did, analysis.ring_hint)

        # Step 2: Register actions
        if actions:
            managed.reversibility.register_from_manifest(actions)

        # Step 3: Mode negotiation
        if managed.reversibility.has_non_reversible_actions():
            managed.sso.force_consistency_mode(ConsistencyMode.STRONG)

        # Step 4: Verify history
        verification = self.verifier.verify(agent_did)

        # Step 5: Resolve effective score
        eff_score = sigma_raw

        # Nexus enrichment: if adapter is available and no explicit sigma given
        if self.nexus and sigma_raw == 0.0:
            eff_score = self.nexus.resolve_sigma(
                agent_did,
                history=agent_history,
            )
            logger.debug("Nexus resolved sigma=%.3f for %s", eff_score, agent_did)
        elif self.nexus and agent_history:
            # Even with explicit sigma, Nexus can verify/enrich
            nexus_sigma = self.nexus.resolve_sigma(
                agent_did,
                history=agent_history,
            )
            # Use the lower of provided vs Nexus (conservative)
            eff_score = min(sigma_raw, nexus_sigma)

        ring = self.ring_enforcer.compute_ring(eff_score)

        # Probationary agents get sandbox
        if not verification.is_trustworthy:
            ring = ExecutionRing.RING_3_SANDBOX

        # Join the session
        managed.sso.join(
            agent_did=agent_did,
            sigma_raw=sigma_raw,
            eff_score=eff_score,
            ring=ring,
        )

        return ring

    async def activate_session(self, session_id: str) -> None:
        """Activate a session after handshaking is complete."""
        managed = self._get_session(session_id)
        managed.sso.activate()

    async def terminate_session(self, session_id: str) -> str | None:
        """
        Terminate a session and commit audit trail.

        Returns:
            audit log root summary hash, or None if audit disabled
        """
        managed = self._get_session(session_id)
        managed.sso.terminate()

        hash_chain_root = self._commit_audit(session_id, managed)
        self._cleanup_session(session_id, managed)

        return hash_chain_root

    def _commit_audit(self, session_id: str, managed: ManagedSession) -> str | None:
        """Commit audit trail and return hash chain root (None if audit disabled)."""
        if not managed.sso.config.enable_audit:
            return None
        hash_chain_root = managed.delta_engine.compute_hash_chain_root()
        if hash_chain_root:
            self.commitment.commit(
                session_id=session_id,
                hash_chain_root=hash_chain_root,
                participant_dids=[p.agent_did for p in managed.sso.participants],
                delta_count=managed.delta_engine.turn_count,
            )
        return hash_chain_root

    def _cleanup_session(self, session_id: str, managed: ManagedSession) -> None:
        """Release bonds, purge VFS data, and archive session."""
        self.vouching.release_session_bonds(session_id)
        self.gc.collect(
            session_id=session_id,
            vfs=managed.sso.vfs if hasattr(managed.sso, "vfs") else None,
            delta_engine=managed.delta_engine,
            delta_count=managed.delta_engine.turn_count,
        )
        managed.sso.archive()
        # Remove from active index after archiving
        self._active_ids.discard(session_id)

    def get_session(self, session_id: str) -> ManagedSession | None:
        return self._sessions.get(session_id)

    async def verify_behavior(
        self,
        session_id: str,
        agent_did: str,
        claimed_embedding: Any,
        observed_embedding: Any,
        action_id: str | None = None,
    ) -> Any | None:
        """
        Verify agent behavior via Verification adapter.

        If drift exceeds threshold, automatically slashes the agent and
        reports to Nexus (if adapter is available).

        Returns:
            DriftCheckResult if Verification adapter is configured, else None.
        """
        if not self.policy_check:
            return None

        result = self.policy_check.check_behavioral_drift(
            agent_did=agent_did,
            session_id=session_id,
            claimed_embedding=claimed_embedding,
            observed_embedding=observed_embedding,
            action_id=action_id,
        )

        if result.should_slash:
            managed = self._get_session(session_id)
            participant = managed.sso.get_participant(agent_did)
            # Build scores dict only for the slash path (avoid on healthy agents)
            agent_scores = {
                p.agent_did: p.eff_score
                for p in managed.sso.participants
            }
            self.slashing.slash(
                vouchee_did=agent_did,
                session_id=session_id,
                vouchee_sigma=participant.eff_score,
                risk_weight=0.95,
                reason=f"Verification drift: {result.drift_score:.3f} ({result.severity.value})",
                agent_scores=agent_scores,
            )
            # Propagate to Nexus
            if self.nexus:
                severity = "critical" if result.drift_score >= 0.75 else "high"
                self.nexus.report_slash(
                    agent_did=agent_did,
                    reason=f"Behavioral drift: {result.drift_score:.3f}",
                    severity=severity,
                )
            logger.warning("Agent %s penalized: drift=%.3f", agent_did, result.drift_score)

        return result

    @property
    def active_sessions(self) -> list[ManagedSession]:
        # Use the active index to skip archived/terminated sessions
        return [self._sessions[sid] for sid in self._active_ids
                if sid in self._sessions]

    def _get_session(self, session_id: str) -> ManagedSession:
        managed = self._sessions.get(session_id)
        if not managed:
            raise ValueError(f"Session {session_id} not found")
        return managed

    async def monitor_sessions(
        self,
        drift_threshold: float = 0.5,
    ) -> list[dict[str, Any]]:
        """
        Batch-monitor all active sessions with early exits.

        Skips archived/terminated sessions via the active index and skips
        healthy agents (those with eff_score above the drift threshold) to
        reduce per-iteration overhead.

        Returns a list of issues found (empty if all healthy).
        """
        issues: list[dict[str, Any]] = []
        # Iterate only over active session IDs (O(active) not O(total))
        for sid in list(self._active_ids):
            managed = self._sessions.get(sid)
            if managed is None:
                self._active_ids.discard(sid)
                continue
            state = managed.sso.state
            # Early exit: skip sessions that have transitioned to inactive
            if state in _INACTIVE_STATES:
                self._active_ids.discard(sid)
                continue
            # Batch-check participants; skip healthy agents
            for p in managed.sso.participants:
                if p.eff_score >= drift_threshold:
                    continue
                # Only flag agents below threshold
                issues.append({
                    "session_id": sid,
                    "agent_did": p.agent_did,
                    "eff_score": p.eff_score,
                    "ring": p.ring,
                    "state": state.value,
                })
        return issues
