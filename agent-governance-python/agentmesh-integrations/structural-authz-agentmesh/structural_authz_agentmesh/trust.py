# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Structural authorization gates adapter for AgentMesh.

Consumes external policy decisions, trust grades, and delegation scope chains
as first-party trust signals in AGT's PolicyEngine. Provides Ed25519 signature
verification for incoming trust artifacts.

Provides:
- TrustGrade: External grade enum with AGT score mapping (0-1000)
- TrustArtifact: Signed external policy decision with Ed25519 verification
- DelegationLink: Single hop in a delegation scope chain
- DelegationChain: Full scope chain with cryptographic validation
- AgentProfile: Agent identity with DID, capabilities, and trust score
- AuthzGate: Trust-gated task authorization against external policy decisions
- TrustTracker: Track and update trust scores from external signal outcomes
"""

from __future__ import annotations

import base64
import json
import time
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ed25519

    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False
    warnings.warn(
        "cryptography package not installed — Ed25519 verification is disabled. "
        "Install with: pip install 'structural-authz-agentmesh[crypto]'",
        RuntimeWarning,
        stacklevel=2,
    )


class TrustGrade(str, Enum):
    """External trust grades mapped to AGT trust scores (0-1000).

    Grades follow a common external policy authority convention (e.g. SPIFFE,
    OPA, Cedar) where verdicts arrive as categorical labels. This enum maps
    those labels deterministically to the AGT 0-1000 integer scale.
    """

    VERIFIED = "verified"  # Fully attested, cryptographically proven
    TRUSTED = "trusted"  # Policy-approved, no flags
    PROVISIONAL = "provisional"  # Conditionally approved, pending attestation
    RESTRICTED = "restricted"  # Allowed but scope-limited
    UNTRUSTED = "untrusted"  # Policy denied
    REVOKED = "revoked"  # Previously trusted, now invalidated

    def to_agt_score(self) -> int:
        """Map external grade to AGT trust score (0-1000)."""
        return _GRADE_SCORE_MAP[self]


_GRADE_SCORE_MAP: Dict[TrustGrade, int] = {
    TrustGrade.VERIFIED: 950,
    TrustGrade.TRUSTED: 750,
    TrustGrade.PROVISIONAL: 500,
    TrustGrade.RESTRICTED: 300,
    TrustGrade.UNTRUSTED: 100,
    TrustGrade.REVOKED: 0,
}


@dataclass
class TrustArtifact:
    """A signed external policy decision consumed by the authorization gate.

    Artifacts are issued by an external trust authority (e.g. an OPA server,
    SPIFFE SVID issuer, or Cedar policy engine) and carry a grade, the subject
    agent DID, allowed scopes, and an Ed25519 signature over the canonical
    payload.

    The canonical payload for signing is deterministic JSON:
        {"did": ..., "grade": ..., "scopes": [...sorted...], "expires_at": ...}
    """

    did: str
    grade: TrustGrade
    scopes: List[str]
    issued_at: datetime
    expires_at: datetime
    issuer_public_key: str  # base64-encoded Ed25519 public key
    signature: str  # base64-encoded signature over canonical payload
    issuer_id: str = ""  # human-readable authority identifier
    metadata: Dict[str, Any] = field(default_factory=dict)

    def canonical_payload(self) -> str:
        """Return the deterministic JSON string that was signed."""
        return json.dumps(
            {
                "did": self.did,
                "grade": self.grade.value,
                "scopes": sorted(self.scopes),
                "expires_at": self.expires_at.isoformat(),
            },
            separators=(",", ":"),
            sort_keys=True,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "did": self.did,
            "grade": self.grade.value,
            "scopes": self.scopes,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "issuer_public_key": self.issuer_public_key,
            "signature": self.signature,
            "issuer_id": self.issuer_id,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TrustArtifact:
        return cls(
            did=data["did"],
            grade=TrustGrade(data["grade"]),
            scopes=data.get("scopes", []),
            issued_at=datetime.fromisoformat(data["issued_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            issuer_public_key=data["issuer_public_key"],
            signature=data["signature"],
            issuer_id=data.get("issuer_id", ""),
            metadata=data.get("metadata", {}),
        )

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at

    def verify_signature(self) -> bool:
        """Verify the Ed25519 signature over the canonical payload.

        Returns False (fail-closed) when the cryptography package is not
        installed rather than falling back to an insecure simulation.
        """
        if not _CRYPTO_AVAILABLE:
            warnings.warn(
                "Ed25519 verification skipped — cryptography package not installed. "
                "Artifact signatures are NOT verified.",
                RuntimeWarning,
                stacklevel=2,
            )
            return False

        try:
            public_key_bytes = base64.b64decode(self.issuer_public_key)
            public_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(
                public_key_bytes
            )
            signature_bytes = base64.b64decode(self.signature)
            public_key_obj.verify(
                signature_bytes, self.canonical_payload().encode("utf-8")
            )
            return True
        except (InvalidSignature, ValueError):
            return False

    @staticmethod
    def sign(
        did: str,
        grade: TrustGrade,
        scopes: List[str],
        expires_at: datetime,
        private_key_b64: str,
        issuer_public_key_b64: str,
        issuer_id: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> TrustArtifact:
        """Create and sign a new TrustArtifact.

        Args:
            did: Subject agent DID.
            grade: External trust grade.
            scopes: Allowed operation scopes.
            expires_at: Hard expiry for this artifact.
            private_key_b64: Base64-encoded Ed25519 private key (32 bytes raw).
            issuer_public_key_b64: Corresponding base64-encoded public key.
            issuer_id: Human-readable authority name.
            metadata: Optional extra metadata.

        Raises:
            RuntimeError: If the cryptography package is not installed.
        """
        if not _CRYPTO_AVAILABLE:
            raise RuntimeError(
                "cryptography package is required to sign TrustArtifacts. "
                "Install with: pip install 'structural-authz-agentmesh[crypto]'"
            )

        artifact = TrustArtifact(
            did=did,
            grade=grade,
            scopes=scopes,
            issued_at=datetime.now(timezone.utc),
            expires_at=expires_at,
            issuer_public_key=issuer_public_key_b64,
            signature="",
            issuer_id=issuer_id,
            metadata=metadata or {},
        )

        private_key_bytes = base64.b64decode(private_key_b64)
        private_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(
            private_key_bytes
        )
        sig_bytes = private_key_obj.sign(artifact.canonical_payload().encode("utf-8"))
        artifact.signature = base64.b64encode(sig_bytes).decode("ascii")
        return artifact


@dataclass
class DelegationLink:
    """One hop in a delegation scope chain.

    A delegator grants a delegatee a subset of their own scopes for a
    specific duration. Each link carries an Ed25519 signature from the
    delegator's private key over the canonical link payload.
    """

    delegator_did: str
    delegatee_did: str
    scopes: List[str]
    delegator_public_key: str  # base64-encoded
    signature: str  # base64-encoded, signs canonical_payload()
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None

    def canonical_payload(self) -> str:
        return json.dumps(
            {
                "delegator": self.delegator_did,
                "delegatee": self.delegatee_did,
                "scopes": sorted(self.scopes),
                "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            },
            separators=(",", ":"),
            sort_keys=True,
        )

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    def verify_signature(self) -> bool:
        """Verify the delegator's Ed25519 signature over this link."""
        if not _CRYPTO_AVAILABLE:
            return False
        try:
            public_key_bytes = base64.b64decode(self.delegator_public_key)
            public_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(
                public_key_bytes
            )
            sig_bytes = base64.b64decode(self.signature)
            public_key_obj.verify(sig_bytes, self.canonical_payload().encode("utf-8"))
            return True
        except (InvalidSignature, ValueError):
            return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "delegator_did": self.delegator_did,
            "delegatee_did": self.delegatee_did,
            "scopes": self.scopes,
            "delegator_public_key": self.delegator_public_key,
            "signature": self.signature,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


class ChainValidationError(Exception):
    """Raised when a delegation scope chain fails validation."""


class DelegationChain:
    """Validates a chain of delegation links for scope-based task authorization.

    The chain root is typically the trust artifact's subject (the agent who
    received the original grant from the external authority). Each subsequent
    link narrows the scope — a delegatee can only delegate scopes they
    themselves hold.

    Checks performed on validate():
    - Each link's signature is valid.
    - No link is expired.
    - Scopes do not widen at any hop (subset enforcement).
    - The chain is contiguous: delegatee of link[n] == delegator of link[n+1].
    - No circular delegations.
    - The final delegatee holds all required_scopes.
    """

    def __init__(self, root_did: str, root_scopes: List[str]) -> None:
        self._root_did = root_did
        self._root_scopes = set(root_scopes)
        self._links: List[DelegationLink] = []

    def add_link(self, link: DelegationLink) -> None:
        self._links.append(link)

    @property
    def links(self) -> List[DelegationLink]:
        return list(self._links)

    def validate(
        self,
        required_scopes: Optional[List[str]] = None,
        verify_signatures: bool = True,
    ) -> tuple[bool, str]:
        """Validate the full chain and check required_scopes are reachable.

        Returns:
            (True, "") on success.
            (False, reason) on any validation failure.
        """
        if not self._links:
            if required_scopes:
                missing = set(required_scopes) - self._root_scopes
                if missing:
                    return (
                        False,
                        f"Root does not hold required scopes: {sorted(missing)}",
                    )
            return True, ""

        # Contiguity and cycle detection
        seen_dids: Set[str] = {self._root_did}
        current_did = self._root_did
        current_scopes = set(self._root_scopes)

        for i, link in enumerate(self._links):
            if link.delegator_did != current_did:
                return (
                    False,
                    f"Link {i}: expected delegator {current_did!r}, got {link.delegator_did!r}",
                )

            if link.delegatee_did in seen_dids:
                return (
                    False,
                    f"Link {i}: circular delegation detected for {link.delegatee_did!r}",
                )

            if link.is_expired():
                return (
                    False,
                    f"Link {i}: delegation from {link.delegator_did!r} is expired",
                )

            delegated = set(link.scopes)
            excess = delegated - current_scopes
            if excess:
                return (
                    False,
                    f"Link {i}: delegated scopes exceed delegator's scopes: {sorted(excess)}",
                )

            if verify_signatures and not link.verify_signature():
                return False, f"Link {i}: invalid signature from {link.delegator_did!r}"

            seen_dids.add(link.delegatee_did)
            current_did = link.delegatee_did
            current_scopes = delegated

        if required_scopes:
            missing = set(required_scopes) - current_scopes
            if missing:
                return (
                    False,
                    f"Final delegatee {current_did!r} lacks required scopes: {sorted(missing)}",
                )

        return True, ""

    def effective_scopes_for(self, did: str) -> Set[str]:
        """Return the effective scopes held by a given DID in this chain."""
        if did == self._root_did:
            return set(self._root_scopes)

        current_did = self._root_did
        current_scopes = set(self._root_scopes)

        for link in self._links:
            if link.delegator_did != current_did:
                break
            current_did = link.delegatee_did
            current_scopes = set(link.scopes)
            if current_did == did:
                return current_scopes

        return set()


@dataclass
class AgentProfile:
    """Agent identity within the structural authorization layer (AgentMesh-aware)."""

    did: str
    name: str
    capabilities: List[str] = field(default_factory=list)
    trust_score: int = 500  # 0-1000
    status: str = "active"  # active, suspended, revoked
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    @property
    def is_active(self) -> bool:
        return self.status == "active"

    def has_capability(self, capability: str) -> bool:
        return capability in self.capabilities

    def has_all_capabilities(self, required: List[str]) -> bool:
        return all(c in self.capabilities for c in required)

    def has_any_capability(self, required: List[str]) -> bool:
        return any(c in self.capabilities for c in required)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "did": self.did,
            "name": self.name,
            "capabilities": self.capabilities,
            "trust_score": self.trust_score,
            "status": self.status,
        }


@dataclass
class AuthzDecision:
    """Result of an authorization gate evaluation."""

    allowed: bool
    agent: AgentProfile
    task: str
    required_scopes: List[str]
    reason: str = ""
    artifact_grade: Optional[TrustGrade] = None


class AuthzGate:
    """Trust-gated task authorization consuming external TrustArtifacts.

    Evaluates whether an agent may execute a task by:
    1. Validating the TrustArtifact signature (Ed25519).
    2. Checking the artifact is not expired.
    3. Mapping the external grade to an AGT score and comparing to min_trust_score.
    4. Verifying the artifact's scopes cover all required_scopes.
    5. Optionally validating a DelegationChain when scopes arrive via delegation.
    """

    def __init__(
        self,
        min_trust_score: int = 500,
        verify_signatures: bool = True,
    ) -> None:
        self.min_trust_score = min_trust_score
        self.verify_signatures = verify_signatures

    def evaluate(
        self,
        agent: AgentProfile,
        task: str,
        artifact: TrustArtifact,
        required_scopes: Optional[List[str]] = None,
        delegation_chain: Optional[DelegationChain] = None,
    ) -> AuthzDecision:
        """Evaluate an authorization request against an external trust artifact.

        Args:
            agent: The agent requesting task authorization.
            task: Human-readable task description.
            artifact: Signed external policy decision for the agent.
            required_scopes: Scopes the task requires (empty = no scope check).
            delegation_chain: Optional scope chain when acting as a delegatee.

        Returns:
            AuthzDecision with allowed=True only if all checks pass.
        """
        scopes = required_scopes or []

        if not agent.is_active:
            return AuthzDecision(
                allowed=False,
                agent=agent,
                task=task,
                required_scopes=scopes,
                reason=f"Agent '{agent.name}' is {agent.status}",
            )

        if artifact.did != agent.did:
            return AuthzDecision(
                allowed=False,
                agent=agent,
                task=task,
                required_scopes=scopes,
                reason=f"Artifact DID {artifact.did!r} does not match agent DID {agent.did!r}",
            )

        if artifact.is_expired():
            return AuthzDecision(
                allowed=False,
                agent=agent,
                task=task,
                required_scopes=scopes,
                reason="TrustArtifact is expired",
            )

        if self.verify_signatures and not artifact.verify_signature():
            return AuthzDecision(
                allowed=False,
                agent=agent,
                task=task,
                required_scopes=scopes,
                reason="TrustArtifact signature verification failed",
            )

        agt_score = artifact.grade.to_agt_score()
        if artifact.grade is TrustGrade.REVOKED or agt_score < self.min_trust_score:
            return AuthzDecision(
                allowed=False,
                agent=agent,
                task=task,
                required_scopes=scopes,
                artifact_grade=artifact.grade,
                reason=(
                    f"Grade '{artifact.grade.value}' maps to score {agt_score}, "
                    f"below minimum {self.min_trust_score}"
                ),
            )

        if scopes:
            if delegation_chain is not None:
                chain_ok, chain_reason = delegation_chain.validate(
                    required_scopes=scopes,
                    verify_signatures=self.verify_signatures,
                )
                if not chain_ok:
                    return AuthzDecision(
                        allowed=False,
                        agent=agent,
                        task=task,
                        required_scopes=scopes,
                        artifact_grade=artifact.grade,
                        reason=f"Delegation chain invalid: {chain_reason}",
                    )
            else:
                artifact_scopes = set(artifact.scopes)
                missing = set(scopes) - artifact_scopes
                if missing:
                    return AuthzDecision(
                        allowed=False,
                        agent=agent,
                        task=task,
                        required_scopes=scopes,
                        artifact_grade=artifact.grade,
                        reason=f"Artifact lacks required scopes: {sorted(missing)}",
                    )

        return AuthzDecision(
            allowed=True,
            agent=agent,
            task=task,
            required_scopes=scopes,
            artifact_grade=artifact.grade,
            reason="",
        )


class TrustTracker:
    """Tracks and updates agent trust scores from external authorization outcomes."""

    def __init__(
        self,
        success_reward: int = 10,
        failure_penalty: int = 50,
        min_score: int = 0,
        max_score: int = 1000,
    ) -> None:
        self.success_reward = success_reward
        self.failure_penalty = failure_penalty
        self.min_score = min_score
        self.max_score = max_score
        self._history: List[Dict[str, Any]] = []

    def record_success(self, agent: AgentProfile, task: str = "") -> int:
        """Record successful task execution. Returns the new trust score."""
        old = agent.trust_score
        agent.trust_score = min(agent.trust_score + self.success_reward, self.max_score)
        self._history.append(
            {
                "did": agent.did,
                "event": "success",
                "old_score": old,
                "new_score": agent.trust_score,
                "task": task,
                "timestamp": time.time(),
            }
        )
        return agent.trust_score

    def record_failure(
        self, agent: AgentProfile, task: str = "", reason: str = ""
    ) -> int:
        """Record task failure. Returns the new trust score."""
        old = agent.trust_score
        agent.trust_score = max(
            agent.trust_score - self.failure_penalty, self.min_score
        )
        self._history.append(
            {
                "did": agent.did,
                "event": "failure",
                "old_score": old,
                "new_score": agent.trust_score,
                "task": task,
                "reason": reason,
                "timestamp": time.time(),
            }
        )
        return agent.trust_score

    def get_history(self, did: Optional[str] = None) -> List[Dict[str, Any]]:
        if did:
            return [h for h in self._history if h["did"] == did]
        return list(self._history)


def generate_keypair() -> tuple[str, str]:
    """Generate an Ed25519 key pair for testing and development.

    Returns:
        (private_key_b64, public_key_b64) as base64-encoded strings.

    Raises:
        RuntimeError: If the cryptography package is not installed.
    """
    if not _CRYPTO_AVAILABLE:
        raise RuntimeError(
            "cryptography package required for key generation. "
            "Install with: pip install 'structural-authz-agentmesh[crypto]'"
        )
    private_key_obj = ed25519.Ed25519PrivateKey.generate()
    public_key_obj = private_key_obj.public_key()
    private_b64 = base64.b64encode(private_key_obj.private_bytes_raw()).decode("ascii")
    public_b64 = base64.b64encode(public_key_obj.public_bytes_raw()).decode("ascii")
    return private_b64, public_b64
