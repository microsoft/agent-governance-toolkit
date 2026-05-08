# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Entra Agent Identity Bridge for Citadel Layer 3

Maps AGT's Ed25519/SPIFFE agent identities to Microsoft Entra ID agent
identities, enabling Citadel Layer 3 (Agent Identity) to recognize and
track AGT-governed agents.

Design principles:
- This is **attestation/federation**, not write-back.
- Entra/Agent 365 remains authoritative for enterprise identity and lifecycle.
- AGT remains authoritative for runtime credentials and trust scores.
- AGT trust scores surface as telemetry risk labels, not primary Entra metadata.
- If Entra is unavailable, AGT continues with local identity (fail-open).

Usage:
    from agent_os.integrations.citadel.identity_bridge import (
        EntraIdentityBridge,
        AgentIdentityBinding,
    )

    bridge = EntraIdentityBridge.from_env()
    binding = bridge.bind(
        agt_agent_id="customer-support-agent-01",
        agt_public_key="<base64-ed25519-pubkey>",
        entra_object_id="00000000-0000-0000-0000-000000000001",
    )
    attestation = bridge.attest(binding, trust_score=850)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)


class TrustRiskLabel(str, Enum):
    """Risk labels derived from AGT trust scores.

    These are the labels surfaced in telemetry and observability pipelines.
    They are NOT written back to Entra as primary attributes.
    """

    TRUSTED = "trusted"
    DEGRADED = "degraded"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"

    @classmethod
    def from_score(cls, score: int) -> TrustRiskLabel:
        """Derive a risk label from an AGT trust score (0-1000).

        Thresholds:
            >= 700: trusted
            >= 400: degraded
            < 400:  untrusted
        """
        if score >= 700:
            return cls.TRUSTED
        if score >= 400:
            return cls.DEGRADED
        return cls.UNTRUSTED


@dataclass
class AgentIdentityBinding:
    """Binding between an AGT agent identity and an Entra agent identity.

    This binding is created once (at registration/provisioning time) and
    cached for the agent's lifetime. It does NOT grant Entra permissions
    or modify Entra objects.

    Attributes:
        binding_id: Unique ID for this binding.
        agt_agent_id: The AGT agent identifier.
        agt_public_key_thumbprint: SHA-256 thumbprint of the Ed25519 public key.
        agt_spiffe_id: Optional SPIFFE ID (spiffe://domain/agent/...).
        entra_object_id: The Entra ID object ID for the agent's managed identity
            or app registration.
        entra_app_id: Optional Entra application (client) ID.
        created_at: ISO 8601 timestamp of binding creation.
        verified: Whether the binding has been verified via key attestation.
    """

    binding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agt_agent_id: str = ""
    agt_public_key_thumbprint: str = ""
    agt_spiffe_id: str = ""
    entra_object_id: str = ""
    entra_app_id: str = ""
    created_at: str = field(
        default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    )
    verified: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a dictionary."""
        return asdict(self)


@dataclass
class IdentityAttestation:
    """An attestation record linking AGT governance state to an Entra identity.

    Attestations are emitted as telemetry events. They provide a snapshot
    of the agent's governance posture at a point in time, correlated to
    its enterprise identity.

    Attributes:
        attestation_id: Unique ID for this attestation.
        binding_id: The identity binding this attestation references.
        agt_agent_id: The AGT agent identifier.
        entra_object_id: The Entra agent object ID.
        trust_score: Current AGT trust score (0-1000).
        risk_label: Derived risk label (trusted/degraded/untrusted).
        policy_bundle_id: Currently loaded policy bundle.
        policy_bundle_hash: SHA-256 hash of the loaded policy bundle.
        timestamp: ISO 8601 timestamp.
        metadata: Additional attestation context.
    """

    attestation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    binding_id: str = ""
    agt_agent_id: str = ""
    entra_object_id: str = ""
    trust_score: int = 0
    risk_label: TrustRiskLabel = TrustRiskLabel.UNKNOWN
    policy_bundle_id: str = ""
    policy_bundle_hash: str = ""
    timestamp: str = field(
        default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    )
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a dictionary."""
        data = asdict(self)
        data["risk_label"] = self.risk_label.value
        return data

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), default=str)


class EntraIdentityBridge:
    """Bridges AGT agent identities to Entra ID agent identities.

    The bridge maintains a local registry of bindings (AGT agent <-> Entra object)
    and produces attestation events that surface AGT trust scores as risk labels
    in telemetry pipelines.

    This bridge does NOT:
    - Write to Entra ID (no Graph API mutations)
    - Grant or revoke permissions
    - Replace AGT's runtime identity system

    It DOES:
    - Map AGT identities to Entra objects for correlation
    - Produce attestation events with risk labels for observability
    - Enable Citadel Layer 3 dashboards to show AGT governance posture
    """

    def __init__(
        self,
        tenant_id: str = "",
        verify_entra: bool = False,
    ) -> None:
        """Initialize the bridge.

        Args:
            tenant_id: Entra tenant ID (for validation, not for Graph calls).
            verify_entra: If True, verify Entra object IDs exist via Graph API.
                Requires azure-identity and msgraph-sdk. Default: False.
        """
        self._tenant_id = tenant_id
        self._verify_entra = verify_entra
        self._bindings: dict[str, AgentIdentityBinding] = {}
        self._graph_client: Any = None

    @classmethod
    def from_env(cls) -> EntraIdentityBridge:
        """Create a bridge from environment variables.

        Environment variables:
            CITADEL_ENTRA_TENANT_ID: Entra tenant ID.
            CITADEL_ENTRA_VERIFY: Set to "true" to verify Entra objects via Graph.
        """
        return cls(
            tenant_id=os.environ.get("CITADEL_ENTRA_TENANT_ID", ""),
            verify_entra=os.environ.get("CITADEL_ENTRA_VERIFY", "").lower() == "true",
        )

    def bind(
        self,
        agt_agent_id: str,
        agt_public_key: str = "",
        agt_spiffe_id: str = "",
        entra_object_id: str = "",
        entra_app_id: str = "",
    ) -> AgentIdentityBinding:
        """Create a binding between an AGT agent and an Entra identity.

        This is typically called once at agent registration/provisioning time.
        The binding is cached locally.

        Args:
            agt_agent_id: The AGT agent identifier.
            agt_public_key: Base64-encoded Ed25519 public key.
            agt_spiffe_id: SPIFFE ID for the agent.
            entra_object_id: Entra ID object ID (managed identity or app registration).
            entra_app_id: Entra application (client) ID.

        Returns:
            The created AgentIdentityBinding.
        """
        # Compute key thumbprint
        thumbprint = ""
        if agt_public_key:
            thumbprint = hashlib.sha256(agt_public_key.encode()).hexdigest()

        binding = AgentIdentityBinding(
            agt_agent_id=agt_agent_id,
            agt_public_key_thumbprint=thumbprint,
            agt_spiffe_id=agt_spiffe_id,
            entra_object_id=entra_object_id,
            entra_app_id=entra_app_id,
            verified=False,
        )

        # Optionally verify the Entra object exists
        if self._verify_entra and entra_object_id:
            binding.verified = self._verify_entra_object(entra_object_id)
            if not binding.verified:
                logger.warning(
                    "Entra object %s could not be verified for agent %s",
                    entra_object_id,
                    agt_agent_id,
                )

        self._bindings[agt_agent_id] = binding
        logger.info(
            "Bound AGT agent '%s' (key: %s) to Entra object %s",
            agt_agent_id,
            thumbprint[:12] if thumbprint else "none",
            entra_object_id or "none",
        )
        return binding

    def attest(
        self,
        binding: AgentIdentityBinding,
        trust_score: int,
        policy_bundle_id: str = "",
        policy_bundle_hash: str = "",
        metadata: Optional[dict[str, Any]] = None,
    ) -> IdentityAttestation:
        """Create an attestation record for an agent's current governance posture.

        The attestation maps the AGT trust score to a risk label and packages
        it with the identity binding for export to telemetry pipelines.

        Args:
            binding: The identity binding to attest.
            trust_score: Current AGT trust score (0-1000).
            policy_bundle_id: ID of the currently loaded policy bundle.
            policy_bundle_hash: SHA-256 hash of the policy bundle content.
            metadata: Additional context for the attestation.

        Returns:
            An IdentityAttestation ready for export.
        """
        attestation = IdentityAttestation(
            binding_id=binding.binding_id,
            agt_agent_id=binding.agt_agent_id,
            entra_object_id=binding.entra_object_id,
            trust_score=trust_score,
            risk_label=TrustRiskLabel.from_score(trust_score),
            policy_bundle_id=policy_bundle_id,
            policy_bundle_hash=policy_bundle_hash,
            metadata=metadata or {},
        )

        logger.info(
            "Attestation for agent '%s': score=%d label=%s entra=%s",
            binding.agt_agent_id,
            trust_score,
            attestation.risk_label.value,
            binding.entra_object_id or "unbound",
        )
        return attestation

    def get_binding(self, agt_agent_id: str) -> Optional[AgentIdentityBinding]:
        """Look up an existing binding for an AGT agent.

        Args:
            agt_agent_id: The AGT agent identifier.

        Returns:
            The binding, or None if not found.
        """
        return self._bindings.get(agt_agent_id)

    def list_bindings(self) -> list[AgentIdentityBinding]:
        """List all registered identity bindings."""
        return list(self._bindings.values())

    def remove_binding(self, agt_agent_id: str) -> bool:
        """Remove an identity binding.

        Args:
            agt_agent_id: The AGT agent identifier to unbind.

        Returns:
            True if the binding was removed, False if it didn't exist.
        """
        if agt_agent_id in self._bindings:
            del self._bindings[agt_agent_id]
            logger.info("Removed identity binding for agent '%s'", agt_agent_id)
            return True
        return False

    def _verify_entra_object(self, object_id: str) -> bool:
        """Verify an Entra object exists via Microsoft Graph API.

        Args:
            object_id: The Entra object ID to verify.

        Returns:
            True if the object exists, False otherwise.
        """
        try:
            from azure.identity import DefaultAzureCredential

            import urllib.request
        except ImportError:
            logger.warning(
                "azure-identity not installed, skipping Entra verification. "
                "Install with: pip install azure-identity"
            )
            return False

        try:
            if self._graph_client is None:
                self._graph_client = DefaultAzureCredential()

            token = self._graph_client.get_token("https://graph.microsoft.com/.default")
            req = urllib.request.Request(
                f"https://graph.microsoft.com/v1.0/directoryObjects/{object_id}",
                headers={"Authorization": f"Bearer {token.token}"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except Exception as e:
            logger.debug("Entra verification failed for %s: %s", object_id, e)
            return False
