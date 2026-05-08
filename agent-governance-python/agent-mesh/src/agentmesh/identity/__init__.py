# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Identity & Zero-Trust Core (Layer 1)

First-class agent identity with:
- Cryptographically bound identities
- Human sponsor accountability
- Ephemeral credentials (15-min TTL)
- SPIFFE/SVID workload identity
- Microsoft Entra Agent ID integration
"""

from .agent_id import AgentDID, AgentIdentity
from .attestation import (
    AttestationClaims,
    AttestationEvidence,
    ConfidentialLevel,
    KeyOrigin,
    ReferenceValues,
    compute_report_data_hash,
    compute_report_data_hash_hex,
    matches_report_data_binding,
    public_key_hash_hex,
)
from .credentials import Credential, CredentialManager
from .delegation import DelegationLink, ScopeChain, UserContext
from .entra import EntraAgentBlueprint, EntraAgentIdentity, EntraAgentRegistry
from .entra_agent_id import EntraAgentID
from .jwk import from_jwk, from_jwks, to_jwk, to_jwks
from .keystore import KeyStore, PKCS11KeyStore, SoftwareKeyStore
from .managed_identity import (
    AWSIAMIdentity,
    EntraManagedIdentity,
    GCPWorkloadIdentity,
    ManagedIdentityAdapter,
)
from .mtls import MTLSConfig, MTLSIdentityVerifier
from .namespace import AgentNamespace, NamespaceRule
from .namespace_manager import NamespaceManager
from .revocation import RevocationEntry, RevocationList
from .risk import RiskScore, RiskScorer
from .rotation import KeyRotationManager
from .spiffe import SVID, SPIFFEIdentity
from .sponsor import HumanSponsor

__all__ = [
    "AgentIdentity",
    "AgentDID",
    "Credential",
    "CredentialManager",
    "ScopeChain",
    "DelegationLink",
    "UserContext",
    "HumanSponsor",
    "RiskScorer",
    "RiskScore",
    "SPIFFEIdentity",
    "SVID",
    "AgentNamespace",
    "NamespaceRule",
    "NamespaceManager",
    "RevocationList",
    "RevocationEntry",
    "KeyRotationManager",
    "to_jwk",
    "from_jwk",
    "to_jwks",
    "from_jwks",
    "MTLSConfig",
    "MTLSIdentityVerifier",
    "KeyStore",
    "SoftwareKeyStore",
    "PKCS11KeyStore",
    "AttestationClaims",
    "AttestationEvidence",
    "ConfidentialLevel",
    "KeyOrigin",
    "ReferenceValues",
    "compute_report_data_hash",
    "compute_report_data_hash_hex",
    "matches_report_data_binding",
    "public_key_hash_hex",
    "EntraAgentIdentity",
    "EntraAgentRegistry",
    "EntraAgentBlueprint",
    "EntraAgentID",
    "ManagedIdentityAdapter",
    "EntraManagedIdentity",
    "AWSIAMIdentity",
    "GCPWorkloadIdentity",
]
