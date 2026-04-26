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

from .agent_id import AgentIdentity, AgentDID
from .entra import EntraAgentIdentity, EntraAgentRegistry, EntraAgentBlueprint
from .entra_agent_id import EntraAgentID
from .credentials import Credential, CredentialManager
from .delegation import ScopeChain, DelegationLink, UserContext
from .sponsor import HumanSponsor
from .risk import RiskScorer, RiskScore
from .spiffe import SPIFFEIdentity, SVID
from .namespace import AgentNamespace, NamespaceRule
from .namespace_manager import NamespaceManager
from .revocation import RevocationList, RevocationEntry
from .rotation import KeyRotationManager
from .jwk import to_jwk, from_jwk, to_jwks, from_jwks
from .managed_identity import (
    ManagedIdentityAdapter,
    EntraManagedIdentity,
    AWSIAMIdentity,
    GCPWorkloadIdentity,
)
from .mtls import MTLSConfig, MTLSIdentityVerifier
from .keystore import KeyStore, SoftwareKeyStore, PKCS11KeyStore

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
    "EntraAgentIdentity",
    "EntraAgentRegistry",
    "EntraAgentBlueprint",
    "EntraAgentID",
    "ManagedIdentityAdapter",
    "EntraManagedIdentity",
    "AWSIAMIdentity",
    "GCPWorkloadIdentity",
]
