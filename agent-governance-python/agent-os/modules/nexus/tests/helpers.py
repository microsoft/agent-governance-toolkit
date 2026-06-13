# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Test helpers — shared keypair and signing utilities for Nexus tests.

Kept in a separate module so both conftest.py and test files can import from
the same module instance, avoiding double-import keypair mismatch.
"""

import os
import sys

_nexus_parent = os.path.join(os.path.dirname(__file__), "..", "..")
if _nexus_parent not in sys.path:
    sys.path.insert(0, _nexus_parent)

from nexus.crypto import generate_keypair, manifest_hash_for_signing, escrow_message, sign
from nexus.schemas.manifest import (
    AgentIdentity,
    AgentCapabilities,
    AgentPrivacy,
    AgentManifest,
)

# Single keypair for all tests. Generated once at import time.
TEST_PRIVATE_KEY, TEST_VERIFICATION_KEY = generate_keypair()


def reg_sig(manifest: AgentManifest, private_key: bytes = TEST_PRIVATE_KEY) -> str:
    """Valid registration/update signature for the given manifest."""
    return sign(private_key, manifest_hash_for_signing(manifest).encode())


def dereg_sig(agent_did: str, private_key: bytes = TEST_PRIVATE_KEY) -> str:
    """Valid deregistration signature for the given DID."""
    return sign(private_key, agent_did.encode())


def escrow_sig(
    requester_did: str,
    provider_did: str,
    task_hash: str,
    credits: int,
    private_key: bytes = TEST_PRIVATE_KEY,
) -> str:
    """Valid escrow signature."""
    return sign(private_key, escrow_message(requester_did, provider_did, task_hash, credits))


def make_manifest(
    did: str = "did:nexus:test-agent-v1",
    owner_id: str = "org-test-corp",
    verification_level: str = "registered",
    domains: list[str] | None = None,
    retention_policy: str = "ephemeral",
    pii_handling: str = "reject",
    training_consent: bool = False,
    idempotency: bool = False,
    reversibility: str = "partial",
    trust_score: int = 400,
    verification_key: str = TEST_VERIFICATION_KEY,
) -> AgentManifest:
    """Build an AgentManifest for tests."""
    return AgentManifest(
        identity=AgentIdentity(
            did=did,
            verification_key=verification_key,
            owner_id=owner_id,
        ),
        capabilities=AgentCapabilities(
            domains=domains or ["data-analysis"],
            idempotency=idempotency,
            reversibility=reversibility,
        ),
        privacy=AgentPrivacy(
            retention_policy=retention_policy,
            pii_handling=pii_handling,
            training_consent=training_consent,
        ),
        verification_level=verification_level,
        trust_score=trust_score,
    )
