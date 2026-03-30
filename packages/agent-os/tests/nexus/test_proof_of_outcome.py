# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import pytest
from nexus.escrow import ProofOfOutcome, EscrowManager
from nexus.reputation import ReputationEngine
from nexus import crypto

@pytest.fixture
def reputation_engine():
    return ReputationEngine(trust_threshold=500)

@pytest.fixture
def escrow_manager(reputation_engine):
    em = EscrowManager(reputation_engine=reputation_engine)
    em.add_credits("did:nexus:requester-agent", 1000)
    return em

@pytest.fixture
def proof_of_outcome(escrow_manager):
    return ProofOfOutcome(escrow_manager=escrow_manager)

@pytest.mark.asyncio
async def test_create_escrow_with_signing(proof_of_outcome, escrow_manager):
    priv, pub = crypto.generate_keypair()
    
    # Create escrow with signing
    receipt = await proof_of_outcome.create_escrow(
        requester_did="did:nexus:requester-agent",
        provider_did="did:nexus:provider-agent",
        task_hash="abc123def456",
        credits=100,
        private_key=priv
    )
    
    assert receipt.requester_signature is not None
    # Verify the signature matches
    crypto.verify_signature(pub, receipt.requester_signature, receipt.request)

@pytest.mark.asyncio
async def test_create_escrow_legacy_signature(proof_of_outcome):
    # Create escrow WITHOUT signing (legacy mode)
    receipt = await proof_of_outcome.create_escrow(
        requester_did="did:nexus:requester-agent",
        provider_did="did:nexus:provider-agent",
        task_hash="abc123def456",
        credits=100
    )
    
    # Legacy signature should be in the expected format: sig_{requester_did}_{task_hash[:8]}
    expected_sig = "sig_did:nexus:requester-agent_abc123de"
    assert receipt.requester_signature == expected_sig
