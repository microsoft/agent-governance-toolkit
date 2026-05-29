# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Authentication and authorization tests for the Cloud Board API."""

from __future__ import annotations

import base64
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from nacl.signing import SigningKey

AGENT_OS_DIR = Path(__file__).resolve().parents[2]
CLOUD_BOARD_DIR = AGENT_OS_DIR / "services" / "cloud-board"
sys.path.insert(0, str(AGENT_OS_DIR))
sys.path.insert(0, str(CLOUD_BOARD_DIR))

from api.main import app  # noqa: E402
from api.routes import arbiter, compliance, escrow, registry, reputation  # noqa: E402

ADMIN_TOKEN = "admin-token"
REQUESTER_DID = "did:nexus:11111111111111111111111111111111"
PROVIDER_DID = "did:nexus:22222222222222222222222222222222"
OTHER_DID = "did:nexus:33333333333333333333333333333333"
REQUESTER_TOKEN = "requester-token"
PROVIDER_TOKEN = "provider-token"
OTHER_TOKEN = "other-token"


@pytest.fixture(autouse=True)
def reset_cloud_board_state(monkeypatch):
    monkeypatch.setenv("NEXUS_CLOUD_BOARD_ADMIN_TOKENS", ADMIN_TOKEN)
    monkeypatch.setenv(
        "NEXUS_CLOUD_BOARD_AGENT_TOKENS",
        ",".join(
            [
                f"{REQUESTER_DID}={REQUESTER_TOKEN}",
                f"{PROVIDER_DID}={PROVIDER_TOKEN}",
                f"{OTHER_DID}={OTHER_TOKEN}",
            ]
        ),
    )
    registry._agents.clear()
    reputation._reputation_history.clear()
    reputation._slash_events.clear()
    escrow._escrows.clear()
    escrow._agent_credits.clear()
    arbiter._disputes.clear()
    compliance._compliance_events.clear()


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def escrow_request(
    requester_did: str = REQUESTER_DID,
    provider_did: str = PROVIDER_DID,
    credits: int = 40,
) -> dict:
    return {
        "requester_did": requester_did,
        "provider_did": provider_did,
        "task_hash": "task-hash",
        "credits": credits,
    }


def test_protected_routes_require_bearer_token(client: TestClient):
    response = client.delete(f"/v1/agents/{REQUESTER_DID}")

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_registration_rejects_did_that_does_not_match_verification_key(client: TestClient):
    response = client.post("/v1/agents", json=signed_registration_request(OTHER_DID))

    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "DID_MISMATCH"


def test_non_admin_cannot_mutate_reputation(client: TestClient):
    response = client.post(
        f"/v1/reputation/{PROVIDER_DID}/report",
        json={"task_id": "task-1", "reporter_did": REQUESTER_DID, "outcome": "success"},
        headers=auth_header(REQUESTER_TOKEN),
    )

    assert response.status_code == 403


def test_compliance_reads_and_exports_require_admin(client: TestClient):
    unauthenticated = client.get("/v1/compliance/events")
    agent = client.get("/v1/compliance/events", headers=auth_header(REQUESTER_TOKEN))
    admin = client.get("/v1/compliance/events", headers=auth_header(ADMIN_TOKEN))

    assert unauthenticated.status_code == 401
    assert agent.status_code == 403
    assert admin.status_code == 200


def test_escrow_credits_start_at_zero_and_cannot_be_self_minted(client: TestClient):
    balance = client.get(
        f"/v1/escrow/credits/{REQUESTER_DID}",
        headers=auth_header(REQUESTER_TOKEN),
    )
    create = client.post(
        "/v1/escrow",
        json=escrow_request(),
        headers=auth_header(REQUESTER_TOKEN),
    )
    mint = client.post(
        f"/v1/escrow/credits/{REQUESTER_DID}/add",
        params={"amount": 100},
        headers=auth_header(REQUESTER_TOKEN),
    )

    assert balance.status_code == 200
    assert balance.json()["credits"] == 0
    assert REQUESTER_DID not in escrow._agent_credits
    assert create.status_code == 400
    assert create.json()["detail"]["error"] == "INSUFFICIENT_CREDITS"
    assert mint.status_code == 403


def test_admin_seeds_positive_credits_before_requester_creates_escrow(client: TestClient):
    seeded = client.post(
        f"/v1/escrow/credits/{REQUESTER_DID}/add",
        params={"amount": 100},
        headers=auth_header(ADMIN_TOKEN),
    )
    rejected = client.post(
        f"/v1/escrow/credits/{REQUESTER_DID}/add",
        params={"amount": 0},
        headers=auth_header(ADMIN_TOKEN),
    )
    created = client.post(
        "/v1/escrow",
        json=escrow_request(),
        headers=auth_header(REQUESTER_TOKEN),
    )

    assert seeded.status_code == 200
    assert seeded.json()["credits"] == 100
    assert rejected.status_code == 400
    assert created.status_code == 200
    assert created.json()["credits"] == 40
    assert escrow._agent_credits[REQUESTER_DID] == 60


def test_requester_token_cannot_create_escrow_for_another_agent(client: TestClient):
    response = client.post(
        "/v1/escrow",
        json=escrow_request(requester_did=OTHER_DID),
        headers=auth_header(REQUESTER_TOKEN),
    )

    assert response.status_code == 403


def test_escrow_release_pays_provider_without_default_balance(client: TestClient):
    client.post(
        f"/v1/escrow/credits/{REQUESTER_DID}/add",
        params={"amount": 100},
        headers=auth_header(ADMIN_TOKEN),
    )
    created = client.post(
        "/v1/escrow",
        json=escrow_request(),
        headers=auth_header(REQUESTER_TOKEN),
    )

    escrow_id = created.json()["escrow_id"]
    released = client.post(
        f"/v1/escrow/{escrow_id}/release",
        json={"outcome": "success", "scak_drift_score": 0.01},
        headers=auth_header(REQUESTER_TOKEN),
    )

    assert released.status_code == 200
    assert escrow._agent_credits[PROVIDER_DID] == 40


def test_dispute_access_is_limited_to_escrow_participants(client: TestClient):
    client.post(
        f"/v1/escrow/credits/{REQUESTER_DID}/add",
        params={"amount": 100},
        headers=auth_header(ADMIN_TOKEN),
    )
    escrow_response = client.post(
        "/v1/escrow",
        json=escrow_request(),
        headers=auth_header(REQUESTER_TOKEN),
    )
    escrow_id = escrow_response.json()["escrow_id"]

    created = client.post(
        "/v1/disputes",
        json={
            "escrow_id": escrow_id,
            "disputing_party": "requester",
            "dispute_reason": "provider did not deliver",
            "claimed_outcome": "failure",
        },
        headers=auth_header(REQUESTER_TOKEN),
    )
    blocked = client.get(
        f"/v1/disputes/{created.json()['dispute_id']}",
        headers=auth_header(OTHER_TOKEN),
    )

    assert created.status_code == 200
    assert blocked.status_code == 403


def _seed_agent(did: str, owner_id: str = "owner-1", contact: str = "ops@example.com") -> None:
    registry._agents[did] = {
        "identity": {
            "did": did,
            "verification_key": "vk",
            "owner_id": owner_id,
            "contact": contact,
        },
        "capabilities": {"domains": ["test"]},
        "privacy": {"retention_policy": "standard"},
        "trust_score": 600,
        "verification_level": "registered",
        "registered_at": datetime.now(timezone.utc).isoformat(),
        "last_seen": datetime.now(timezone.utc).isoformat(),
    }


def test_get_agent_redacts_pii_for_anonymous_callers(client: TestClient):
    _seed_agent(REQUESTER_DID)

    anon = client.get(f"/v1/agents/{REQUESTER_DID}").json()
    authed = client.get(
        f"/v1/agents/{REQUESTER_DID}",
        headers=auth_header(PROVIDER_TOKEN),
    ).json()

    assert "owner_id" not in anon["identity"]
    assert "contact" not in anon["identity"]
    assert authed["identity"]["owner_id"] == "owner-1"
    assert authed["identity"]["contact"] == "ops@example.com"


def test_discover_agents_redacts_pii_for_anonymous_callers(client: TestClient):
    _seed_agent(REQUESTER_DID)

    anon = client.get("/v1/agents/discover", params={"min_score": 0}).json()
    assert anon
    assert "owner_id" not in anon[0]["identity"]
    assert "contact" not in anon[0]["identity"]


def test_get_agent_rejects_invalid_bearer_token(client: TestClient):
    _seed_agent(REQUESTER_DID)

    response = client.get(
        f"/v1/agents/{REQUESTER_DID}",
        headers=auth_header("not-a-real-token"),
    )

    assert response.status_code == 401


def test_slash_history_requires_admin(client: TestClient):
    unauthenticated = client.get("/v1/reputation/slashes")
    agent = client.get("/v1/reputation/slashes", headers=auth_header(REQUESTER_TOKEN))
    admin = client.get("/v1/reputation/slashes", headers=auth_header(ADMIN_TOKEN))

    assert unauthenticated.status_code == 401
    assert agent.status_code == 403
    assert admin.status_code == 200


def test_raise_dispute_uses_json_body(client: TestClient):
    client.post(
        f"/v1/escrow/credits/{REQUESTER_DID}/add",
        params={"amount": 100},
        headers=auth_header(ADMIN_TOKEN),
    )
    escrow_response = client.post(
        "/v1/escrow",
        json=escrow_request(),
        headers=auth_header(REQUESTER_TOKEN),
    )
    escrow_id = escrow_response.json()["escrow_id"]

    via_query = client.post(
        f"/v1/escrow/{escrow_id}/dispute",
        params={"reason": "should-be-rejected"},
        headers=auth_header(REQUESTER_TOKEN),
    )
    via_body = client.post(
        f"/v1/escrow/{escrow_id}/dispute",
        json={"reason": "provider did not deliver outputs"},
        headers=auth_header(REQUESTER_TOKEN),
    )

    assert via_query.status_code == 422
    assert via_body.status_code == 200
    assert escrow._escrows[escrow_id]["dispute_reason"] == "provider did not deliver outputs"


def signed_registration_request(did: str) -> dict:
    signing_key = SigningKey.generate()
    verification_key = base64.urlsafe_b64encode(bytes(signing_key.verify_key)).decode().rstrip("=")
    proof_timestamp = datetime.now(timezone.utc).isoformat()
    proof = (
        base64.urlsafe_b64encode(
            signing_key.sign(verification_key.encode() + proof_timestamp.encode()).signature
        )
        .decode()
        .rstrip("=")
    )

    return {
        "identity": {
            "did": did,
            "verification_key": verification_key,
            "owner_id": "owner",
        },
        "proof": proof,
        "proof_timestamp": proof_timestamp,
    }
