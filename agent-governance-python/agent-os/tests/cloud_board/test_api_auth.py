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


def _open_resolved_dispute(client: TestClient, outcome: str) -> tuple[str, str]:
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
    dispute_response = client.post(
        "/v1/disputes",
        json={
            "escrow_id": escrow_id,
            "disputing_party": "requester",
            "dispute_reason": "provider did not deliver",
            "claimed_outcome": outcome,
        },
        headers=auth_header(REQUESTER_TOKEN),
    )
    dispute_id = dispute_response.json()["dispute_id"]
    for token in (REQUESTER_TOKEN, PROVIDER_TOKEN):
        client.post(
            f"/v1/disputes/{dispute_id}/evidence",
            params={"party": "requester" if token == REQUESTER_TOKEN else "provider"},
            json={"flight_recorder_logs_hash": f"hash-{token}"},
            headers=auth_header(token),
        )
    return escrow_id, dispute_id


def test_scak_release_without_drift_score_fails_closed(client: TestClient):
    client.post(
        f"/v1/escrow/credits/{REQUESTER_DID}/add",
        params={"amount": 100},
        headers=auth_header(ADMIN_TOKEN),
    )
    payload = escrow_request()
    payload["require_scak"] = True
    payload["scak_threshold"] = 0.15
    created = client.post(
        "/v1/escrow",
        json=payload,
        headers=auth_header(REQUESTER_TOKEN),
    )
    escrow_id = created.json()["escrow_id"]

    missing = client.post(
        f"/v1/escrow/{escrow_id}/release",
        json={"outcome": "success"},
        headers=auth_header(REQUESTER_TOKEN),
    )
    over_threshold = client.post(
        f"/v1/escrow/{escrow_id}/release",
        json={"outcome": "success", "scak_drift_score": 0.9},
        headers=auth_header(REQUESTER_TOKEN),
    )

    assert missing.status_code == 400
    assert missing.json()["detail"]["error"] == "SCAK_DRIFT_SCORE_REQUIRED"
    # Provider must not have been paid by the failed release attempt.
    assert PROVIDER_DID not in escrow._agent_credits
    # The escrow is still releasable; a subsequent attempt with a high drift
    # score should hit the failure path (returning credits to the requester).
    assert over_threshold.status_code == 200
    assert escrow._agent_credits[REQUESTER_DID] == 100


def test_resolve_dispute_requires_admin_supplied_outcome(client: TestClient):
    escrow_id, dispute_id = _open_resolved_dispute(client, outcome="success")

    no_body = client.post(
        f"/v1/disputes/{dispute_id}/resolve",
        headers=auth_header(ADMIN_TOKEN),
    )
    bad_outcome = client.post(
        f"/v1/disputes/{dispute_id}/resolve",
        json={"outcome": "requester_loses"},
        headers=auth_header(ADMIN_TOKEN),
    )
    resolved = client.post(
        f"/v1/disputes/{dispute_id}/resolve",
        json={"outcome": "requester_wins", "explanation": "evidence backed requester"},
        headers=auth_header(ADMIN_TOKEN),
    )

    assert no_body.status_code == 422
    assert bad_outcome.status_code == 422
    # Even though the disputing party claimed "success" (i.e. provider_wins),
    # the admin-supplied "requester_wins" is what gets recorded.
    assert resolved.status_code == 200
    assert resolved.json()["outcome"] == "requester_wins"
    assert arbiter._disputes[dispute_id]["resolution_outcome"] == "requester_wins"


def test_get_resolution_returns_stored_decision_and_404s_before_resolve(client: TestClient):
    _escrow_id, dispute_id = _open_resolved_dispute(client, outcome="failure")

    not_resolved = client.get(
        f"/v1/disputes/{dispute_id}/resolution",
        headers=auth_header(REQUESTER_TOKEN),
    )
    client.post(
        f"/v1/disputes/{dispute_id}/resolve",
        json={"outcome": "provider_wins", "explanation": "logs confirm delivery"},
        headers=auth_header(ADMIN_TOKEN),
    )
    fetched = client.get(
        f"/v1/disputes/{dispute_id}/resolution",
        headers=auth_header(REQUESTER_TOKEN),
    )

    assert not_resolved.status_code == 404
    assert not_resolved.json()["detail"]["error"] == "RESOLUTION_NOT_FOUND"
    body = fetched.json()
    assert fetched.status_code == 200
    assert body["outcome"] == "provider_wins"
    # Default escrow_request() locks 40 credits; the arbiter now disburses
    # the actual escrow balance (not a hardcoded 100).
    assert body["credits_to_provider"] == 40
    assert body["credits_to_requester"] == 0
    assert body["decision_explanation"] == "logs confirm delivery"


def test_release_outcome_failure_requires_provider_or_admin(client: TestClient):
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

    # Requester cannot unilaterally refund themselves via outcome=failure.
    requester_attempt = client.post(
        f"/v1/escrow/{escrow_id}/release",
        json={"outcome": "failure"},
        headers=auth_header(REQUESTER_TOKEN),
    )
    # Provider can acknowledge failure.
    provider_attempt = client.post(
        f"/v1/escrow/{escrow_id}/release",
        json={"outcome": "failure"},
        headers=auth_header(PROVIDER_TOKEN),
    )

    assert requester_attempt.status_code == 403
    # No partial refund must have happened from the rejected attempt.
    assert PROVIDER_DID not in escrow._agent_credits
    assert provider_attempt.status_code == 200
    # Provider acknowledging failure returns the locked credits to the requester.
    assert escrow._agent_credits[REQUESTER_DID] == 100  # 60 leftover + 40 refunded


def test_submit_dispute_locks_escrow_against_subsequent_release(client: TestClient):
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

    dispute = client.post(
        "/v1/disputes",
        json={
            "escrow_id": escrow_id,
            "disputing_party": "requester",
            "dispute_reason": "provider did not deliver",
            "claimed_outcome": "failure",
        },
        headers=auth_header(REQUESTER_TOKEN),
    )

    # The escrow is now locked in 'disputed' state. A direct release attempt
    # (from either party) must be rejected so the parties cannot bypass the
    # arbiter while the dispute is in flight.
    follow_up_release = client.post(
        f"/v1/escrow/{escrow_id}/release",
        json={"outcome": "success", "scak_drift_score": 0.01},
        headers=auth_header(REQUESTER_TOKEN),
    )

    assert dispute.status_code == 200
    assert escrow._escrows[escrow_id]["status"] == "disputed"
    assert follow_up_release.status_code == 400
    assert PROVIDER_DID not in escrow._agent_credits


def test_resolve_dispute_disburses_locked_credits_and_unlocks_escrow(client: TestClient):
    escrow_id, dispute_id = _open_resolved_dispute(client, outcome="failure")

    # Sanity: the escrow is currently locked at 'disputed' and credits remain
    # in escrow (neither party has been paid).
    assert escrow._escrows[escrow_id]["status"] == "disputed"
    assert escrow._agent_credits.get(PROVIDER_DID, 0) == 0

    resolved = client.post(
        f"/v1/disputes/{dispute_id}/resolve",
        json={"outcome": "provider_wins", "explanation": "evidence backed provider"},
        headers=auth_header(ADMIN_TOKEN),
    )

    assert resolved.status_code == 200
    # Locked credits (40) were actually moved to the provider, not just
    # returned in the response body.
    assert escrow._agent_credits[PROVIDER_DID] == 40
    # The escrow is no longer stuck in 'disputed'.
    assert escrow._escrows[escrow_id]["status"] == "released"
    assert escrow._escrows[escrow_id]["resolved_by"] == "arbiter"
    # A compliance event was emitted for the resolution.
    assert any(
        e.get("event_type") == "dispute_resolved" and e.get("dispute_id") == dispute_id
        for e in compliance._compliance_events
    )


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
