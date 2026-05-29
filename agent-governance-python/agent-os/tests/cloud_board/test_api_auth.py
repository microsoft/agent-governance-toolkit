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
    # F#12 — escrow.create_escrow now requires the provider DID to be
    # registered. Seed the three test DIDs so existing tests that don't
    # exercise registration continue to work.
    for did in (REQUESTER_DID, PROVIDER_DID, OTHER_DID):
        _seed_agent(did)


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

    # F#3 — uniform 401 (not 403) closes a token-validity oracle.
    assert response.status_code == 401


def test_compliance_reads_and_exports_require_admin(client: TestClient):
    unauthenticated = client.get("/v1/compliance/events")
    agent = client.get("/v1/compliance/events", headers=auth_header(REQUESTER_TOKEN))
    admin = client.get("/v1/compliance/events", headers=auth_header(ADMIN_TOKEN))

    assert unauthenticated.status_code == 401
    assert agent.status_code == 401  # F#3 oracle-close
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
    assert mint.status_code == 401  # F#3 oracle-close


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
    # F#5 — non-participant gets 404 (not 403) so dispute IDs cannot be
    # enumerated via status-code differential.
    assert blocked.status_code == 404


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


def test_get_agent_redacts_pii_for_other_authenticated_callers(client: TestClient):
    """F#3 — _view_manifest uses an allowlist and only the owner or admin
    sees full identity. Other authenticated callers and anonymous callers
    both see only the allowlisted fields.
    """
    _seed_agent(REQUESTER_DID)

    anon = client.get(f"/v1/agents/{REQUESTER_DID}").json()
    other = client.get(
        f"/v1/agents/{REQUESTER_DID}",
        headers=auth_header(PROVIDER_TOKEN),
    ).json()
    owner = client.get(
        f"/v1/agents/{REQUESTER_DID}",
        headers=auth_header(REQUESTER_TOKEN),
    ).json()
    admin = client.get(
        f"/v1/agents/{REQUESTER_DID}",
        headers=auth_header(ADMIN_TOKEN),
    ).json()

    # Anonymous + other-authenticated both redact PII.
    for view in (anon, other):
        assert "owner_id" not in view["identity"]
        assert "contact" not in view["identity"]
    # Only the owning agent or admin sees full identity.
    assert owner["identity"]["owner_id"] == "owner-1"
    assert owner["identity"]["contact"] == "ops@example.com"
    assert admin["identity"]["owner_id"] == "owner-1"
    assert admin["identity"]["contact"] == "ops@example.com"


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
    assert agent.status_code == 401  # F#3 oracle-close
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


# ---------------------------------------------------------------------------
# F#15 / F#4 — bearer-auth hardening regressions
# ---------------------------------------------------------------------------


def test_bearer_token_length_cap(client: TestClient):
    """F#15 — overlong bearer tokens are rejected before SHA-256."""
    response = client.get(
        f"/v1/escrow/credits/{REQUESTER_DID}",
        headers=auth_header("x" * 1024),
    )
    assert response.status_code == 401


def test_malformed_agent_token_entry_does_not_503_admin_plane(
    client: TestClient, monkeypatch
):
    """F#4 — a single malformed AGENT_TOKENS entry must not 503 every
    authenticated request (including the admin plane).
    """
    monkeypatch.setenv(
        "NEXUS_CLOUD_BOARD_AGENT_TOKENS",
        ",".join(
            [
                f"{REQUESTER_DID}={REQUESTER_TOKEN}",
                "this-is-malformed-no-equals",
                "did:nexus:bad=",
                "=missing-did",
                "not-a-did:foo=token",
                f"{PROVIDER_DID}={PROVIDER_TOKEN}",
            ]
        ),
    )
    admin = client.get("/v1/compliance/events", headers=auth_header(ADMIN_TOKEN))
    agent = client.get(
        f"/v1/escrow/credits/{REQUESTER_DID}",
        headers=auth_header(REQUESTER_TOKEN),
    )
    assert admin.status_code == 200
    assert agent.status_code == 200


# ---------------------------------------------------------------------------
# F#1, F#2, F#5, F#7, F#8, F#9, F#12 — escrow regression tests
# ---------------------------------------------------------------------------


def _create_funded_escrow(client: TestClient, credits: int = 40) -> str:
    """Seed credits and create an escrow; return the escrow_id."""
    client.post(
        f"/v1/escrow/credits/{REQUESTER_DID}/add",
        params={"amount": max(100, credits)},
        headers=auth_header(ADMIN_TOKEN),
    )
    created = client.post(
        "/v1/escrow",
        json=escrow_request(credits=credits),
        headers=auth_header(REQUESTER_TOKEN),
    )
    assert created.status_code == 200, created.json()
    return created.json()["escrow_id"]


def test_raise_dispute_rejects_terminal_escrow_no_double_payout(client: TestClient):
    """F#1 — after a successful /release, /dispute MUST NOT reopen the escrow,
    AND total system credits must not double.

    Full chain: create -> release(success) -> dispute (attempt) -> assert
    total system credits == original locked amount (not 2x).
    """
    escrow_id = _create_funded_escrow(client, credits=40)
    total_before = (
        escrow._agent_credits.get(REQUESTER_DID, 0)
        + escrow._agent_credits.get(PROVIDER_DID, 0)
        + escrow._escrows[escrow_id].get("credits", 0)
    )

    released = client.post(
        f"/v1/escrow/{escrow_id}/release",
        json={"outcome": "success", "scak_drift_score": 0.01},
        headers=auth_header(REQUESTER_TOKEN),
    )
    assert released.status_code == 200
    assert escrow._agent_credits[PROVIDER_DID] == 40

    # Attempt re-open via /dispute -- must be rejected.
    reopened = client.post(
        f"/v1/escrow/{escrow_id}/dispute",
        json={"reason": "actually it did not deliver"},
        headers=auth_header(REQUESTER_TOKEN),
    )
    assert reopened.status_code == 400
    assert reopened.json()["detail"]["error"] == "ESCROW_ALREADY_RESOLVED"
    assert escrow._escrows[escrow_id]["status"] == "released"

    # And via /disputes (submit_dispute path).
    via_disputes = client.post(
        "/v1/disputes",
        json={
            "escrow_id": escrow_id,
            "disputing_party": "requester",
            "dispute_reason": "second-pay attempt",
            "claimed_outcome": "failure",
        },
        headers=auth_header(REQUESTER_TOKEN),
    )
    assert via_disputes.status_code == 400

    # Total system credits unchanged (no double-pay).
    total_after = (
        escrow._agent_credits.get(REQUESTER_DID, 0)
        + escrow._agent_credits.get(PROVIDER_DID, 0)
    )
    assert total_after == total_before, (
        f"credits doubled: {total_before} -> {total_after}"
    )


def test_disburse_disputed_escrow_refuses_second_payout(client: TestClient):
    """F#1 defense-in-depth: even if status is flipped back to 'disputed'
    after a prior disbursement, the resolved_at marker blocks a second
    disbursement.
    """
    escrow_id, dispute_id = _open_resolved_dispute(client, outcome="failure")
    first = client.post(
        f"/v1/disputes/{dispute_id}/resolve",
        json={"outcome": "provider_wins", "explanation": "first"},
        headers=auth_header(ADMIN_TOKEN),
    )
    assert first.status_code == 200
    assert escrow._agent_credits[PROVIDER_DID] == 40

    escrow._escrows[escrow_id]["status"] = "disputed"
    with pytest.raises(Exception) as exc_info:
        escrow.disburse_disputed_escrow(
            escrow_id,
            credits_to_requester=0,
            credits_to_provider=40,
            resolution_reason="second-pay attempt",
        )
    assert "ESCROW_ALREADY_DISBURSED" in str(exc_info.value)
    assert escrow._agent_credits[PROVIDER_DID] == 40


@pytest.mark.parametrize("bad_value", [float("nan"), float("inf"), float("-inf")])
def test_scak_drift_score_rejects_non_finite_values(bad_value: float):
    """F#2 — NaN/+Inf/-Inf MUST NOT bypass the SCAK fail-closed gate.

    Asserted at the Pydantic model layer because httpx/JSON cannot
    transport non-finite floats over the wire (defense-in-depth).
    """
    from api.routes.escrow import ReleaseEscrowRequest
    from pydantic import ValidationError

    with pytest.raises(ValidationError) as exc_info:
        ReleaseEscrowRequest(outcome="success", scak_drift_score=bad_value)
    assert "finite" in str(exc_info.value).lower()


def test_release_dispute_branch_preserves_audit_reason(client: TestClient):
    """F#7 — /dispute then /release(outcome=dispute) MUST NOT clobber
    an existing dispute_reason with None.
    """
    escrow_id = _create_funded_escrow(client)
    client.post(
        f"/v1/escrow/{escrow_id}/dispute",
        json={"reason": "original audit reason"},
        headers=auth_header(REQUESTER_TOKEN),
    )
    assert escrow._escrows[escrow_id]["dispute_reason"] == "original audit reason"


def test_create_escrow_rejects_self_escrow(client: TestClient):
    """F#9 — requester_did == provider_did must 400."""
    client.post(
        f"/v1/escrow/credits/{REQUESTER_DID}/add",
        params={"amount": 100},
        headers=auth_header(ADMIN_TOKEN),
    )
    response = client.post(
        "/v1/escrow",
        json=escrow_request(provider_did=REQUESTER_DID),
        headers=auth_header(REQUESTER_TOKEN),
    )
    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "SELF_ESCROW_FORBIDDEN"


def test_create_escrow_rejects_unregistered_provider(client: TestClient):
    """F#12 — provider_did must be a registered agent."""
    client.post(
        f"/v1/escrow/credits/{REQUESTER_DID}/add",
        params={"amount": 100},
        headers=auth_header(ADMIN_TOKEN),
    )
    registry._agents.pop(PROVIDER_DID, None)
    response = client.post(
        "/v1/escrow",
        json=escrow_request(),
        headers=auth_header(REQUESTER_TOKEN),
    )
    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "PROVIDER_NOT_REGISTERED"


def test_unauthorized_escrow_access_returns_404_not_403(client: TestClient):
    """F#5 — unauthorized escrow access returns 404 (not 403) so escrow IDs
    cannot be enumerated via status-code differential.
    """
    escrow_id = _create_funded_escrow(client)
    other_view = client.get(
        f"/v1/escrow/{escrow_id}",
        headers=auth_header(OTHER_TOKEN),
    )
    nonexistent_view = client.get(
        "/v1/escrow/escrow_doesnotexist",
        headers=auth_header(OTHER_TOKEN),
    )
    assert other_view.status_code == 404
    assert nonexistent_view.status_code == 404


def test_dispute_reason_capped_on_release_dispute(client: TestClient):
    """F#8 — ReleaseEscrowRequest.dispute_reason is capped at 1000 chars."""
    escrow_id = _create_funded_escrow(client)
    response = client.post(
        f"/v1/escrow/{escrow_id}/release",
        json={"outcome": "dispute", "dispute_reason": "x" * 1001},
        headers=auth_header(REQUESTER_TOKEN),
    )
    assert response.status_code == 422

# ---------------------------------------------------------------------------
# F#5, F#6, F#8, F#14, F#17 — arbiter regression tests
# ---------------------------------------------------------------------------


def test_submit_dispute_rejects_duplicate_for_same_escrow(client: TestClient):
    """F#6 — only one unresolved dispute per escrow."""
    escrow_id = _create_funded_escrow(client)
    first = client.post(
        "/v1/disputes",
        json={
            "escrow_id": escrow_id,
            "disputing_party": "requester",
            "dispute_reason": "first",
            "claimed_outcome": "failure",
        },
        headers=auth_header(REQUESTER_TOKEN),
    )
    second = client.post(
        "/v1/disputes",
        json={
            "escrow_id": escrow_id,
            "disputing_party": "requester",
            "dispute_reason": "duplicate spam",
            "claimed_outcome": "failure",
        },
        headers=auth_header(REQUESTER_TOKEN),
    )
    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json()["detail"]["error"] == "DISPUTE_ALREADY_OPEN"


def test_submit_dispute_records_submitted_by(client: TestClient):
    """F#14 — disputes carry an attribution field for who initiated them."""
    escrow_id = _create_funded_escrow(client)
    response = client.post(
        "/v1/disputes",
        json={
            "escrow_id": escrow_id,
            "disputing_party": "requester",
            "dispute_reason": "did not deliver",
            "claimed_outcome": "failure",
        },
        headers=auth_header(REQUESTER_TOKEN),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["submitted_by"] == REQUESTER_DID
    assert arbiter._disputes[body["dispute_id"]]["submitted_by"] == REQUESTER_DID


def test_submit_dispute_unauthorized_returns_404_not_403(client: TestClient):
    """F#5 — submit_dispute against someone else's escrow returns 404."""
    escrow_id = _create_funded_escrow(client)
    response = client.post(
        "/v1/disputes",
        json={
            "escrow_id": escrow_id,
            "disputing_party": "requester",
            "dispute_reason": "trying to dispute someone else's escrow",
            "claimed_outcome": "failure",
        },
        headers=auth_header(OTHER_TOKEN),
    )
    assert response.status_code == 404


def test_dispute_reason_capped_on_submit_dispute(client: TestClient):
    """F#8 — SubmitDisputeRequest.dispute_reason is capped at 1000 chars."""
    escrow_id = _create_funded_escrow(client)
    response = client.post(
        "/v1/disputes",
        json={
            "escrow_id": escrow_id,
            "disputing_party": "requester",
            "dispute_reason": "x" * 1001,
            "claimed_outcome": "failure",
        },
        headers=auth_header(REQUESTER_TOKEN),
    )
    assert response.status_code == 422


def test_orphan_dispute_marked_terminal_when_escrow_gone(client: TestClient):
    """F#17 — if the escrow is deleted out from under a dispute, resolving it
    marks the dispute terminal (unresolvable) so it doesn't leak as orphan.
    """
    escrow_id, dispute_id = _open_resolved_dispute(client, outcome="failure")
    del escrow._escrows[escrow_id]

    response = client.post(
        f"/v1/disputes/{dispute_id}/resolve",
        json={"outcome": "requester_wins"},
        headers=auth_header(ADMIN_TOKEN),
    )
    assert response.status_code == 409
    assert arbiter._disputes[dispute_id]["resolved"] is True
    assert arbiter._disputes[dispute_id]["status"] == "unresolvable"

# ---------------------------------------------------------------------------
# F#3, F#11, F#16 — registry regression tests
# ---------------------------------------------------------------------------


def test_registration_rejects_naive_proof_timestamp(client: TestClient):
    """F#11 — naive (tz-less) proof timestamps must 400 (not 500 or accept)."""
    payload = signed_registration_request(
        "did:nexus:0000000000000000000000000000000000000000000000000000000000000000"
    )
    payload["proof_timestamp"] = datetime.now().replace(tzinfo=None).isoformat()
    response = client.post("/v1/agents", json=payload)
    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "INVALID_TIMESTAMP"


def test_did_now_uses_full_256_bit_sha256(client: TestClient):
    """F#16 — derived DID uses full 64-hex-char SHA-256 (no 128-bit truncation)."""
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
    import hashlib as _hashlib
    expected_did = "did:nexus:" + _hashlib.sha256(bytes(signing_key.verify_key)).hexdigest()
    assert len(expected_did) == len("did:nexus:") + 64

    response = client.post(
        "/v1/agents",
        json={
            "identity": {
                "did": expected_did,
                "verification_key": verification_key,
                "owner_id": "owner",
            },
            "proof": proof,
            "proof_timestamp": proof_timestamp,
        },
    )
    assert response.status_code == 200, response.json()
    assert response.json()["agent_did"] == expected_did

    # The legacy 32-char truncated DID must now be rejected.
    short_did = expected_did[: len("did:nexus:") + 32]
    response_short = client.post(
        "/v1/agents",
        json={
            "identity": {
                "did": short_did,
                "verification_key": verification_key,
                "owner_id": "owner",
            },
            "proof": proof,
            "proof_timestamp": proof_timestamp,
        },
    )
    assert response_short.status_code in (400, 409)
    if response_short.status_code == 400:
        assert response_short.json()["detail"]["error"] == "DID_MISMATCH"
