# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for signed distributed IFC receipts."""

from datetime import UTC, datetime, timedelta

from pydantic import BaseModel

from agentmesh.identity.agent_id import AgentIdentity
from agentmesh.transport.information_flow import (
    DEFAULT_RECEIPT_TTL,
    InformationFlowNonceCache,
    RECEIPT_FRAME_KEY,
    attach_information_flow_receipt,
    create_information_flow_receipt,
    extract_information_flow_receipt,
    verify_information_flow_receipt,
)


class _Envelope(BaseModel):
    envelope_id: str = "env-123"
    workflow_id: str = "workflow-abc"
    aggregate_sensitivity: str = "confidential"
    integrity: str = "untrusted"
    version: int = 3


def _identity(name: str) -> AgentIdentity:
    return AgentIdentity.create(
        name=name,
        sponsor=f"{name}@example.com",
        capabilities=["delegate"],
    )


def _envelope(
    *,
    sensitivity: str = "confidential",
    integrity: str = "untrusted",
    version: int = 3,
) -> _Envelope:
    return _Envelope(
        aggregate_sensitivity=sensitivity,
        integrity=integrity,
        version=version,
    )


def test_signed_receipt_verifies_and_can_be_attached_to_message() -> None:
    sender = _identity("sender")
    receiver = _identity("receiver")
    payload = {"text": "summarize private customer ticket"}
    receipt = create_information_flow_receipt(
        sender,
        recipient_did=str(receiver.did),
        subject_id="message-1",
        envelope=_envelope(),
        payload=payload,
        nonce="nonce-1",
    )

    message = attach_information_flow_receipt({"id": "message-1", "payload": payload}, receipt)
    extracted = extract_information_flow_receipt(message)

    assert RECEIPT_FRAME_KEY in message
    assert extracted is not None
    decision = verify_information_flow_receipt(
        extracted,
        sender,
        payload=payload,
        expected_recipient_did=str(receiver.did),
        expected_subject_id="message-1",
        nonce_cache=InformationFlowNonceCache(),
    )
    assert decision.allowed is True
    assert extracted.to_context_metadata()["aggregate_sensitivity"] == "confidential"
    assert extracted.to_context_metadata()["integrity"] == "untrusted"


def test_tampering_with_payload_is_rejected() -> None:
    sender = _identity("sender")
    receiver = _identity("receiver")
    payload = {"text": "original"}
    receipt = create_information_flow_receipt(
        sender,
        recipient_did=str(receiver.did),
        subject_id="message-1",
        envelope=_envelope(),
        payload=payload,
        nonce="nonce-1",
    )

    decision = verify_information_flow_receipt(
        receipt,
        sender,
        payload={"text": "tampered"},
        expected_recipient_did=str(receiver.did),
        expected_subject_id="message-1",
        nonce_cache=InformationFlowNonceCache(),
    )

    assert decision.allowed is False
    assert "payload hash" in decision.reason


def test_tampering_with_receipt_metadata_invalidates_signature() -> None:
    sender = _identity("sender")
    receiver = _identity("receiver")
    payload = {"text": "private"}
    receipt = create_information_flow_receipt(
        sender,
        recipient_did=str(receiver.did),
        subject_id="message-1",
        envelope=_envelope(),
        payload=payload,
        nonce="nonce-1",
    )
    downgraded = receipt.model_copy(update={"aggregate_sensitivity": "public"})

    decision = verify_information_flow_receipt(
        downgraded,
        sender,
        payload=payload,
        expected_recipient_did=str(receiver.did),
        expected_subject_id="message-1",
        nonce_cache=InformationFlowNonceCache(),
    )

    assert decision.allowed is False
    assert "signature" in decision.reason


def test_replay_nonce_is_rejected_and_recorded_after_success() -> None:
    sender = _identity("sender")
    receiver = _identity("receiver")
    payload = {"text": "private"}
    receipt = create_information_flow_receipt(
        sender,
        recipient_did=str(receiver.did),
        subject_id="message-1",
        envelope=_envelope(),
        payload=payload,
        nonce="nonce-1",
    )
    nonce_cache = InformationFlowNonceCache()

    first = verify_information_flow_receipt(
        receipt,
        sender,
        payload=payload,
        expected_recipient_did=str(receiver.did),
        expected_subject_id="message-1",
        nonce_cache=nonce_cache,
    )
    replay = verify_information_flow_receipt(
        receipt,
        sender,
        payload=payload,
        expected_recipient_did=str(receiver.did),
        expected_subject_id="message-1",
        nonce_cache=nonce_cache,
    )

    assert first.allowed is True
    assert replay.allowed is False
    assert "nonce" in replay.reason


def test_expired_receipt_is_rejected() -> None:
    sender = _identity("sender")
    receiver = _identity("receiver")
    payload = {"text": "private"}
    issued_at = datetime(2026, 1, 1, tzinfo=UTC)
    receipt = create_information_flow_receipt(
        sender,
        recipient_did=str(receiver.did),
        subject_id="message-1",
        envelope=_envelope(),
        payload=payload,
        nonce="nonce-1",
        issued_at=issued_at,
        expires_at=issued_at + timedelta(minutes=5),
    )

    decision = verify_information_flow_receipt(
        receipt,
        sender,
        payload=payload,
        now=issued_at + timedelta(minutes=6),
        expected_recipient_did=str(receiver.did),
        expected_subject_id="message-1",
        nonce_cache=InformationFlowNonceCache(),
    )

    assert decision.allowed is False
    assert "expired" in decision.reason


def test_future_issued_receipt_is_rejected() -> None:
    sender = _identity("sender")
    receiver = _identity("receiver")
    payload = {"text": "private"}
    now = datetime(2026, 1, 1, tzinfo=UTC)
    receipt = create_information_flow_receipt(
        sender,
        recipient_did=str(receiver.did),
        subject_id="message-1",
        envelope=_envelope(),
        payload=payload,
        nonce="nonce-1",
        issued_at=now + timedelta(minutes=2),
        expires_at=now + timedelta(minutes=7),
    )

    decision = verify_information_flow_receipt(
        receipt,
        sender,
        payload=payload,
        now=now,
        expected_recipient_did=str(receiver.did),
        expected_subject_id="message-1",
        nonce_cache=InformationFlowNonceCache(),
    )

    assert decision.allowed is False
    assert "future" in decision.reason


def test_over_ttl_receipt_is_rejected() -> None:
    sender = _identity("sender")
    receiver = _identity("receiver")
    payload = {"text": "private"}
    issued_at = datetime(2026, 1, 1, tzinfo=UTC)
    receipt = create_information_flow_receipt(
        sender,
        recipient_did=str(receiver.did),
        subject_id="message-1",
        envelope=_envelope(),
        payload=payload,
        nonce="nonce-1",
        issued_at=issued_at,
        expires_at=issued_at + DEFAULT_RECEIPT_TTL + timedelta(seconds=1),
    )

    decision = verify_information_flow_receipt(
        receipt,
        sender,
        payload=payload,
        now=issued_at + timedelta(minutes=1),
        expected_recipient_did=str(receiver.did),
        expected_subject_id="message-1",
        nonce_cache=InformationFlowNonceCache(),
    )

    assert decision.allowed is False
    assert "TTL" in decision.reason


def test_child_receipt_cannot_lower_sensitivity_or_restore_integrity() -> None:
    sender = _identity("sender")
    receiver = _identity("receiver")
    first_payload = {"text": "private untrusted input"}
    first = create_information_flow_receipt(
        sender,
        recipient_did=str(receiver.did),
        subject_id="message-1",
        envelope=_envelope(
            sensitivity="confidential",
            integrity="untrusted",
            version=1,
        ),
        payload=first_payload,
        nonce="nonce-1",
    )
    second_payload = {"text": "derived output"}
    lowered = create_information_flow_receipt(
        sender,
        recipient_did=str(receiver.did),
        subject_id="message-2",
        envelope=_envelope(
            sensitivity="public",
            integrity="trusted",
            version=2,
        ),
        payload=second_payload,
        nonce="nonce-2",
        parent_receipt=first,
    )

    decision = verify_information_flow_receipt(
        lowered,
        sender,
        payload=second_payload,
        previous_receipt=first,
        expected_recipient_did=str(receiver.did),
        expected_subject_id="message-2",
        nonce_cache=InformationFlowNonceCache(),
    )

    assert decision.allowed is False
    assert "sensitivity" in decision.reason


def test_child_receipt_cannot_restore_integrity() -> None:
    sender = _identity("sender")
    receiver = _identity("receiver")
    first_payload = {"text": "untrusted input"}
    first = create_information_flow_receipt(
        sender,
        recipient_did=str(receiver.did),
        subject_id="message-1",
        envelope=_envelope(sensitivity="confidential", integrity="untrusted", version=1),
        payload=first_payload,
        nonce="nonce-1",
    )
    second_payload = {"text": "derived output"}
    restored = create_information_flow_receipt(
        sender,
        recipient_did=str(receiver.did),
        subject_id="message-2",
        envelope=_envelope(sensitivity="confidential", integrity="trusted", version=2),
        payload=second_payload,
        nonce="nonce-2",
        parent_receipt=first,
    )

    decision = verify_information_flow_receipt(
        restored,
        sender,
        payload=second_payload,
        previous_receipt=first,
        expected_recipient_did=str(receiver.did),
        expected_subject_id="message-2",
        nonce_cache=InformationFlowNonceCache(),
    )

    assert decision.allowed is False
    assert "integrity" in decision.reason


def test_receipt_subject_mismatch_is_rejected() -> None:
    sender = _identity("sender")
    receiver = _identity("receiver")
    payload = {"text": "private"}
    receipt = create_information_flow_receipt(
        sender,
        recipient_did=str(receiver.did),
        subject_id="message-1",
        envelope=_envelope(),
        payload=payload,
        nonce="nonce-1",
    )

    decision = verify_information_flow_receipt(
        receipt,
        sender,
        payload=payload,
        expected_recipient_did=str(receiver.did),
        expected_subject_id="message-2",
        nonce_cache=InformationFlowNonceCache(),
    )

    assert decision.allowed is False
    assert "subject" in decision.reason


def test_receipt_verification_requires_recipient_subject_and_nonce_cache() -> None:
    sender = _identity("sender")
    receiver = _identity("receiver")
    payload = {"text": "private"}
    receipt = create_information_flow_receipt(
        sender,
        recipient_did=str(receiver.did),
        subject_id="message-1",
        envelope=_envelope(),
        payload=payload,
        nonce="nonce-1",
    )

    missing_recipient = verify_information_flow_receipt(
        receipt,
        sender,
        payload=payload,
        expected_subject_id="message-1",
        nonce_cache=InformationFlowNonceCache(),
    )
    missing_subject = verify_information_flow_receipt(
        receipt,
        sender,
        payload=payload,
        expected_recipient_did=str(receiver.did),
        nonce_cache=InformationFlowNonceCache(),
    )
    missing_cache = verify_information_flow_receipt(
        receipt,
        sender,
        payload=payload,
        expected_recipient_did=str(receiver.did),
        expected_subject_id="message-1",
    )

    assert missing_recipient.allowed is False
    assert "recipient binding" in missing_recipient.reason
    assert missing_subject.allowed is False
    assert "subject binding" in missing_subject.reason
    assert missing_cache.allowed is False
    assert "nonce cache" in missing_cache.reason


def test_child_receipt_must_preserve_workflow_id() -> None:
    sender = _identity("sender")
    receiver = _identity("receiver")
    first_payload = {"text": "private untrusted input"}
    first = create_information_flow_receipt(
        sender,
        recipient_did=str(receiver.did),
        subject_id="message-1",
        envelope=_envelope(version=1),
        payload=first_payload,
        nonce="nonce-1",
    )
    child_payload = {"text": "derived output"}
    wrong_workflow = create_information_flow_receipt(
        sender,
        recipient_did=str(receiver.did),
        subject_id="message-2",
        envelope=_Envelope(workflow_id="workflow-other", version=2),
        payload=child_payload,
        nonce="nonce-2",
        parent_receipt=first,
    )

    decision = verify_information_flow_receipt(
        wrong_workflow,
        sender,
        payload=child_payload,
        previous_receipt=first,
        expected_recipient_did=str(receiver.did),
        expected_subject_id="message-2",
        nonce_cache=InformationFlowNonceCache(),
    )

    assert decision.allowed is False
    assert "workflow" in decision.reason


def test_receipt_default_expiration_is_bounded() -> None:
    sender = _identity("sender")
    receiver = _identity("receiver")
    issued_at = datetime(2026, 1, 1, tzinfo=UTC)
    receipt = create_information_flow_receipt(
        sender,
        recipient_did=str(receiver.did),
        subject_id="message-1",
        envelope=_envelope(),
        payload={"text": "private"},
        nonce="nonce-1",
        issued_at=issued_at,
    )

    assert receipt.expires_at == issued_at + DEFAULT_RECEIPT_TTL
