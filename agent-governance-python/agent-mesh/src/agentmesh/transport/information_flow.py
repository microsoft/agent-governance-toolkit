# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Signed information-flow receipts for AgentMesh messages.

The relay treats message payloads as opaque, so distributed IFC is carried as a
signed receipt attached to the native agent-to-agent message frame. Receivers
verify the receipt before folding the remote context into their local workflow.
"""

from __future__ import annotations

import hashlib
import json
from collections import OrderedDict
from datetime import UTC, datetime, timedelta
from threading import RLock
from typing import Any, Literal, Protocol, cast

from pydantic import BaseModel, Field, field_validator

from agentmesh.identity.agent_id import AgentIdentity


RECEIPT_FRAME_KEY = "information_flow_receipt"
RECEIPT_SCHEMA_VERSION = "agt.ifc.receipt.v1"
DEFAULT_RECEIPT_TTL = timedelta(minutes=5)


class InformationFlowEnvelopeLike(Protocol):
    """Minimal ContextEnvelope-compatible shape used to mint receipts."""

    envelope_id: str
    workflow_id: str
    aggregate_sensitivity: object
    integrity: str
    version: int


class InformationFlowReceiptVerification(BaseModel):
    """Result of verifying a distributed IFC receipt."""

    allowed: bool
    reason: str


class InformationFlowNonceCache:
    """Bounded, thread-safe replay cache for verified IFC receipt nonces."""

    def __init__(self, *, max_entries: int = 10000) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self._max_entries = max_entries
        self._nonces: OrderedDict[str, None] = OrderedDict()
        self._lock = RLock()

    def add_if_absent(self, nonce: str) -> bool:
        """Return false when *nonce* was already recorded."""

        with self._lock:
            if nonce in self._nonces:
                return False
            self._nonces[nonce] = None
            self._nonces.move_to_end(nonce)
            while len(self._nonces) > self._max_entries:
                self._nonces.popitem(last=False)
            return True


class InformationFlowReceipt(BaseModel):
    """Signed IFC evidence for one native AgentMesh message.

    The receipt commits to the coarse envelope reference, current aggregate
    sensitivity, integrity, recipient, message subject, message payload hash, and
    anti-replay nonce. It deliberately omits full labels and restrictions.
    """

    schema_version: Literal["agt.ifc.receipt.v1"] = RECEIPT_SCHEMA_VERSION
    issuer_did: str
    recipient_did: str
    subject_id: str
    envelope_id: str
    workflow_id: str = ""
    envelope_version: int = Field(default=0, ge=0)
    aggregate_sensitivity: str = "public"
    integrity: Literal["trusted", "untrusted"] = "trusted"
    message_hash: str
    nonce: str
    issued_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None
    parent_receipt_hash: str | None = None
    signature: str = ""

    @field_validator(
        "issuer_did",
        "recipient_did",
        "subject_id",
        "envelope_id",
        "message_hash",
        "nonce",
    )
    @classmethod
    def _must_not_be_empty(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("must not be empty")
        return value

    @field_validator("aggregate_sensitivity", mode="before")
    @classmethod
    def _normalize_sensitivity(cls, value: object) -> str:
        return _classification_name(value)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def _normalize_datetime(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def signing_bytes(self) -> bytes:
        """Return canonical bytes covered by the receipt signature."""

        payload = self.model_dump(mode="json", exclude={"signature"})
        return _canonical_json(payload).encode("utf-8")

    def receipt_hash(self) -> str:
        """Return the stable hash of the signed receipt."""

        return hashlib.sha256(
            _canonical_json(self.model_dump(mode="json")).encode("utf-8")
        ).hexdigest()

    def to_context_metadata(self) -> dict[str, object]:
        """Project verified receipt metadata into local IFC context fields."""

        return {
            "envelope_id": self.envelope_id,
            "workflow_id": self.workflow_id,
            "aggregate_sensitivity": self.aggregate_sensitivity,
            "integrity": self.integrity,
            "version": self.envelope_version,
        }


def message_hash(payload: dict[str, Any]) -> str:
    """Return a stable hash for a JSON-compatible AgentMesh message payload."""

    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def create_information_flow_receipt(
    issuer: AgentIdentity,
    *,
    recipient_did: str,
    subject_id: str,
    envelope: InformationFlowEnvelopeLike,
    payload: dict[str, Any],
    nonce: str,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    parent_receipt: InformationFlowReceipt | None = None,
) -> InformationFlowReceipt:
    """Create and sign an IFC receipt for a native AgentMesh message."""

    issued = issued_at or datetime.now(UTC)
    receipt = InformationFlowReceipt(
        issuer_did=str(issuer.did),
        recipient_did=recipient_did,
        subject_id=subject_id,
        envelope_id=envelope.envelope_id,
        workflow_id=envelope.workflow_id,
        envelope_version=envelope.version,
        aggregate_sensitivity=envelope.aggregate_sensitivity,
        integrity=_integrity(envelope.integrity),
        message_hash=message_hash(payload),
        nonce=nonce,
        issued_at=issued,
        expires_at=expires_at or issued + DEFAULT_RECEIPT_TTL,
        parent_receipt_hash=parent_receipt.receipt_hash() if parent_receipt else None,
    )
    signature = issuer.sign(receipt.signing_bytes())
    return receipt.model_copy(update={"signature": signature})


def attach_information_flow_receipt(
    message: dict[str, Any],
    receipt: InformationFlowReceipt,
) -> dict[str, Any]:
    """Return a copy of *message* with its signed IFC receipt attached."""

    frame = dict(message)
    frame[RECEIPT_FRAME_KEY] = receipt.model_dump(mode="json")
    return frame


def extract_information_flow_receipt(
    message: dict[str, Any],
) -> InformationFlowReceipt | None:
    """Extract an IFC receipt from a native AgentMesh message frame."""

    payload = message.get(RECEIPT_FRAME_KEY)
    if payload is None:
        return None
    if isinstance(payload, InformationFlowReceipt):
        return payload
    if isinstance(payload, dict):
        return InformationFlowReceipt(**payload)
    raise ValueError("information_flow_receipt must be an object")


def verify_information_flow_receipt(
    receipt: InformationFlowReceipt,
    issuer: AgentIdentity,
    *,
    payload: dict[str, Any],
    expected_recipient_did: str | None = None,
    expected_subject_id: str | None = None,
    previous_receipt: InformationFlowReceipt | None = None,
    nonce_cache: InformationFlowNonceCache | None = None,
    now: datetime | None = None,
    max_ttl: timedelta = DEFAULT_RECEIPT_TTL,
    allowed_clock_skew: timedelta = timedelta(seconds=30),
) -> InformationFlowReceiptVerification:
    """Verify a signed IFC receipt and reject replay, tampering, and downgrade.

    ``previous_receipt`` is expected to be the receiver's already-verified
    parent receipt for the same envelope lineage.
    """

    if receipt.issuer_did != str(issuer.did):
        return InformationFlowReceiptVerification(
            allowed=False,
            reason="Receipt issuer does not match the signing identity",
        )
    if not issuer.verify_signature(receipt.signing_bytes(), receipt.signature):
        return InformationFlowReceiptVerification(
            allowed=False,
            reason="Receipt signature is invalid",
        )
    if expected_recipient_did is None:
        return InformationFlowReceiptVerification(
            allowed=False,
            reason="Receipt verification requires expected recipient binding",
        )
    if receipt.recipient_did != expected_recipient_did:
        return InformationFlowReceiptVerification(
            allowed=False,
            reason="Receipt recipient does not match the expected receiver",
        )
    if expected_subject_id is None:
        return InformationFlowReceiptVerification(
            allowed=False,
            reason="Receipt verification requires expected subject binding",
        )
    if receipt.subject_id != expected_subject_id:
        return InformationFlowReceiptVerification(
            allowed=False,
            reason="Receipt subject does not match the expected message",
        )
    if receipt.expires_at is None:
        return InformationFlowReceiptVerification(
            allowed=False,
            reason="Receipt verification requires an expiration time",
        )

    current_time = (now or datetime.now(UTC)).astimezone(UTC)
    if receipt.issued_at > current_time + allowed_clock_skew:
        return InformationFlowReceiptVerification(
            allowed=False,
            reason="Receipt issue time is in the future",
        )
    if receipt.expires_at <= current_time:
        return InformationFlowReceiptVerification(
            allowed=False,
            reason="Receipt is expired",
        )
    if receipt.expires_at - receipt.issued_at > max_ttl:
        return InformationFlowReceiptVerification(
            allowed=False,
            reason="Receipt TTL exceeds the allowed maximum",
        )
    if nonce_cache is None:
        return InformationFlowReceiptVerification(
            allowed=False,
            reason="Receipt verification requires a replay nonce cache",
        )

    if receipt.message_hash != message_hash(payload):
        return InformationFlowReceiptVerification(
            allowed=False,
            reason="Receipt payload hash does not match the message payload",
        )

    downgrade_decision = _verify_monotonic(receipt, previous_receipt)
    if not downgrade_decision.allowed:
        return downgrade_decision

    if not nonce_cache.add_if_absent(receipt.nonce):
        return InformationFlowReceiptVerification(
            allowed=False,
            reason="Receipt nonce was already seen",
        )

    return InformationFlowReceiptVerification(
        allowed=True,
        reason="Receipt verified",
    )


def _verify_monotonic(
    receipt: InformationFlowReceipt,
    previous_receipt: InformationFlowReceipt | None,
) -> InformationFlowReceiptVerification:
    if previous_receipt is None:
        return InformationFlowReceiptVerification(allowed=True, reason="No prior receipt")

    if receipt.parent_receipt_hash != previous_receipt.receipt_hash():
        return InformationFlowReceiptVerification(
            allowed=False,
            reason="Receipt does not extend the expected parent receipt",
        )
    if receipt.envelope_id != previous_receipt.envelope_id:
        return InformationFlowReceiptVerification(
            allowed=False,
            reason="Receipt envelope does not match the parent receipt",
        )
    if receipt.workflow_id != previous_receipt.workflow_id:
        return InformationFlowReceiptVerification(
            allowed=False,
            reason="Receipt workflow does not match the parent receipt",
        )
    if receipt.envelope_version < previous_receipt.envelope_version:
        return InformationFlowReceiptVerification(
            allowed=False,
            reason="Receipt envelope version regressed",
        )
    if _classification_rank(receipt.aggregate_sensitivity) < _classification_rank(
        previous_receipt.aggregate_sensitivity
    ):
        return InformationFlowReceiptVerification(
            allowed=False,
            reason="Receipt lowered aggregate sensitivity",
        )
    if previous_receipt.integrity == "untrusted" and receipt.integrity != "untrusted":
        return InformationFlowReceiptVerification(
            allowed=False,
            reason="Receipt restored untrusted integrity",
        )

    return InformationFlowReceiptVerification(allowed=True, reason="Receipt is monotonic")


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _classification_rank(value: object) -> int:
    ranks = {
        "public": 0,
        "internal": 1,
        "confidential": 2,
        "restricted": 3,
        "top_secret": 4,
    }
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ranks:
            return ranks[normalized]
    if isinstance(value, int):
        if value in ranks.values():
            return value
    name = getattr(value, "name", None)
    if isinstance(name, str):
        normalized_name = name.strip().lower()
        if normalized_name in ranks:
            return ranks[normalized_name]
    enum_value = getattr(value, "value", None)
    if isinstance(enum_value, int) and enum_value in ranks.values():
        return enum_value
    raise ValueError(f"Unknown data classification: {value!r}")


def _classification_name(value: object) -> str:
    names = ["public", "internal", "confidential", "restricted", "top_secret"]
    return names[_classification_rank(value)]


def _integrity(value: object) -> Literal["trusted", "untrusted"]:
    normalized = str(value).strip().lower()
    if normalized not in {"trusted", "untrusted"}:
        raise ValueError(f"Unknown IFC integrity label: {value!r}")
    return cast(Literal["trusted", "untrusted"], normalized)


__all__ = [
    "DEFAULT_RECEIPT_TTL",
    "RECEIPT_FRAME_KEY",
    "RECEIPT_SCHEMA_VERSION",
    "InformationFlowEnvelopeLike",
    "InformationFlowNonceCache",
    "InformationFlowReceipt",
    "InformationFlowReceiptVerification",
    "attach_information_flow_receipt",
    "create_information_flow_receipt",
    "extract_information_flow_receipt",
    "message_hash",
    "verify_information_flow_receipt",
]
