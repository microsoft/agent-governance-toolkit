# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Governance Receipt — signed proof that a policy decision was made for an MCP tool call.

Each receipt links the Cedar policy decision, MCP tool name/args hash, and agent DID,
and carries an Ed25519 signature for non-repudiation.  Receipts use RFC 8785 JCS for
deterministic hashing and are hash-chained via ``parent_receipt_hash`` so verifiers can
detect insertion or deletion of tool calls without replaying the full session log.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional

_logger = logging.getLogger(__name__)


class ReceiptSigningError(RuntimeError):
    """Raised when Ed25519 receipt signing fails."""


class ReceiptAuthorizationError(RuntimeError):
    """Raised when external receipt authorization fails validation."""


@dataclass
class GovernanceReceipt:
    """Signed proof of a governance decision for an MCP tool call."""

    receipt_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tool_name: str = ""
    agent_did: str = ""
    cedar_policy_id: str = ""
    cedar_decision: Literal["allow", "deny"] = "deny"
    args_hash: str = ""
    timestamp: float = field(default_factory=time.time)
    session_id: Optional[str] = None
    parent_receipt_hash: Optional[str] = None
    signature: Optional[str] = None
    signer_public_key: Optional[str] = None
    assurance_level: Literal["self_attested", "externally_authorized"] = "self_attested"
    authorizer_id: Optional[str] = None
    authorization_expires_at: Optional[float] = None
    authorization_nonce: Optional[str] = None
    authorization_signature: Optional[str] = None
    authorizer_public_key: Optional[str] = None
    error: Optional[str] = None

    def canonical_payload(self) -> str:
        """RFC 8785 JCS canonical JSON; signature fields excluded (they cover this payload)."""
        data: Dict[str, Any] = {
            "agent_did": self.agent_did,
            "args_hash": self.args_hash,
            "cedar_decision": self.cedar_decision,
            "cedar_policy_id": self.cedar_policy_id,
            "receipt_id": self.receipt_id,
            "timestamp": self.timestamp,
            "tool_name": self.tool_name,
        }
        if self.parent_receipt_hash is not None:
            data["parent_receipt_hash"] = self.parent_receipt_hash
        if self.session_id is not None:
            data["session_id"] = self.session_id
        # ensure_ascii=False: RFC 8785 §3.2.2.2 requires raw UTF-8, not \uXXXX escapes
        return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def canonical_authorization_payload(self) -> str:
        """Return the external-authorizer payload that binds this exact receipt."""
        if (
            self.authorizer_id is None
            or self.authorization_expires_at is None
            or self.authorization_nonce is None
        ):
            raise ReceiptAuthorizationError("External authorization metadata is incomplete.")

        data = {
            "authorizer_id": self.authorizer_id,
            "authorization_expires_at": self.authorization_expires_at,
            "authorization_nonce": self.authorization_nonce,
            "receipt_payload_hash": self.payload_hash(),
            "type": "https://agent-governance.org/receipts/external-authorization/v1",
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def payload_hash(self) -> str:
        return hashlib.sha256(self.canonical_payload().encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "tool_name": self.tool_name,
            "agent_did": self.agent_did,
            "cedar_policy_id": self.cedar_policy_id,
            "cedar_decision": self.cedar_decision,
            "args_hash": self.args_hash,
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "parent_receipt_hash": self.parent_receipt_hash,
            "payload_hash": self.payload_hash(),
            "signature": self.signature,
            "signer_public_key": self.signer_public_key,
            "assurance_level": self.assurance_level,
            "authorizer_id": self.authorizer_id,
            "authorization_expires_at": self.authorization_expires_at,
            "authorization_nonce": self.authorization_nonce,
            "authorization_signature": self.authorization_signature,
            "authorizer_public_key": self.authorizer_public_key,
            "error": self.error,
        }

    def to_slsa_provenance(self) -> Dict[str, Any]:
        """Emit as a SLSA v1.0 / in-toto Statement provenance predicate."""
        deps = (
            [{"uri": "pkg:agentmesh/receipt/parent", "digest": {"sha256": self.parent_receipt_hash}}]
            if self.parent_receipt_hash
            else []
        )
        return {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": f"pkg:agentmesh/tool/{self.tool_name}", "digest": {"sha256": self.args_hash}}],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://agent-governance.org/schema/mcp-tool-call/v1",
                    "externalParameters": {
                        "agent_did": self.agent_did,
                        "cedar_policy_id": self.cedar_policy_id,
                        "cedar_decision": self.cedar_decision,
                    },
                    "resolvedDependencies": deps,
                },
                "runDetails": {
                    "builder": {"id": "https://agent-governance.org/adapters/mcp-receipt-governed"},
                    "metadata": {
                        "invocationId": self.receipt_id,
                        "startedOn": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.timestamp)),
                    },
                },
            },
        }


def hash_tool_args(tool_args: Optional[Dict[str, Any]]) -> str:
    """SHA-256 of tool arguments as canonical JSON. ``None`` or empty → hash of ``{}``."""
    canonical = json.dumps(tool_args, sort_keys=True, separators=(",", ":")) if tool_args else "{}"
    return hashlib.sha256(canonical.encode()).hexdigest()


def sign_receipt(
    receipt: GovernanceReceipt,
    private_key_hex: str,
    *,
    payload: Optional[bytes] = None,
    signature_field: str = "signature",
    public_key_field: str = "signer_public_key",
) -> GovernanceReceipt:
    """Sign a receipt with an Ed25519 private key (hex-encoded 32-byte seed)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    signed_payload = receipt.canonical_payload().encode() if payload is None else payload
    setattr(receipt, signature_field, private_key.sign(signed_payload).hex())
    setattr(receipt, public_key_field, private_key.public_key().public_bytes_raw().hex())
    return receipt


def verify_receipt(
    receipt: GovernanceReceipt,
    *,
    payload: Optional[bytes] = None,
    signature: Optional[str] = None,
    signer_public_key: Optional[str] = None,
) -> bool:
    """Verify the Ed25519 signature on a receipt. Returns ``False`` if unsigned or invalid."""
    signature_value = receipt.signature if signature is None else signature
    public_key_value = receipt.signer_public_key if signer_public_key is None else signer_public_key
    if not signature_value or not public_key_value:
        return False
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_value))
        signed_payload = receipt.canonical_payload().encode() if payload is None else payload
        public_key.verify(bytes.fromhex(signature_value), signed_payload)
        return True
    except ImportError as exc:
        raise ImportError("The 'cryptography' library is required for Ed25519 signature verification.") from exc
    except Exception:
        return False


def authorize_receipt(
    receipt: GovernanceReceipt,
    private_key_hex: str,
    *,
    authorizer_id: str,
    expires_at: float,
    nonce: Optional[str] = None,
) -> GovernanceReceipt:
    """Attach an external pre-execution authorization to a signed receipt.

    The authorizer signature is over the receipt payload hash, authorizer identity
    expiration, and nonce. The authorizer key is identified by signature
    verification and must differ from the receipt signer key; independent custody
    of that key remains a deployment requirement.
    """
    if not verify_receipt(receipt):
        raise ReceiptAuthorizationError("External authorization requires a valid signed receipt.")
    if not authorizer_id:
        raise ReceiptAuthorizationError("External authorization requires a non-empty authorizer_id.")
    if (
        isinstance(expires_at, bool)
        or not isinstance(expires_at, (int, float))
        or not math.isfinite(expires_at)
        or expires_at <= time.time()
    ):
        raise ReceiptAuthorizationError(
            "External authorization expiration must be a finite timestamp in the future."
        )

    original_authorization = (
        receipt.assurance_level,
        receipt.authorizer_id,
        receipt.authorization_expires_at,
        receipt.authorization_nonce,
        receipt.authorization_signature,
        receipt.authorizer_public_key,
    )

    receipt.assurance_level = "externally_authorized"
    receipt.authorizer_id = authorizer_id
    receipt.authorization_expires_at = expires_at
    receipt.authorization_nonce = nonce or str(uuid.uuid4())
    try:
        sign_receipt(
            receipt,
            private_key_hex,
            payload=receipt.canonical_authorization_payload().encode(),
            signature_field="authorization_signature",
            public_key_field="authorizer_public_key",
        )
    except Exception:
        (
            receipt.assurance_level,
            receipt.authorizer_id,
            receipt.authorization_expires_at,
            receipt.authorization_nonce,
            receipt.authorization_signature,
            receipt.authorizer_public_key,
        ) = original_authorization
        raise
    if _normalize_public_key(receipt.authorizer_public_key) == _normalize_public_key(
        receipt.signer_public_key
    ):
        (
            receipt.assurance_level,
            receipt.authorizer_id,
            receipt.authorization_expires_at,
            receipt.authorization_nonce,
            receipt.authorization_signature,
            receipt.authorizer_public_key,
        ) = original_authorization
        raise ReceiptAuthorizationError("External authorizer key must differ from the receipt signer key.")

    return receipt


def _is_hex(value: object, expected_length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == expected_length
        and all(char in "0123456789abcdefABCDEF" for char in value)
    )


def _normalize_public_key(value: object) -> Optional[str]:
    """Return an Ed25519 public key in canonical hexadecimal form."""
    return value.lower() if _is_hex(value, 64) else None


def _has_authorization_metadata(receipt: GovernanceReceipt) -> bool:
    return any(
        value is not None
        for value in (
            receipt.authorizer_id,
            receipt.authorization_expires_at,
            receipt.authorization_nonce,
            receipt.authorization_signature,
            receipt.authorizer_public_key,
        )
    )


def verify_receipt_authorization(
    receipt: GovernanceReceipt,
    *,
    trusted_authorizer_keys: Optional[List[str]] = None,
    now: Optional[float] = None,
) -> List[str]:
    """Verify the external authorization metadata on a receipt.

    A valid signature alone is not sufficient: callers must provide the configured
    authorizer trust roots for an externally authorized receipt to be accepted.
    """
    if receipt.assurance_level != "externally_authorized":
        return ["Receipt is not marked externally_authorized."]

    required_fields = {
        "authorizer_id": receipt.authorizer_id,
        "authorization_expires_at": receipt.authorization_expires_at,
        "authorization_nonce": receipt.authorization_nonce,
        "authorization_signature": receipt.authorization_signature,
        "authorizer_public_key": receipt.authorizer_public_key,
    }
    missing = [name for name, value in required_fields.items() if value is None or value == ""]
    if missing:
        return [f"External authorization is missing {', '.join(missing)}."]

    errors: List[str] = []
    if not isinstance(receipt.authorizer_id, str):
        errors.append("External authorization has a malformed authorizer_id.")
    if not isinstance(receipt.authorization_nonce, str):
        errors.append("External authorization has a malformed authorization_nonce.")
    if (
        isinstance(receipt.authorization_expires_at, bool)
        or not isinstance(receipt.authorization_expires_at, (int, float))
        or not math.isfinite(receipt.authorization_expires_at)
    ):
        errors.append("External authorization has a malformed authorization_expires_at.")
    if not _is_hex(receipt.authorizer_public_key, 64):
        errors.append("External authorization has a malformed authorizer_public_key.")
    if not _is_hex(receipt.authorization_signature, 128):
        errors.append("External authorization has a malformed authorization_signature.")
    authorizer_public_key = _normalize_public_key(receipt.authorizer_public_key)
    signer_public_key = _normalize_public_key(receipt.signer_public_key)
    if authorizer_public_key is not None and authorizer_public_key == signer_public_key:
        errors.append("External authorizer key must differ from the receipt signer key.")
    if not verify_receipt(receipt):
        errors.append("External authorization requires a valid receipt signature.")
    verification_time = receipt.timestamp if now is None else now
    if isinstance(verification_time, bool) or not isinstance(verification_time, (int, float)):
        errors.append("External authorization has a malformed verification timestamp.")
    elif not math.isfinite(verification_time):
        errors.append("External authorization has a malformed verification timestamp.")
    if (
        isinstance(receipt.authorization_expires_at, (int, float))
        and not isinstance(receipt.authorization_expires_at, bool)
        and math.isfinite(receipt.authorization_expires_at)
        and isinstance(verification_time, (int, float))
        and not isinstance(verification_time, bool)
        and math.isfinite(verification_time)
        and receipt.authorization_expires_at <= verification_time
    ):
        errors.append("External authorization has expired.")

    if not trusted_authorizer_keys:
        errors.append("No trusted authorizer keys are configured.")
    else:
        trusted_keys = {
            normalized
            for key in trusted_authorizer_keys
            if (normalized := _normalize_public_key(key)) is not None
        }
        if authorizer_public_key is not None and authorizer_public_key not in trusted_keys:
            errors.append(
                f"Untrusted external authorizer {authorizer_public_key[:16]}... - receipt rejected."
            )

    if errors:
        return errors

    assert isinstance(receipt.authorizer_public_key, str)
    assert isinstance(receipt.authorization_signature, str)
    if not verify_receipt(
        receipt,
        payload=receipt.canonical_authorization_payload().encode(),
        signature=receipt.authorization_signature,
        signer_public_key=receipt.authorizer_public_key,
    ):
        return ["External authorization signature is invalid."]

    return []


def verify_receipt_chain(
    receipts: List[GovernanceReceipt],
    *,
    trusted_keys: Optional[List[str]] = None,
    trusted_authorizer_keys: Optional[List[str]] = None,
    require_external_authorization: bool = False,
    now: Optional[float] = None,
) -> List[str]:
    """Verify hash-chain integrity and Ed25519 signatures for an ordered receipt list.

    Returns a list of error strings; empty means the chain is fully valid.
    Checks: no-parent on first receipt, contiguous parent hashes, no duplicate
    receipt IDs, valid signatures, trusted receipt signers, and externally
    authorized receipts (when present or required).
    """
    if not receipts:
        return []

    errors: List[str] = []
    trusted_set = set(trusted_keys) if trusted_keys else None
    seen_ids: set = set()

    for i, r in enumerate(receipts):
        if r.receipt_id in seen_ids:
            errors.append(f"[{i}] Duplicate receipt_id {r.receipt_id} — possible replay attack")
        seen_ids.add(r.receipt_id)

        if i == 0:
            if r.parent_receipt_hash is not None:
                errors.append(f"[{i}] First receipt has unexpected parent_receipt_hash")
        else:
            expected = receipts[i - 1].payload_hash()
            if r.parent_receipt_hash != expected:
                errors.append(
                    f"[{i}] Hash chain broken: expected {expected[:16]}…, "
                    f"got {(r.parent_receipt_hash or 'None')[:16]}…"
                )

        if r.signature:
            key = r.signer_public_key or ""
            if not _is_hex(key, 64):
                errors.append(f"[{i}] Malformed signer_public_key for receipt {r.receipt_id}")
            elif not verify_receipt(r):
                errors.append(f"[{i}] Ed25519 signature invalid for receipt {r.receipt_id}")
            elif trusted_set and key not in trusted_set:
                errors.append(f"[{i}] Untrusted signer {key[:16]}… — receipt rejected")
        else:
            errors.append(f"[{i}] Unsigned receipt — missing Ed25519 signature")

        if r.assurance_level == "externally_authorized":
            authorization_errors = verify_receipt_authorization(
                r,
                trusted_authorizer_keys=trusted_authorizer_keys,
                now=now,
            )
            errors.extend(f"[{i}] {error}" for error in authorization_errors)
        elif r.assurance_level == "self_attested":
            if _has_authorization_metadata(r):
                errors.append(f"[{i}] Self-attested receipt contains external authorization metadata")
            if require_external_authorization:
                errors.append(f"[{i}] External authorization is required but receipt is self-attested")
        else:
            errors.append(f"[{i}] Unknown assurance level {r.assurance_level!r}")

    return errors


class ReceiptStore:
    """Thread-safe in-memory store for governance receipts."""

    def __init__(self) -> None:
        self._receipts: List[GovernanceReceipt] = []
        self._lock = threading.Lock()

    def add(self, receipt: GovernanceReceipt) -> None:
        with self._lock:
            if any(r.receipt_id == receipt.receipt_id for r in self._receipts):
                raise ValueError(f"Duplicate receipt_id {receipt.receipt_id!r} — possible replay attack")
            self._receipts.append(receipt)

    def query(
        self,
        agent_did: Optional[str] = None,
        tool_name: Optional[str] = None,
        cedar_decision: Optional[str] = None,
    ) -> List[GovernanceReceipt]:
        with self._lock:
            results = list(self._receipts)
        if agent_did:
            results = [r for r in results if r.agent_did == agent_did]
        if tool_name:
            results = [r for r in results if r.tool_name == tool_name]
        if cedar_decision:
            results = [r for r in results if r.cedar_decision == cedar_decision]
        return results

    def export(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [r.to_dict() for r in self._receipts]

    def clear(self) -> None:
        with self._lock:
            self._receipts.clear()

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._receipts)

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            total = len(self._receipts)
            allowed = sum(1 for r in self._receipts if r.cedar_decision == "allow")
            snapshot = list(self._receipts)
        return {
            "total": total,
            "allowed": allowed,
            "denied": total - allowed,
            "unique_agents": len({r.agent_did for r in snapshot}),
            "unique_tools": len({r.tool_name for r in snapshot}),
        }
