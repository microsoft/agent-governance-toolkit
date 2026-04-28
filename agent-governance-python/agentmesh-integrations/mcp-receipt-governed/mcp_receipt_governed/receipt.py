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
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional

_logger = logging.getLogger(__name__)


class ReceiptSigningError(Exception):
    """Raised when Ed25519 receipt signing fails."""


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


def sign_receipt(receipt: GovernanceReceipt, private_key_hex: str) -> GovernanceReceipt:
    """Sign a receipt with an Ed25519 private key (hex-encoded 32-byte seed)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    payload = receipt.canonical_payload().encode()
    receipt.signature = private_key.sign(payload).hex()
    receipt.signer_public_key = private_key.public_key().public_bytes_raw().hex()
    return receipt


def verify_receipt(receipt: GovernanceReceipt) -> bool:
    """Verify the Ed25519 signature on a receipt. Returns ``False`` if unsigned or invalid."""
    if not receipt.signature or not receipt.signer_public_key:
        return False
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(receipt.signer_public_key))
        public_key.verify(bytes.fromhex(receipt.signature), receipt.canonical_payload().encode())
        return True
    except ImportError as exc:
        raise ImportError("The 'cryptography' library is required for Ed25519 signature verification.") from exc
    except Exception:
        return False


def verify_receipt_chain(
    receipts: List[GovernanceReceipt],
    *,
    trusted_keys: Optional[List[str]] = None,
) -> List[str]:
    """Verify hash-chain integrity and Ed25519 signatures for an ordered receipt list.

    Returns a list of error strings; empty means the chain is fully valid.
    Checks: no-parent on first receipt, contiguous parent hashes, no duplicate
    receipt IDs, valid signatures, and (if ``trusted_keys`` given) trusted signers.
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
            if len(key) != 64 or not all(c in "0123456789abcdefABCDEF" for c in key):
                errors.append(f"[{i}] Malformed signer_public_key for receipt {r.receipt_id}")
            elif not verify_receipt(r):
                errors.append(f"[{i}] Ed25519 signature invalid for receipt {r.receipt_id}")
            elif trusted_set and key not in trusted_set:
                errors.append(f"[{i}] Untrusted signer {key[:16]}… — receipt rejected")
        else:
            errors.append(f"[{i}] Unsigned receipt — missing Ed25519 signature")

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
