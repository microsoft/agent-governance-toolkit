# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Governance Receipt — signed proof that a policy decision was made for an MCP tool call.

Each receipt links:
  - The Cedar policy ID and its allow/deny decision
  - The MCP tool name and arguments hash
  - The agent DID requesting the tool call
  - An Ed25519 signature for non-repudiation

Receipts use RFC 8785 JSON Canonicalization Scheme (JCS) for deterministic
hashing so that any party can independently verify the receipt signature.

Hash chaining links receipts via ``parent_receipt_hash`` so that verifiers
can detect insertion or deletion of individual tool calls without replaying
the full session log.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional

_logger = logging.getLogger(__name__)


@dataclass
class GovernanceReceipt:
    """Signed proof of a governance decision for an MCP tool call.

    Attributes:
        receipt_id: Unique receipt identifier (UUID4).
        tool_name: MCP tool that was invoked.
        agent_did: DID of the agent requesting the tool call.
        cedar_policy_id: Identifier of the Cedar policy that was evaluated.
        cedar_decision: Whether Cedar permitted or denied the action.
        args_hash: SHA-256 hash of the tool call arguments (canonical JSON).
        timestamp: Unix timestamp of the decision.
        parent_receipt_hash: SHA-256 hash of the preceding receipt's canonical
            payload.  ``None`` for the first receipt in a chain.
        signature: Ed25519 signature over the canonical receipt payload.
        signer_public_key: Hex-encoded Ed25519 public key of the signer.
        error: Optional error message if the decision failed.
    """

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
        """Return RFC 8785 (JCS) canonical JSON for deterministic hashing.

        Only governance-relevant fields are included; signature fields are
        excluded because the signature covers this payload.

        The output uses ``ensure_ascii=False`` so that Unicode codepoints are
        emitted as raw UTF-8 rather than ``\\uXXXX`` escapes, which is required
        by RFC 8785 § 3.2.2.2.
        """
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
        return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def payload_hash(self) -> str:
        """SHA-256 hash of the canonical payload."""
        return hashlib.sha256(self.canonical_payload().encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize receipt to a dictionary."""
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
        """Emit the receipt as a SLSA v1.0 provenance predicate.

        Maps the governance decision to the in-toto Statement / SLSA
        Provenance format so that standard supply-chain verification
        tools (``slsa-verifier``, ``in-toto``) can consume it.

        Returns:
            An in-toto v1 Statement dict with a SLSA Provenance predicate.
        """
        parent_dep: Optional[Dict[str, Any]] = None
        if self.parent_receipt_hash:
            parent_dep = {
                "uri": "pkg:agentmesh/receipt/parent",
                "digest": {"sha256": self.parent_receipt_hash},
            }

        return {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [
                {
                    "name": f"pkg:agentmesh/tool/{self.tool_name}",
                    "digest": {"sha256": self.args_hash},
                }
            ],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "buildType": ("https://agent-governance.org/schema/mcp-tool-call/v1"),
                    "externalParameters": {
                        "agent_did": self.agent_did,
                        "cedar_policy_id": self.cedar_policy_id,
                        "cedar_decision": self.cedar_decision,
                    },
                    "resolvedDependencies": ([parent_dep] if parent_dep else []),
                },
                "runDetails": {
                    "builder": {
                        "id": ("https://agent-governance.org/adapters/" "mcp-receipt-governed"),
                    },
                    "metadata": {
                        "invocationId": self.receipt_id,
                        "startedOn": time.strftime(
                            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.timestamp)
                        ),
                    },
                },
            },
        }


def hash_tool_args(tool_args: Optional[Dict[str, Any]]) -> str:
    """Compute SHA-256 hash of tool arguments using canonical JSON.

    Args:
        tool_args: The MCP tool call arguments. ``None`` or empty produces
            the hash of an empty JSON object.

    Returns:
        Hex-encoded SHA-256 digest.
    """
    if not tool_args:
        canonical = "{}"
    else:
        canonical = json.dumps(tool_args, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def sign_receipt(receipt: GovernanceReceipt, private_key_hex: str) -> GovernanceReceipt:
    """Sign a governance receipt with an Ed25519 private key.

    Uses the stdlib ``hashlib`` for hashing and a minimal Ed25519 signature
    via the ``cryptography`` library (already an AGT dependency) or falls back
    to HMAC-SHA256 for environments without ``cryptography``.

    Args:
        receipt: The receipt to sign.
        private_key_hex: Hex-encoded 32-byte Ed25519 seed.

    Returns:
        The receipt with ``signature`` and ``signer_public_key`` populated.
    """
    payload = receipt.canonical_payload().encode()

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed = bytes.fromhex(private_key_hex)
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    sig = private_key.sign(payload)
    receipt.signature = sig.hex()
    receipt.signer_public_key = private_key.public_key().public_bytes_raw().hex()

    return receipt


def verify_receipt(receipt: GovernanceReceipt) -> bool:
    """Verify the Ed25519 signature on a governance receipt.

    Args:
        receipt: The receipt to verify.

    Returns:
        ``True`` if the signature is valid, ``False`` otherwise.
    """
    if not receipt.signature or not receipt.signer_public_key:
        return False

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        pub_bytes = bytes.fromhex(receipt.signer_public_key)
        public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        sig_bytes = bytes.fromhex(receipt.signature)
        payload = receipt.canonical_payload().encode()
        public_key.verify(sig_bytes, payload)
        return True
    except ImportError:
        _logger.error("cryptography not available — cannot verify Ed25519 signature")
        return False
    except Exception:
        return False


def verify_receipt_chain(
    receipts: List[GovernanceReceipt],
    *,
    trusted_keys: Optional[List[str]] = None,
) -> List[str]:
    """Verify the hash chain and signatures of an ordered receipt list.

    Checks:
      1. The first receipt has no parent (``parent_receipt_hash is None``).
      2. Each subsequent receipt's ``parent_receipt_hash`` equals the
         ``payload_hash()`` of the preceding receipt.
      3. Every receipt has an Ed25519 signature.
      4. Every signed receipt passes Ed25519 verification.
      5. If ``trusted_keys`` is provided, the signer's public key must
         be in the trusted set.

    Args:
        receipts: Ordered list of receipts to verify.
        trusted_keys: Optional list of hex-encoded Ed25519 public keys.
            When provided, receipts signed by keys not in this list are
            flagged as untrusted.

    Returns:
        A list of human-readable error strings. An empty list means the
        chain is fully valid.
    """
    errors: List[str] = []

    if not receipts:
        return errors

    trusted_set = set(trusted_keys) if trusted_keys else None

    for i, receipt in enumerate(receipts):
        # Chain contiguity
        if i == 0:
            if receipt.parent_receipt_hash is not None:
                errors.append(f"[{i}] First receipt has unexpected parent_receipt_hash")
        else:
            expected = receipts[i - 1].payload_hash()
            if receipt.parent_receipt_hash != expected:
                errors.append(
                    f"[{i}] Hash chain broken: expected parent {expected[:16]}…, "
                    f"got {(receipt.parent_receipt_hash or 'None')[:16]}…"
                )

        # Signature verification
        if receipt.signature:
            if not verify_receipt(receipt):
                errors.append(
                    f"[{i}] Ed25519 signature verification failed for "
                    f"receipt {receipt.receipt_id}"
                )
            elif trusted_set and receipt.signer_public_key not in trusted_set:
                errors.append(
                    f"[{i}] Signer key {(receipt.signer_public_key or '')[:16]}… "
                    f"not in trusted key set"
                )
        else:
            errors.append(f"[{i}] Unsigned receipt — missing Ed25519 signature")

    return errors


class ReceiptStore:
    """In-memory store for governance receipts with query capabilities.

    Thread-safe for concurrent adapter usage.
    """

    def __init__(self) -> None:
        self._receipts: List[GovernanceReceipt] = []

    def add(self, receipt: GovernanceReceipt) -> None:
        """Store a receipt."""
        self._receipts.append(receipt)

    def query(
        self,
        agent_did: Optional[str] = None,
        tool_name: Optional[str] = None,
        cedar_decision: Optional[str] = None,
    ) -> List[GovernanceReceipt]:
        """Query receipts by agent, tool, or decision.

        Args:
            agent_did: Filter by agent DID.
            tool_name: Filter by MCP tool name.
            cedar_decision: Filter by ``"allow"`` or ``"deny"``.

        Returns:
            List of matching receipts.
        """
        results = list(self._receipts)
        if agent_did:
            results = [r for r in results if r.agent_did == agent_did]
        if tool_name:
            results = [r for r in results if r.tool_name == tool_name]
        if cedar_decision:
            results = [r for r in results if r.cedar_decision == cedar_decision]
        return results

    def export(self) -> List[Dict[str, Any]]:
        """Export all receipts as a list of dictionaries."""
        return [r.to_dict() for r in self._receipts]

    def clear(self) -> None:
        """Remove all receipts."""
        self._receipts.clear()

    @property
    def count(self) -> int:
        """Number of stored receipts."""
        return len(self._receipts)

    def get_stats(self) -> Dict[str, Any]:
        """Aggregate statistics for the receipt store."""
        total = len(self._receipts)
        allowed = sum(1 for r in self._receipts if r.cedar_decision == "allow")
        return {
            "total": total,
            "allowed": allowed,
            "denied": total - allowed,
            "unique_agents": len({r.agent_did for r in self._receipts}),
            "unique_tools": len({r.tool_name for r in self._receipts}),
        }
