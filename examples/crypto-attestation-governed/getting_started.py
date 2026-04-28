#!/usr/bin/env python3
"""Cryptographic attestation example for governed tool calls.

This script demonstrates:
1) Ed25519-signed receipts for allowed governed actions
2) Hash-chained audit trail for tamper evidence
3) Embedded policy attestation per receipt
4) Offline verification of signatures and chain integrity
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


@dataclass
class PolicyAttestation:
    """Proof that policy evaluation occurred before action execution."""

    policy_id: str
    policy_version: str
    policy_sha256: str
    decision: str
    reason: str


@dataclass
class GovernedActionReceipt:
    """Signed receipt emitted for each allowed action."""

    receipt_id: str
    timestamp_utc: str
    agent_id: str
    action_name: str
    action_args: dict[str, Any]
    policy_attestation: PolicyAttestation
    previous_receipt_hash: str | None
    signer_public_key_b64: str
    signature_b64: str
    receipt_hash: str


def canonical_json(data: dict[str, Any]) -> bytes:
    """Encode a dict with deterministic key ordering for signing/hashing."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def sha256_hex(data: bytes) -> str:
    """Return SHA-256 hex digest."""
    return hashlib.sha256(data).hexdigest()


def policy_sha(policy_document: dict[str, Any]) -> str:
    """Hash the policy document deterministically."""
    return sha256_hex(canonical_json(policy_document))


def now_utc() -> str:
    """Return RFC3339-like UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def b64(data: bytes) -> str:
    """Base64 encode as text."""
    return base64.b64encode(data).decode("ascii")


def create_signed_receipt(
    *,
    signing_key: Ed25519PrivateKey,
    agent_id: str,
    action_name: str,
    action_args: dict[str, Any],
    attestation: PolicyAttestation,
    previous_hash: str | None,
) -> GovernedActionReceipt:
    """Create a receipt with Ed25519 signature and hash-chain linkage."""
    public_key = signing_key.public_key()
    public_key_bytes = public_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)

    payload: dict[str, Any] = {
        "receipt_id": str(uuid4()),
        "timestamp_utc": now_utc(),
        "agent_id": agent_id,
        "action_name": action_name,
        "action_args": action_args,
        "policy_attestation": asdict(attestation),
        "previous_receipt_hash": previous_hash,
        "signer_public_key_b64": b64(public_key_bytes),
    }

    message = canonical_json(payload)
    signature = signing_key.sign(message)
    signed_payload = {
        **payload,
        "signature_b64": b64(signature),
    }
    receipt_hash = sha256_hex(canonical_json(signed_payload))

    return GovernedActionReceipt(
        receipt_id=payload["receipt_id"],
        timestamp_utc=payload["timestamp_utc"],
        agent_id=agent_id,
        action_name=action_name,
        action_args=action_args,
        policy_attestation=attestation,
        previous_receipt_hash=previous_hash,
        signer_public_key_b64=payload["signer_public_key_b64"],
        signature_b64=signed_payload["signature_b64"],
        receipt_hash=receipt_hash,
    )


def verify_receipt(receipt: dict[str, Any]) -> tuple[bool, str]:
    """Verify signature, receipt hash, and core attestation fields."""
    return verify_receipt_with_constraints(receipt=receipt)


def verify_receipt_with_constraints(
    *,
    receipt: dict[str, Any],
    expected_policy_document: dict[str, Any] | None = None,
    trusted_signer_key_b64: str | None = None,
    max_age_seconds: int | None = 3600,
) -> tuple[bool, str]:
    """Verify a receipt with optional trust and replay constraints.

    Args:
        receipt: Parsed receipt dict
        expected_policy_document: If provided, re-hash and verify `policy_sha256`
        trusted_signer_key_b64: If provided, enforce signer key pinning
        max_age_seconds: If provided, reject stale timestamps older than this window
    """
    required = {
        "receipt_id",
        "timestamp_utc",
        "agent_id",
        "action_name",
        "action_args",
        "policy_attestation",
        "previous_receipt_hash",
        "signer_public_key_b64",
        "signature_b64",
        "receipt_hash",
    }
    missing = required - set(receipt.keys())
    if missing:
        return False, f"missing fields: {sorted(missing)}"

    payload = {k: receipt[k] for k in receipt.keys() if k not in {"signature_b64", "receipt_hash"}}
    signed_payload = {**payload, "signature_b64": receipt["signature_b64"]}

    expected_hash = sha256_hex(canonical_json(signed_payload))
    if expected_hash != receipt["receipt_hash"]:
        return False, "receipt_hash mismatch"

    if trusted_signer_key_b64 and receipt["signer_public_key_b64"] != trusted_signer_key_b64:
        return False, "untrusted signer key"

    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(receipt["signer_public_key_b64"]))
        sig = base64.b64decode(receipt["signature_b64"])
        pub.verify(sig, canonical_json(payload))
    except (ValueError, InvalidSignature) as exc:
        return False, f"signature verification failed: {exc.__class__.__name__}"

    attestation = receipt["policy_attestation"]
    if attestation.get("decision") != "allow":
        return False, "policy decision is not allow"

    required_attestation_fields = {"policy_id", "policy_version", "policy_sha256", "decision", "reason"}
    missing_attestation = required_attestation_fields - set(attestation.keys())
    if missing_attestation:
        return False, f"missing policy attestation fields: {sorted(missing_attestation)}"

    if expected_policy_document is not None:
        expected_policy_hash = policy_sha(expected_policy_document)
        if attestation.get("policy_sha256") != expected_policy_hash:
            return False, "policy_sha256 mismatch"

    if max_age_seconds is not None:
        try:
            ts = datetime.fromisoformat(receipt["timestamp_utc"])
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            if ts > now + timedelta(seconds=5):
                return False, "receipt timestamp is in the future"
            if now - ts > timedelta(seconds=max_age_seconds):
                return False, "receipt timestamp outside allowed age window"
        except ValueError:
            return False, "invalid timestamp format"

    return True, "ok"


def verify_chain(receipts: list[dict[str, Any]]) -> tuple[bool, str]:
    """Verify previous hash pointers across full receipt list."""
    previous_hash: str | None = None
    for idx, receipt in enumerate(receipts):
        if receipt.get("previous_receipt_hash") != previous_hash:
            return False, f"chain link mismatch at index {idx}"
        previous_hash = receipt.get("receipt_hash")
    return True, "ok"


def write_receipts(path: Path, receipts: list[dict[str, Any]]) -> None:
    """Write line-delimited JSON receipts."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for receipt in receipts:
            handle.write(json.dumps(receipt, ensure_ascii=True) + "\n")


def read_receipts(path: Path) -> list[dict[str, Any]]:
    """Read line-delimited JSON receipts."""
    receipts: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            receipts.append(json.loads(line))
    return receipts


def demo(output_file: Path, tamper: bool = False) -> int:
    """Run end-to-end receipt creation and offline verification demo."""
    policy_document = {
        "policy_id": "default-governance-policy",
        "version": "1.0.0",
        "rules": [
            {"name": "deny_shell_exec", "decision": "deny"},
            {"name": "allow_web_search", "decision": "allow"},
        ],
    }

    actions = [
        {"action_name": "web_search", "action_args": {"query": "agent governance best practices"}},
        {"action_name": "read_kb", "action_args": {"doc_id": "policy-101"}},
        {"action_name": "summarize", "action_args": {"source": "kb:policy-101"}},
    ]

    key = Ed25519PrivateKey.generate()
    trusted_signer_key_b64 = b64(
        key.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )
    receipts: list[dict[str, Any]] = []
    previous_hash: str | None = None

    for action in actions:
        attestation = PolicyAttestation(
            policy_id=policy_document["policy_id"],
            policy_version=policy_document["version"],
            policy_sha256=policy_sha(policy_document),
            decision="allow",
            reason=f"rule matched: allow_{action['action_name']}",
        )
        receipt = create_signed_receipt(
            signing_key=key,
            agent_id="did:agt:demo-agent",
            action_name=action["action_name"],
            action_args=action["action_args"],
            attestation=attestation,
            previous_hash=previous_hash,
        )
        receipt_dict = asdict(receipt)
        receipt_dict["policy_attestation"] = asdict(receipt.policy_attestation)
        receipts.append(receipt_dict)
        previous_hash = receipt.receipt_hash

    if tamper and receipts:
        # Simulate offline audit detection by mutating one recorded argument.
        receipts[1]["action_args"]["doc_id"] = "policy-999-tampered"

    write_receipts(output_file, receipts)
    print(f"Wrote {len(receipts)} receipts to {output_file}")

    loaded = read_receipts(output_file)
    for idx, receipt in enumerate(loaded):
        ok, message = verify_receipt_with_constraints(
            receipt=receipt,
            expected_policy_document=policy_document,
            trusted_signer_key_b64=trusted_signer_key_b64,
            max_age_seconds=3600,
        )
        print(f"receipt[{idx}] verification: {'PASS' if ok else 'FAIL'} ({message})")
        if not ok:
            return 1

    chain_ok, chain_message = verify_chain(loaded)
    print(f"chain verification: {'PASS' if chain_ok else 'FAIL'} ({chain_message})")
    return 0 if chain_ok else 1


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("receipts.jsonl"),
        help="Output JSONL file path (default: receipts.jsonl)",
    )
    parser.add_argument(
        "--tamper",
        action="store_true",
        help="Intentionally tamper with one receipt to demonstrate verification failure",
    )
    args = parser.parse_args()
    return demo(output_file=args.output, tamper=args.tamper)


if __name__ == "__main__":
    raise SystemExit(main())
