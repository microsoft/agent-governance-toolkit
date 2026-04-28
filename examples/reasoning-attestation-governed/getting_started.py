#!/usr/bin/env python3
"""Reasoning attestation example for governed actions.

This example demonstrates:
1) A signed envelope that captures sparse autoencoder (SAE) feature activations
2) JCS-canonical JSON serialization (RFC 8785 style constraints)
3) Binding between reasoning state, policy decision, and action reference
4) Offline verification of signature + binding integrity
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


@dataclass
class DictionaryReference:
    """Reference metadata for SAE dictionary reproducibility."""

    dictionary_id: str
    model_family: str
    dictionary_version: str
    source_uri: str
    source_sha256: str


@dataclass
class SAEFeatureActivation:
    """Sparse activation record for a single SAE feature."""

    feature_id: str
    activation: str
    token_span: str
    interpretation: str


@dataclass
class PolicyDecision:
    """Governance policy outcome tied to an action."""

    policy_id: str
    policy_version: str
    policy_sha256: str
    decision: str
    reason: str


def _normalize_for_jcs(obj: Any) -> Any:
    """Normalize supported JSON types for deterministic canonical encoding.

    This example intentionally limits values to JCS-friendly primitives:
    dict, list, str, int, bool, None (and Decimal-like numbers pre-rendered as strings).
    """
    if isinstance(obj, dict):
        return {str(k): _normalize_for_jcs(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_normalize_for_jcs(v) for v in obj]
    if isinstance(obj, (str, int, bool)) or obj is None:
        return obj
    raise TypeError(
        f"Unsupported type for JCS-canonical envelope: {type(obj).__name__}. "
        "Use strings for decimal-valued fields."
    )


def jcs_canonical_bytes(payload: dict[str, Any]) -> bytes:
    """Serialize as deterministic JSON compatible with RFC 8785-style ordering."""
    normalized = _normalize_for_jcs(payload)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Return SHA-256 hex digest."""
    return hashlib.sha256(data).hexdigest()


def b64_encode(data: bytes) -> str:
    """Base64 encode bytes to text."""
    return base64.b64encode(data).decode("ascii")


def build_action_reference(agent_id: str, action_name: str, action_args: dict[str, Any], ts: str) -> str:
    """Create stable action reference for policy/reasoning binding."""
    action_payload = {
        "agent_id": agent_id,
        "action_name": action_name,
        "action_args": action_args,
        "timestamp_utc": ts,
    }
    return sha256_hex(jcs_canonical_bytes(action_payload))


def sign_reasoning_envelope(
    *,
    signing_key: Ed25519PrivateKey,
    action_ref: str,
    policy: PolicyDecision,
    dictionary: DictionaryReference,
    features: list[SAEFeatureActivation],
    model_id: str,
) -> dict[str, Any]:
    """Build and sign a reasoning attestation envelope."""
    ts = datetime.now(timezone.utc).isoformat()
    pub_key_b64 = b64_encode(
        signing_key.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )

    envelope_payload = {
        "schema_version": "1.0.0",
        "attestation_type": "reasoning_state",
        "timestamp_utc": ts,
        "action_ref": action_ref,
        "model_id": model_id,
        "policy_decision": asdict(policy),
        "dictionary_reference": asdict(dictionary),
        "sae_activations": [asdict(f) for f in features],
        "signer_public_key_b64": pub_key_b64,
    }

    signature_b64 = b64_encode(signing_key.sign(jcs_canonical_bytes(envelope_payload)))
    signed_envelope = {
        **envelope_payload,
        "signature_b64": signature_b64,
    }
    signed_envelope["envelope_sha256"] = sha256_hex(jcs_canonical_bytes(signed_envelope))
    return signed_envelope


def verify_reasoning_envelope(
    envelope: dict[str, Any],
    *,
    expected_action_ref: str,
    expected_policy_sha256: str,
    trusted_signer_key_b64: str | None = None,
) -> tuple[bool, str]:
    """Verify signed reasoning envelope and governance bindings."""
    required = {
        "schema_version",
        "attestation_type",
        "timestamp_utc",
        "action_ref",
        "model_id",
        "policy_decision",
        "dictionary_reference",
        "sae_activations",
        "signer_public_key_b64",
        "signature_b64",
        "envelope_sha256",
    }
    missing = required - set(envelope.keys())
    if missing:
        return False, f"missing envelope fields: {sorted(missing)}"

    signed_fields = {k: envelope[k] for k in envelope if k != "envelope_sha256"}
    expected_hash = sha256_hex(jcs_canonical_bytes(signed_fields))
    if expected_hash != envelope["envelope_sha256"]:
        return False, "envelope_sha256 mismatch"

    if trusted_signer_key_b64 and envelope["signer_public_key_b64"] != trusted_signer_key_b64:
        return False, "untrusted signer key"

    if envelope["action_ref"] != expected_action_ref:
        return False, "action_ref binding mismatch"

    policy = envelope["policy_decision"]
    if policy.get("decision") != "allow":
        return False, "policy decision is not allow"
    if policy.get("policy_sha256") != expected_policy_sha256:
        return False, "policy_sha256 binding mismatch"

    try:
        public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(envelope["signer_public_key_b64"]))
        signature = base64.b64decode(envelope["signature_b64"])
        public_key.verify(signature, jcs_canonical_bytes({k: envelope[k] for k in envelope if k not in {"signature_b64", "envelope_sha256"}}))
    except (ValueError, InvalidSignature) as exc:
        return False, f"signature verification failed: {exc.__class__.__name__}"

    return True, "ok"


def demo(output_file: Path, tamper: bool = False) -> int:
    """Run end-to-end example and offline verification."""
    agent_id = "did:agt:research-agent"
    action_name = "summarize_compliance_report"
    action_args = {"report_id": "soc2-q2", "audience": "internal-audit"}
    action_ts = datetime.now(timezone.utc).isoformat()
    action_ref = build_action_reference(agent_id, action_name, action_args, action_ts)

    policy_document = {
        "policy_id": "reasoning-attestation-policy",
        "policy_version": "1.0.0",
        "rules": [
            {"name": "allow_summarize_internal_audit", "decision": "allow"},
            {"name": "deny_external_sharing", "decision": "deny"},
        ],
    }
    policy_hash = sha256_hex(jcs_canonical_bytes(policy_document))
    policy = PolicyDecision(
        policy_id=policy_document["policy_id"],
        policy_version=policy_document["policy_version"],
        policy_sha256=policy_hash,
        decision="allow",
        reason="rule matched: allow_summarize_internal_audit",
    )

    dictionary = DictionaryReference(
        dictionary_id="sae-gpt4o-compliance-v1",
        model_family="gpt-4o",
        dictionary_version="2026.04",
        source_uri="https://example.org/dictionaries/sae-gpt4o-compliance-v1.json",
        source_sha256="9f5dc8dcf9d6f9c0df0cc5a0a5d09f9fb00d903f779ef93957b017dc8ba7af10",
    )

    features = [
        SAEFeatureActivation(
            feature_id="f_1182",
            activation="0.91",
            token_span="SOC 2 controls",
            interpretation="compliance_framework_reference",
        ),
        SAEFeatureActivation(
            feature_id="f_405",
            activation="0.83",
            token_span="least privilege",
            interpretation="security_principle_binding",
        ),
        SAEFeatureActivation(
            feature_id="f_9021",
            activation="0.77",
            token_span="audit evidence",
            interpretation="attestation_traceability_signal",
        ),
    ]

    signing_key = Ed25519PrivateKey.generate()
    trusted_signer_key_b64 = b64_encode(
        signing_key.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    )

    envelope = sign_reasoning_envelope(
        signing_key=signing_key,
        action_ref=action_ref,
        policy=policy,
        dictionary=dictionary,
        features=features,
        model_id="gpt-4o-2026-04",
    )

    if tamper:
        envelope["sae_activations"][0]["activation"] = "0.12"

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(envelope, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote reasoning envelope to {output_file}")

    loaded = json.loads(output_file.read_text(encoding="utf-8"))
    ok, message = verify_reasoning_envelope(
        loaded,
        expected_action_ref=action_ref,
        expected_policy_sha256=policy_hash,
        trusted_signer_key_b64=trusted_signer_key_b64,
    )
    print(f"offline verification: {'PASS' if ok else 'FAIL'} ({message})")
    return 0 if ok else 1


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reasoning_attestation.json"),
        help="Output file path (default: reasoning_attestation.json)",
    )
    parser.add_argument(
        "--tamper",
        action="store_true",
        help="Mutate one activation after signing to demonstrate verification failure",
    )
    args = parser.parse_args()
    return demo(output_file=args.output, tamper=args.tamper)


if __name__ == "__main__":
    raise SystemExit(main())
