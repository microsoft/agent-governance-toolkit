"""AGT + Cognitive Attestation: policy enforcement plus signed interpretability.

AGT decides whether an action is allowed. Cognitive Attestation signs the
interpretable decomposition of model state behind the decision, so an auditor
can verify what the reasoning substrate looked like when the action fired,
not just whether the policy rule matched.

Paper: Cognitive Attestation (Zenodo DOI 10.5281/zenodo.19646276)
Reference implementation: github.com/aeoess/agent-passport-system
Community-contributed, experimental, Apache 2.0.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

# ---------------------------------------------------------------------------
# RFC 8785 JCS canonicalization (minimal subset sufficient for this envelope)
# ---------------------------------------------------------------------------
# NOTE: This is a MINIMAL JCS implementation that covers the field types used
# in this example envelope. It does not implement the full RFC 8785 edge
# cases (Unicode normalization, certain IEEE 754 special values, etc.).
# Production code should use a fully-tested JCS library such as `jcs` on PyPI
# or the reference implementation at github.com/cyberphone/json-canonicalization.
# The APS SDK at github.com/aeoess/agent-passport-system ships a spec-conformant
# implementation used for all real signatures.
# ---------------------------------------------------------------------------

def canonicalize_jcs(value: Any) -> bytes:
    """RFC 8785 JSON Canonicalization Scheme (minimal)."""
    return _encode(value).encode("utf-8")


def _encode(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        if isinstance(value, float) and value == int(value):
            return str(int(value))
        return json.dumps(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(_encode(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value.keys())
        return "{" + ",".join(
            f"{json.dumps(k, ensure_ascii=False)}:{_encode(value[k])}" for k in keys
        ) + "}"
    raise TypeError(f"Not JSON-serializable: {type(value).__name__}")


# ---------------------------------------------------------------------------
# Envelope types
# ---------------------------------------------------------------------------

@dataclass
class FeatureActivation:
    feature_id: str
    activation_statistic: float
    label: str = ""


@dataclass
class CognitiveAttestation:
    spec_version: str = "1.0"
    action_ref: str = ""
    dictionary_ref: str = ""
    feature_activations: list[FeatureActivation] = field(default_factory=list)
    canonical_hash: str = ""
    signer_role: str = "agent"
    signer_pubkey_hex: str = ""
    signature_b64: str = ""


def build_envelope(
    action: dict[str, Any],
    features: list[FeatureActivation],
    dictionary_ref: str,
    signer_role: str = "agent",
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Build the unsigned envelope (canonical form, ready to sign).

    The `timestamp` field is included in the canonical form and therefore
    in the signature. This prevents replay of a valid envelope into a
    different point in time: any attempt to reuse a previously-signed
    envelope will still carry the original timestamp, which a verifier
    can reject against freshness policy.
    """
    action_bytes = canonicalize_jcs(action)
    action_ref = "sha256:" + hashlib.sha256(action_bytes).hexdigest()

    # Canonical sort: (feature_id, activation_statistic). This order is
    # required by the Cognitive Attestation spec (Zenodo 10.5281/zenodo.19646276,
    # Section 3.2) so that two independently-produced envelopes over the
    # same feature set produce identical canonical bytes.
    sorted_features = sorted(
        features,
        key=lambda f: (f.feature_id, f.activation_statistic),
    )

    if timestamp is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    envelope = {
        "spec_version": "1.0",
        "action_ref": action_ref,
        "dictionary_ref": dictionary_ref,
        "feature_activations": [
            {
                "feature_id": f.feature_id,
                "activation_statistic": f.activation_statistic,
                "label": f.label,
            }
            for f in sorted_features
        ],
        "signer_role": signer_role,
        "timestamp": timestamp,
    }
    canonical = canonicalize_jcs(envelope)
    envelope["canonical_hash"] = "sha256:" + hashlib.sha256(canonical).hexdigest()
    return envelope


def sign_envelope(unsigned: dict[str, Any], sk: Ed25519PrivateKey) -> dict[str, Any]:
    """Attach signer pubkey, then sign the canonical form (excluding signature)."""
    import base64
    pk = sk.public_key()
    pk_hex = pk.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    # Build the exact dict that the verifier will canonicalize
    to_sign = dict(unsigned)
    to_sign["signer_pubkey_hex"] = pk_hex
    # canonicalize over everything except the signature itself
    canonical = canonicalize_jcs(to_sign)
    sig = sk.sign(canonical)

    signed = dict(to_sign)
    signed["signature_b64"] = base64.b64encode(sig).decode("ascii")
    return signed


def verify_envelope(
    signed: dict[str, Any],
    max_age_seconds: int | None = 300,
    now: datetime | None = None,
) -> tuple[bool, str]:
    """Verify signature AND (optionally) freshness.

    Returns (ok, reason). On success, reason is "ok". On failure, reason is
    one of: "signature_invalid", "envelope_expired", "envelope_not_yet_valid",
    "timestamp_malformed", "missing_signature", "missing_pubkey".

    Set max_age_seconds=None to disable freshness checking (signature-only
    verification, not recommended for live traffic).
    """
    import base64
    from cryptography.exceptions import InvalidSignature

    # Signature check
    if "signature_b64" not in signed:
        return False, "missing_signature"
    if "signer_pubkey_hex" not in signed:
        return False, "missing_pubkey"
    to_verify = {k: v for k, v in signed.items() if k not in {"signature_b64"}}
    canonical = canonicalize_jcs(to_verify)
    try:
        sig = base64.b64decode(signed["signature_b64"])
        pk = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(signed["signer_pubkey_hex"])
        )
        pk.verify(sig, canonical)
    except InvalidSignature:
        return False, "signature_invalid"
    except Exception:
        return False, "signature_invalid"

    # Freshness check (replay defence). An envelope older than max_age_seconds
    # is rejected even with a valid signature, because the signed timestamp
    # lets the verifier distinguish a new legitimate envelope from a replay
    # of an old one.
    if max_age_seconds is not None:
        ts_str = signed.get("timestamp")
        if not ts_str:
            return False, "timestamp_malformed"
        try:
            # Accept "...Z" and "...+00:00" forms
            ts_str_norm = ts_str.replace("Z", "+00:00")
            ts = datetime.fromisoformat(ts_str_norm)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return False, "timestamp_malformed"
        current = now or datetime.now(timezone.utc)
        age = (current - ts).total_seconds()
        if age > max_age_seconds:
            return False, "envelope_expired"
        if age < -max_age_seconds:
            return False, "envelope_not_yet_valid"

    return True, "ok"


# ---------------------------------------------------------------------------
# Minimal AGT-style policy evaluator (stand-in so the example runs standalone)
# ---------------------------------------------------------------------------

def evaluate_policy(action: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    """Minimal policy check for demonstration purposes ONLY.

    This is NOT a substitute for the AGT policy engine. It intentionally
    implements only exact-match tool name rules so this example is fully
    self-contained and does not pull AGT as a heavy dependency. Real
    deployments MUST replace this with `agent-governance-toolkit`'s
    policy engine, which supports regex matches, nested conditions,
    temporal rules, obligations, and the full AGT rule schema.
    """
    tool = action.get("tool", "")
    for rule in policy.get("rules", []):
        match = rule.get("match", {}).get("tool", {})
        one_of = match.get("one_of", [])
        if tool in one_of:
            return {
                "decision": rule["action"],
                "rule_id": rule["id"],
                "reason": rule.get("reason", ""),
            }
    return {
        "decision": policy.get("default_action", "deny"),
        "rule_id": "default",
        "reason": "No matching rule.",
    }


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def main() -> None:
    # Step 1: agent has an Ed25519 key
    sk = Ed25519PrivateKey.generate()
    pk_hex = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    print(f"Agent pubkey: {pk_hex[:20]}...")

    # Step 2: policy (AGT-compatible shape)
    policy = {
        "version": 1,
        "name": "cogattest-demo-policy",
        "default_action": "deny",
        "rules": [
            {
                "id": "allow-read",
                "match": {"tool": {"one_of": ["web_search", "file_read"]}},
                "action": "allow",
            },
            {
                "id": "deny-destructive",
                "match": {"tool": {"one_of": ["file_delete", "drop_database"]}},
                "action": "deny",
                "reason": "Destructive operations blocked.",
            },
        ],
    }

    # Step 3: proposed action
    action = {
        "tool": "web_search",
        "params": {"query": "ed25519 signature properties"},
        "target": "mcp://search",
    }

    # Step 4: AGT-style policy decision
    decision = evaluate_policy(action, policy)
    print(f"\nAGT policy decision: {decision['decision']} "
          f"(rule={decision['rule_id']})")

    if decision["decision"] != "allow":
        print("Action blocked. No attestation produced.")
        return

    # Step 5: agent's reasoning substrate, decomposed into SAE features.
    # In production this comes from running a sparse autoencoder over
    # the model's residual stream. Here we use a fixed demo dictionary
    # and static features so the output is reproducible.
    features = [
        FeatureActivation("f_0412", 0.87, "search-intent"),
        FeatureActivation("f_1055", 0.54, "cryptography-topic"),
        FeatureActivation("f_0233", 0.33, "query-formulation"),
    ]
    dictionary_ref = (
        "sae://neuronpedia/gpt2-small/"
        "res-jb/12288/v1"
    )

    # Step 6: build + sign Cognitive Attestation envelope
    unsigned = build_envelope(
        action=action,
        features=features,
        dictionary_ref=dictionary_ref,
        signer_role="agent",
    )
    signed = sign_envelope(unsigned, sk)
    print(f"\nEnvelope action_ref:    {signed['action_ref']}")
    print(f"Envelope canonical_hash: {signed['canonical_hash']}")
    print(f"Signer pubkey:           {signed['signer_pubkey_hex'][:20]}...")
    print(f"Signature (b64):         {signed['signature_b64'][:40]}...")
    print(f"Features attested:       {len(signed['feature_activations'])}")

    # Step 7: offline verification (signature + freshness)
    ok, reason = verify_envelope(signed)
    print(f"\nOffline verification: {'PASS' if ok else f'FAIL ({reason})'}")

    # Step 8: tamper check
    tampered = json.loads(json.dumps(signed))
    tampered["feature_activations"][0]["activation_statistic"] = 0.99
    ok2, reason2 = verify_envelope(tampered)
    if not ok2:
        print(f"Tamper detection:     PASS (tampering detected, envelope rejected, reason={reason2})")
    else:
        print("Tamper detection:     FAIL (tampering not detected, envelope accepted)")

    # Step 9: freshness / replay defence
    import copy
    from datetime import timedelta
    stale = copy.deepcopy(signed)
    # Simulate verifying the same valid envelope 10 minutes later (>300s default)
    later = datetime.now(timezone.utc) + timedelta(minutes=10)
    ok3, reason3 = verify_envelope(stale, max_age_seconds=300, now=later)
    if not ok3 and reason3 == "envelope_expired":
        print(f"Replay defence:       PASS (stale envelope rejected, reason={reason3})")
    else:
        print(f"Replay defence:       FAIL (ok={ok3}, reason={reason3})")


if __name__ == "__main__":
    main()
