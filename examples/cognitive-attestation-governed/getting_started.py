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
) -> dict[str, Any]:
    """Build the unsigned envelope (canonical form, ready to sign)."""
    action_bytes = canonicalize_jcs(action)
    action_ref = "sha256:" + hashlib.sha256(action_bytes).hexdigest()

    # Canonical sort: (feature_id, activation_statistic) as spec requires
    sorted_features = sorted(
        features,
        key=lambda f: (f.feature_id, f.activation_statistic),
    )

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


def verify_envelope(signed: dict[str, Any]) -> bool:
    import base64
    from cryptography.exceptions import InvalidSignature

    to_verify = {k: v for k, v in signed.items() if k not in {"signature_b64"}}
    canonical = canonicalize_jcs(to_verify)
    sig = base64.b64decode(signed["signature_b64"])
    pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(signed["signer_pubkey_hex"]))
    try:
        pk.verify(sig, canonical)
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# Minimal AGT-style policy evaluator (stand-in so the example runs standalone)
# ---------------------------------------------------------------------------

def evaluate_policy(action: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    """Minimal policy check. In production, use agent-governance-toolkit."""
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

    # Step 7: offline verification
    ok = verify_envelope(signed)
    print(f"\nOffline verification: {'PASS' if ok else 'FAIL'}")

    # Step 8: tamper check
    tampered = json.loads(json.dumps(signed))
    tampered["feature_activations"][0]["activation_statistic"] = 0.99
    ok2 = verify_envelope(tampered)
    print(f"Tamper detection:     {'PASS (rejected)' if not ok2 else 'FAIL (accepted)'}")


if __name__ == "__main__":
    main()
