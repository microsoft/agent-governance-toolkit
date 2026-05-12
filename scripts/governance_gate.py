#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
GitHub Actions Governance Gate for Agent Deployments

Validates an agent's policy configuration, generates a signed Ed25519
deployment receipt, and writes an entry to the audit trail.  Exits non-zero
on any policy violation so GitHub Actions can block the deployment.

Usage (standalone):
    python scripts/governance_gate.py \
        --policy .agents/security.yaml \
        --manifest agents.yaml \
        --commit abc1234 \
        --deployer octocat

Usage (from a GitHub Actions workflow):
    - name: Governance Gate
      run: python scripts/governance_gate.py
      env:
        GOVERNANCE_POLICY: .agents/security.yaml
        GOVERNANCE_MANIFEST: agents.yaml
        GITHUB_SHA: ${{ github.sha }}
        GITHUB_ACTOR: ${{ github.actor }}

Exit codes:
    0  All checks passed, receipt generated.
    1  One or more policy checks failed.
    2  Bad arguments or missing required files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    import base64
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


# ---------------------------------------------------------------------------
# Required policy fields and their validation rules
# ---------------------------------------------------------------------------

_REQUIRED_CHECKS: list[tuple[str, str, Any]] = [
    # (field_path, display_name, expected_value_or_type)
    ("audit.enabled",       "audit_enabled",  True),
    ("pii_scanning.enabled","pii_scanning",   True),
    ("allowed_tools",       "allowed_tools",  list),
    ("max_tool_calls",      "max_tool_calls", int),
]


def _get_nested(data: dict, dotted_key: str) -> tuple[bool, Any]:
    """Traverse nested dict with a dotted key. Returns (found, value)."""
    keys = dotted_key.split(".")
    node: Any = data
    for k in keys:
        if not isinstance(node, dict) or k not in node:
            return False, None
        node = node[k]
    return True, node


def _validate_policy(policy_data: dict) -> list[str]:
    """Return a list of failure messages; empty list means all passed."""
    failures: list[str] = []
    for field_path, display, expected in _REQUIRED_CHECKS:
        found, value = _get_nested(policy_data, field_path)
        if not found:
            failures.append(f"{display}: MISSING (field '{field_path}' not found)")
            continue
        if expected is True and not value:
            failures.append(f"{display}: FAIL (expected true, got {value!r})")
        elif expected is list and not isinstance(value, list):
            failures.append(f"{display}: FAIL (expected a list, got {type(value).__name__})")
        elif expected is int and not isinstance(value, int):
            failures.append(f"{display}: FAIL (expected an integer, got {type(value).__name__})")
    return failures


# ---------------------------------------------------------------------------
# Receipt generation
# ---------------------------------------------------------------------------

def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _canonical_payload(receipt: dict) -> str:
    """RFC 8785-style canonical JSON (signature excluded)."""
    payload = {k: v for k, v in receipt.items() if k not in ("signature", "signer_public_key")}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _generate_receipt(
    commit: str,
    deployer: str,
    policy_hash: str,
    manifest_hash: str,
    decision: str,
    private_key_pem: str | None,
) -> dict:
    receipt: dict[str, Any] = {
        "receipt_id": f"rec_{uuid.uuid4().hex[:12]}",
        "action": "agent_deployment",
        "principal": deployer,
        "decision": decision,
        "commit_sha": commit,
        "policy_hash": f"sha256:{policy_hash}",
        "manifest_hash": f"sha256:{manifest_hash}",
        "nonce": uuid.uuid4().hex,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "signature": None,
        "signer_public_key": None,
    }

    if _HAS_CRYPTO and private_key_pem:
        try:
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            key = load_pem_private_key(private_key_pem.encode(), password=None)
            if isinstance(key, Ed25519PrivateKey):
                payload_bytes = _canonical_payload(receipt).encode()
                sig = key.sign(payload_bytes)
                pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                receipt["signature"] = base64.b64encode(sig).decode()
                receipt["signer_public_key"] = base64.b64encode(pub).decode()
        except Exception as exc:
            print(f"  WARNING: signing failed: {exc}", file=sys.stderr)
            receipt["signature_error"] = str(exc)

    return receipt


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------

def _write_audit_entry(receipt: dict, audit_path: Path) -> None:
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with audit_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(receipt) + "\n")


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _ok(msg: str) -> None:
    print(f"  {msg:<28s} PASS")


def _fail(msg: str) -> None:
    print(f"  {msg:<28s} FAIL", file=sys.stderr)


def _banner(title: str) -> None:
    print(f"\n{title}")
    print("-" * (len(title)))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run(
    policy_file: Path,
    manifest_file: Path,
    commit: str,
    deployer: str,
    audit_log: Path,
    private_key_pem: str | None,
    require_receipt: bool,
) -> int:
    print("=" * 52)
    print("  Governance Gate: agent-deployment-check")
    print("=" * 52)
    print(f"  Policy file:    {policy_file}")
    print(f"  Agent manifest: {manifest_file}")
    print(f"  Commit:         {commit[:12]}")
    print(f"  Deployer:       {deployer}")

    # --- Load files ---
    if not _HAS_YAML:
        print("\nERROR: PyYAML is required. Install with: pip install pyyaml", file=sys.stderr)
        return 2

    for path in (policy_file, manifest_file):
        if not path.exists():
            print(f"\nERROR: File not found: {path}", file=sys.stderr)
            return 2

    policy_raw = policy_file.read_text(encoding="utf-8")
    manifest_raw = manifest_file.read_text(encoding="utf-8")
    policy_data: dict = yaml.safe_load(policy_raw) or {}
    policy_hash = _sha256(policy_raw)
    manifest_hash = _sha256(manifest_raw)

    # --- Policy checks ---
    _banner("Checking policy configuration...")
    failures = _validate_policy(policy_data)

    all_display = [d for _, d, _ in _REQUIRED_CHECKS]
    failing_display = {f.split(":")[0].strip() for f in failures}
    for display in all_display:
        if display in failing_display:
            _fail(display)
        else:
            _ok(display)

    # --- Receipt ---
    decision = "allow" if not failures else "deny"
    _banner("Generating deployment receipt...")
    receipt = _generate_receipt(
        commit=commit,
        deployer=deployer,
        policy_hash=policy_hash,
        manifest_hash=manifest_hash,
        decision=decision,
        private_key_pem=private_key_pem,
    )
    signed = receipt.get("signature") is not None
    print(f"  Receipt ID:     {receipt['receipt_id']}")
    print(f"  Signed:         {'yes (Ed25519)' if signed else 'no (cryptography not available)'}")
    print(f"  Policy hash:    {receipt['policy_hash'][:20]}...")

    if require_receipt and not signed and _HAS_CRYPTO and not private_key_pem:
        failures.append("receipt: FAIL (require_receipt=true but no signing key provided)")

    # --- Audit trail ---
    _write_audit_entry(receipt, audit_log)

    # --- Result ---
    print()
    if failures:
        print("Governance gate: FAILED", file=sys.stderr)
        print("\nFailures:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print("Governance gate: PASSED")
    return 0


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--policy",   default=os.environ.get("GOVERNANCE_POLICY", ".agents/security.yaml"), type=Path)
    p.add_argument("--manifest", default=os.environ.get("GOVERNANCE_MANIFEST", "agents.yaml"),         type=Path)
    p.add_argument("--commit",   default=os.environ.get("GITHUB_SHA",    os.environ.get("COMMIT", "unknown")))
    p.add_argument("--deployer", default=os.environ.get("GITHUB_ACTOR",  os.environ.get("DEPLOYER", "unknown")))
    p.add_argument("--audit-log",     default=".governance/audit.jsonl",  type=Path)
    p.add_argument("--signing-key",   default=os.environ.get("GOVERNANCE_SIGNING_KEY"), help="Ed25519 private key PEM (or env GOVERNANCE_SIGNING_KEY)")
    p.add_argument("--require-receipt", action="store_true", default=os.environ.get("GOVERNANCE_REQUIRE_RECEIPT", "").lower() == "true")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    return run(
        policy_file=args.policy,
        manifest_file=args.manifest,
        commit=args.commit,
        deployer=args.deployer,
        audit_log=args.audit_log,
        private_key_pem=args.signing_key,
        require_receipt=args.require_receipt,
    )


if __name__ == "__main__":
    sys.exit(main())
