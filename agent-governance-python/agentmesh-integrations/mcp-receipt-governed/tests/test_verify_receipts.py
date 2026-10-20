# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""End-to-end tests for the offline receipt verifier."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from mcp_receipt_governed.receipt import (
    GovernanceReceipt,
    authorize_receipt,
    sign_receipt,
    verify_receipt_chain,
)


@pytest.fixture()
def ed25519_keys():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        signer = Ed25519PrivateKey.generate()
        authorizer = Ed25519PrivateKey.generate()
        return (
            signer.private_bytes_raw().hex(),
            authorizer.private_bytes_raw().hex(),
            authorizer.public_key().public_bytes_raw().hex(),
        )
    except ImportError as exc:
        raise pytest.skip.Exception("cryptography not installed") from exc


def test_verifier_accepts_trusted_external_authorization(tmp_path, ed25519_keys):
    signer_key, authorizer_key, authorizer_public_key = ed25519_keys
    receipt = GovernanceReceipt(receipt_id="receipt-1", timestamp=time.time())
    sign_receipt(receipt, signer_key)
    authorize_receipt(
        receipt,
        authorizer_key,
        authorizer_id="did:example:authorizer",
        expires_at=time.time() + 60,
    )
    receipt_file = tmp_path / "receipts.json"
    receipt_file.write_text(json.dumps([receipt.to_dict()]), encoding="utf-8")
    script = Path(__file__).parents[1] / "scripts" / "verify_receipts.py"
    source_root = str(script.parents[1])
    existing_pythonpath = os.environ.get("PYTHONPATH")
    environment = os.environ | {
        "PYTHONPATH": (
            f"{source_root}{os.pathsep}{existing_pythonpath}" if existing_pythonpath else source_root
        )
    }

    result = subprocess.run(
        [
            sys.executable,
            str(script),
            str(receipt_file),
            "--trusted-authorizer-key",
            authorizer_public_key,
            "--require-external-authorization",
        ],
        capture_output=True,
        check=False,
        env=environment,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "External authorization valid and trusted" in result.stdout


@pytest.mark.parametrize("json_output", [False, True], ids=["text", "json"])
@pytest.mark.parametrize("chain_kind", ["unsigned", "mixed", "signed", "tampered"])
def test_verifier_signature_results_match_library(
    tmp_path, ed25519_keys, json_output, chain_kind
):
    signer_key, _, _ = ed25519_keys
    receipts = []
    for index in range(3):
        receipt = GovernanceReceipt(
            receipt_id=f"receipt-{index}",
            tool_name="read",
            timestamp=float(index + 1),
            parent_receipt_hash=receipts[-1].payload_hash() if receipts else None,
        )
        if chain_kind != "unsigned" and not (chain_kind == "mixed" and index == 1):
            sign_receipt(receipt, signer_key)
        receipts.append(receipt)
    if chain_kind == "tampered":
        receipts[-1].tool_name = "tampered"

    receipt_file = tmp_path / "receipts.json"
    receipt_file.write_text(json.dumps([r.to_dict() for r in receipts]), encoding="utf-8")
    script = Path(__file__).parents[1] / "scripts" / "verify_receipts.py"
    environment = os.environ | {"PYTHONPATH": str(script.parents[1])}
    command = [sys.executable, str(script), str(receipt_file)]
    if json_output:
        command.append("--json")
    result = subprocess.run(
        command, capture_output=True, check=False, env=environment, text=True
    )

    expected_errors = 0 if chain_kind == "signed" else 3 if chain_kind == "unsigned" else 1
    assert len(verify_receipt_chain(receipts)) == expected_errors
    assert result.returncode == (1 if expected_errors else 0), result.stderr
    if json_output:
        # The existing CLI writes diagnostics before the final JSON document.
        report = json.loads(result.stdout[result.stdout.index("{"):])
        assert report["passed"] is (expected_errors == 0)
        assert report["exit_code"] == result.returncode
        assert report["total_receipts"] == 3
        assert sum(len(r["errors"]) for r in report["receipts"]) == expected_errors
        for index, entry in enumerate(report["receipts"]):
            failed = (
                chain_kind == "unsigned"
                or (chain_kind == "mixed" and index == 1)
                or (chain_kind == "tampered" and index == 2)
            )
            assert entry["passed"] is (not failed)
            if chain_kind in {"unsigned", "mixed"} and failed:
                assert entry["errors"] == ["Unsigned receipt - missing Ed25519 signature"]
    elif expected_errors:
        assert "Verification failed" in result.stdout
        assert "signatures are valid" not in result.stdout
        if chain_kind in {"unsigned", "mixed"}:
            assert result.stdout.count("[FAIL] Unsigned receipt") == expected_errors
    else:
        assert "Verification passed - chain is contiguous and signatures are valid" in result.stdout
