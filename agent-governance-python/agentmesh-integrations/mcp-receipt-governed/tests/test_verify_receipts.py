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

from mcp_receipt_governed.receipt import GovernanceReceipt, authorize_receipt, sign_receipt


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
