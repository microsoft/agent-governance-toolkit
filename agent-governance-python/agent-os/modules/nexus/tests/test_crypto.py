# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the Ed25519 crypto helpers."""

import os
import sys

_nexus_parent = os.path.join(os.path.dirname(__file__), "..", "..")
if _nexus_parent not in sys.path:
    sys.path.insert(0, _nexus_parent)

from nexus.crypto import generate_keypair, sign, verify


class TestVerify:
    """Tests for crypto.verify()."""

    def test_valid_signature(self):
        private_key, verification_key = generate_keypair()
        message = b"hello"
        signature = sign(private_key, message)
        assert verify(verification_key, message, signature) is True

    def test_wrong_key_returns_false(self):
        private_key, _ = generate_keypair()
        _, other_verification_key = generate_keypair()
        message = b"hello"
        signature = sign(private_key, message)
        assert verify(other_verification_key, message, signature) is False

    def test_tampered_message_returns_false(self):
        private_key, verification_key = generate_keypair()
        signature = sign(private_key, b"hello")
        assert verify(verification_key, b"goodbye", signature) is False

    def test_missing_prefix_returns_false(self):
        private_key, verification_key = generate_keypair()
        message = b"hello"
        signature = sign(private_key, message)
        raw_key = verification_key[len("ed25519:"):]
        assert verify(raw_key, message, signature) is False

    def test_wrong_prefix_returns_false(self):
        private_key, verification_key = generate_keypair()
        message = b"hello"
        signature = sign(private_key, message)
        raw_key = verification_key[len("ed25519:"):]
        assert verify(f"rsa:{raw_key}", message, signature) is False
