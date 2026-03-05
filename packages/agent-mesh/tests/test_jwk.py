# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for JWK (JSON Web Key) export/import of AgentIdentity."""

import base64
import re

import pytest

from agentmesh.identity import AgentIdentity
from agentmesh.exceptions import IdentityError


@pytest.fixture
def identity() -> AgentIdentity:
    """Create a test agent identity."""
    return AgentIdentity.create(
        name="jwk-test-agent",
        sponsor="test@example.com",
        capabilities=["read", "write"],
        organization="test-org",
    )


class TestToJwk:
    """Tests for JWK export."""

    def test_public_jwk_has_correct_structure(self, identity: AgentIdentity) -> None:
        jwk = identity.to_jwk()
        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "Ed25519"
        assert "x" in jwk
        assert jwk["kid"] == str(identity.did)
        assert jwk["use"] == "sig"

    def test_public_jwk_does_not_contain_private_key(self, identity: AgentIdentity) -> None:
        jwk = identity.to_jwk()
        assert "d" not in jwk

    def test_public_jwk_default_excludes_private(self, identity: AgentIdentity) -> None:
        jwk = identity.to_jwk(include_private=False)
        assert "d" not in jwk

    def test_private_jwk_contains_d(self, identity: AgentIdentity) -> None:
        jwk = identity.to_jwk(include_private=True)
        assert "d" in jwk
        assert isinstance(jwk["d"], str)

    def test_base64url_encoding_no_padding(self, identity: AgentIdentity) -> None:
        jwk = identity.to_jwk(include_private=True)
        # base64url uses - and _ instead of + and /, and no = padding
        for key in ("x", "d"):
            value = jwk[key]
            assert "=" not in value, f"'{key}' contains padding"
            assert "+" not in value, f"'{key}' contains + (not base64url)"
            assert "/" not in value, f"'{key}' contains / (not base64url)"
            # Verify it's valid base64url by decoding
            padded = value + "=" * (4 - len(value) % 4) if len(value) % 4 else value
            base64.urlsafe_b64decode(padded)

    def test_private_export_without_private_key_raises(self) -> None:
        """Identity without private key cannot export private JWK."""
        identity = AgentIdentity.create(name="test", sponsor="t@t.com")
        # Remove private key
        identity._private_key = None
        with pytest.raises(IdentityError, match="Private key not available"):
            identity.to_jwk(include_private=True)


class TestFromJwk:
    """Tests for JWK import."""

    def test_import_creates_valid_identity(self, identity: AgentIdentity) -> None:
        jwk = identity.to_jwk()
        imported = AgentIdentity.from_jwk(jwk)
        assert imported.public_key == identity.public_key
        assert str(imported.did) == str(identity.did)

    def test_import_with_private_key(self, identity: AgentIdentity) -> None:
        jwk = identity.to_jwk(include_private=True)
        imported = AgentIdentity.from_jwk(jwk)
        assert imported._private_key is not None
        # Verify signing works
        sig = imported.sign(b"test data")
        assert imported.verify_signature(b"test data", sig)

    def test_roundtrip_sign_verify(self, identity: AgentIdentity) -> None:
        """Create → export → import → verify signature works."""
        data = b"important agent message"
        signature = identity.sign(data)

        # Export with private key and reimport
        jwk = identity.to_jwk(include_private=True)
        imported = AgentIdentity.from_jwk(jwk)

        # Imported identity can verify original signature
        assert imported.verify_signature(data, signature)

        # Imported identity can create new valid signatures
        new_sig = imported.sign(data)
        assert identity.verify_signature(data, new_sig)

    def test_roundtrip_public_only(self, identity: AgentIdentity) -> None:
        """Public-only import can verify but not sign."""
        data = b"test"
        signature = identity.sign(data)

        jwk = identity.to_jwk(include_private=False)
        imported = AgentIdentity.from_jwk(jwk)

        assert imported.verify_signature(data, signature)
        assert imported._private_key is None

    def test_invalid_kty_raises(self) -> None:
        with pytest.raises(IdentityError, match="Unsupported key type"):
            AgentIdentity.from_jwk({"kty": "RSA", "crv": "Ed25519", "x": "AAAA"})

    def test_invalid_crv_raises(self) -> None:
        with pytest.raises(IdentityError, match="Unsupported curve"):
            AgentIdentity.from_jwk({"kty": "OKP", "crv": "X25519", "x": "AAAA"})

    def test_missing_x_raises(self) -> None:
        with pytest.raises(IdentityError, match="missing required 'x'"):
            AgentIdentity.from_jwk({"kty": "OKP", "crv": "Ed25519"})

    def test_non_dict_raises(self) -> None:
        with pytest.raises(IdentityError, match="JWK must be a dict"):
            AgentIdentity.from_jwk("not a dict")  # type: ignore[arg-type]

    def test_invalid_x_value_raises(self) -> None:
        with pytest.raises(IdentityError):
            AgentIdentity.from_jwk({"kty": "OKP", "crv": "Ed25519", "x": "!!invalid!!"})


class TestJwkSet:
    """Tests for JWK Set export/import."""

    def test_to_jwks_structure(self, identity: AgentIdentity) -> None:
        jwks = identity.to_jwks()
        assert "keys" in jwks
        assert isinstance(jwks["keys"], list)
        assert len(jwks["keys"]) == 1
        assert jwks["keys"][0]["kty"] == "OKP"

    def test_jwks_roundtrip(self, identity: AgentIdentity) -> None:
        jwks = identity.to_jwks(include_private=True)
        imported = AgentIdentity.from_jwks(jwks)
        assert imported.public_key == identity.public_key
        assert imported._private_key is not None

    def test_from_jwks_with_kid_filter(self, identity: AgentIdentity) -> None:
        jwks = identity.to_jwks()
        kid = str(identity.did)
        imported = AgentIdentity.from_jwks(jwks, kid=kid)
        assert str(imported.did) == kid

    def test_from_jwks_wrong_kid_raises(self, identity: AgentIdentity) -> None:
        jwks = identity.to_jwks()
        with pytest.raises(IdentityError, match="No key found with kid"):
            AgentIdentity.from_jwks(jwks, kid="did:mesh:nonexistent")

    def test_from_jwks_invalid_structure_raises(self) -> None:
        with pytest.raises(IdentityError, match="missing 'keys' array"):
            AgentIdentity.from_jwks({"not_keys": []})

    def test_from_jwks_empty_keys_raises(self) -> None:
        with pytest.raises(IdentityError, match="contains no keys"):
            AgentIdentity.from_jwks({"keys": []})

    def test_jwks_public_only_default(self, identity: AgentIdentity) -> None:
        jwks = identity.to_jwks()
        assert "d" not in jwks["keys"][0]
