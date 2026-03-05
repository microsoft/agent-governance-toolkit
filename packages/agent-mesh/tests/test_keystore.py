# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for KeyStore implementations (SoftwareKeyStore and PKCS11KeyStore)."""

import pytest
from unittest.mock import MagicMock, patch, PropertyMock

from agentmesh.identity.keystore import KeyStore, SoftwareKeyStore, PKCS11KeyStore


# ---------------------------------------------------------------------------
# SoftwareKeyStore — full coverage
# ---------------------------------------------------------------------------


class TestSoftwareKeyStore:
    """Tests for the in-memory Ed25519 SoftwareKeyStore."""

    def test_generate_keypair(self):
        """Test keypair generation returns 32-byte public key."""
        store = SoftwareKeyStore()
        pub = store.generate_keypair("agent-1")

        assert isinstance(pub, bytes)
        assert len(pub) == 32

    def test_generate_keypair_duplicate_raises(self):
        """Test that generating a second keypair for the same agent raises ValueError."""
        store = SoftwareKeyStore()
        store.generate_keypair("agent-1")

        with pytest.raises(ValueError, match="already exists"):
            store.generate_keypair("agent-1")

    def test_sign_and_verify(self):
        """Test round-trip sign → verify."""
        store = SoftwareKeyStore()
        pub = store.generate_keypair("agent-1")
        data = b"hello world"

        sig = store.sign("agent-1", data)

        assert isinstance(sig, bytes)
        assert len(sig) == 64  # Ed25519 signature length
        assert store.verify(pub, data, sig) is True

    def test_verify_rejects_tampered_data(self):
        """Test that verification fails with altered data."""
        store = SoftwareKeyStore()
        pub = store.generate_keypair("agent-1")
        sig = store.sign("agent-1", b"original")

        assert store.verify(pub, b"tampered", sig) is False

    def test_verify_rejects_wrong_key(self):
        """Test that verification fails with a different public key."""
        store = SoftwareKeyStore()
        pub1 = store.generate_keypair("agent-1")
        pub2 = store.generate_keypair("agent-2")
        sig = store.sign("agent-1", b"data")

        assert store.verify(pub2, b"data", sig) is False

    def test_verify_rejects_invalid_signature(self):
        """Test that verification fails with garbage signature bytes."""
        store = SoftwareKeyStore()
        pub = store.generate_keypair("agent-1")

        assert store.verify(pub, b"data", b"\x00" * 64) is False

    def test_verify_rejects_invalid_key(self):
        """Test that verification returns False for invalid public key bytes."""
        store = SoftwareKeyStore()

        assert store.verify(b"bad-key", b"data", b"\x00" * 64) is False

    def test_sign_missing_key_raises(self):
        """Test that signing with a non-existent agent raises KeyError."""
        store = SoftwareKeyStore()

        with pytest.raises(KeyError, match="No keypair found"):
            store.sign("nonexistent", b"data")

    def test_get_public_key(self):
        """Test retrieving a public key matches the one from generation."""
        store = SoftwareKeyStore()
        pub = store.generate_keypair("agent-1")

        assert store.get_public_key("agent-1") == pub

    def test_get_public_key_missing_raises(self):
        """Test that get_public_key for a non-existent agent raises KeyError."""
        store = SoftwareKeyStore()

        with pytest.raises(KeyError, match="No keypair found"):
            store.get_public_key("nonexistent")

    def test_delete_key(self):
        """Test deleting a key removes it from the store."""
        store = SoftwareKeyStore()
        store.generate_keypair("agent-1")
        store.delete_key("agent-1")

        with pytest.raises(KeyError):
            store.get_public_key("agent-1")

    def test_delete_key_missing_raises(self):
        """Test that deleting a non-existent key raises KeyError."""
        store = SoftwareKeyStore()

        with pytest.raises(KeyError, match="No keypair found"):
            store.delete_key("nonexistent")

    def test_multiple_agents(self):
        """Test independent keypairs for multiple agents."""
        store = SoftwareKeyStore()
        pub1 = store.generate_keypair("agent-1")
        pub2 = store.generate_keypair("agent-2")

        assert pub1 != pub2

        sig1 = store.sign("agent-1", b"msg")
        sig2 = store.sign("agent-2", b"msg")

        assert store.verify(pub1, b"msg", sig1) is True
        assert store.verify(pub2, b"msg", sig2) is True
        assert store.verify(pub1, b"msg", sig2) is False

    def test_sign_after_delete_raises(self):
        """Test that signing after key deletion raises KeyError."""
        store = SoftwareKeyStore()
        store.generate_keypair("agent-1")
        store.delete_key("agent-1")

        with pytest.raises(KeyError):
            store.sign("agent-1", b"data")

    def test_regenerate_after_delete(self):
        """Test that a new keypair can be generated after deletion."""
        store = SoftwareKeyStore()
        pub1 = store.generate_keypair("agent-1")
        store.delete_key("agent-1")
        pub2 = store.generate_keypair("agent-1")

        # New key should differ (overwhelmingly likely)
        assert pub1 != pub2

    def test_is_abstract_base(self):
        """Test that KeyStore cannot be instantiated directly."""
        with pytest.raises(TypeError):
            KeyStore()  # type: ignore[abstract]


# ---------------------------------------------------------------------------
# PKCS11KeyStore — mock-based tests
# ---------------------------------------------------------------------------


class TestPKCS11KeyStore:
    """Tests for the HSM-backed PKCS11KeyStore using mocked pkcs11 library."""

    @pytest.fixture()
    def mock_pkcs11(self):
        """Create a comprehensive mock of the pkcs11 package."""
        mock_mod = MagicMock()
        mock_mod.KeyType.EC_EDWARDS = "ec_edwards"
        mock_mod.Mechanism.EDDSA = "eddsa"
        mock_mod.Attribute.EC_POINT = "ec_point"

        # Set up library → slot → token → session chain
        mock_session = MagicMock()
        mock_token = MagicMock()
        mock_token.open.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_token.open.return_value.__exit__ = MagicMock(return_value=False)
        mock_lib = MagicMock()
        mock_lib.get_slots.return_value = [mock_token]
        mock_mod.lib.return_value = mock_lib

        return mock_mod, mock_session

    def _make_store(self, mock_pkcs11):
        """Helper to construct a PKCS11KeyStore with mocked import."""
        mock_mod, _ = mock_pkcs11
        with patch.dict("sys.modules", {"pkcs11": mock_mod}):
            store = PKCS11KeyStore(
                library_path="/usr/lib/softhsm/libsofthsm2.so",
                slot=0,
                pin="1234",
            )
        return store

    def test_import_error_when_pkcs11_missing(self):
        """Test that ImportError is raised when pkcs11 is not installed."""
        with patch.dict("sys.modules", {"pkcs11": None}):
            with pytest.raises(ImportError, match="pkcs11"):
                PKCS11KeyStore(library_path="/fake/lib.so")

    def test_generate_keypair(self, mock_pkcs11):
        """Test HSM keypair generation via mocked PKCS#11."""
        mock_mod, mock_session = mock_pkcs11
        store = self._make_store(mock_pkcs11)

        mock_pub = MagicMock()
        mock_priv = MagicMock()
        mock_pub.__getitem__ = MagicMock(return_value=b"\x01" * 32)
        mock_session.generate_keypair.return_value = (mock_pub, mock_priv)

        pub = store.generate_keypair("agent-1")
        assert pub == b"\x01" * 32
        mock_session.generate_keypair.assert_called_once()

    def test_generate_keypair_duplicate_raises(self, mock_pkcs11):
        """Test duplicate keypair generation raises ValueError."""
        mock_mod, mock_session = mock_pkcs11
        store = self._make_store(mock_pkcs11)

        mock_pub = MagicMock()
        mock_priv = MagicMock()
        mock_pub.__getitem__ = MagicMock(return_value=b"\x01" * 32)
        mock_session.generate_keypair.return_value = (mock_pub, mock_priv)

        store.generate_keypair("agent-1")

        with pytest.raises(ValueError, match="already exists"):
            store.generate_keypair("agent-1")

    def test_sign(self, mock_pkcs11):
        """Test signing via mocked HSM."""
        mock_mod, mock_session = mock_pkcs11
        store = self._make_store(mock_pkcs11)

        mock_pub = MagicMock()
        mock_priv = MagicMock()
        mock_pub.__getitem__ = MagicMock(return_value=b"\x01" * 32)
        mock_priv.sign.return_value = b"\xaa" * 64
        mock_session.generate_keypair.return_value = (mock_pub, mock_priv)

        store.generate_keypair("agent-1")
        sig = store.sign("agent-1", b"data")

        assert sig == b"\xaa" * 64
        mock_priv.sign.assert_called_once()

    def test_sign_missing_key_raises(self, mock_pkcs11):
        """Test signing with missing key raises KeyError."""
        store = self._make_store(mock_pkcs11)

        with pytest.raises(KeyError, match="No keypair found"):
            store.sign("nonexistent", b"data")

    def test_get_public_key(self, mock_pkcs11):
        """Test public key retrieval from mocked HSM."""
        mock_mod, mock_session = mock_pkcs11
        store = self._make_store(mock_pkcs11)

        mock_pub = MagicMock()
        mock_priv = MagicMock()
        mock_pub.__getitem__ = MagicMock(return_value=b"\x02" * 32)
        mock_session.generate_keypair.return_value = (mock_pub, mock_priv)

        store.generate_keypair("agent-1")
        assert store.get_public_key("agent-1") == b"\x02" * 32

    def test_get_public_key_missing_raises(self, mock_pkcs11):
        """Test get_public_key for missing agent raises KeyError."""
        store = self._make_store(mock_pkcs11)

        with pytest.raises(KeyError, match="No keypair found"):
            store.get_public_key("nonexistent")

    def test_delete_key(self, mock_pkcs11):
        """Test key deletion calls destroy on HSM handles."""
        mock_mod, mock_session = mock_pkcs11
        store = self._make_store(mock_pkcs11)

        mock_pub = MagicMock()
        mock_priv = MagicMock()
        mock_pub.__getitem__ = MagicMock(return_value=b"\x01" * 32)
        mock_session.generate_keypair.return_value = (mock_pub, mock_priv)

        store.generate_keypair("agent-1")
        store.delete_key("agent-1")

        mock_pub.destroy.assert_called_once()
        mock_priv.destroy.assert_called_once()

        with pytest.raises(KeyError):
            store.get_public_key("agent-1")

    def test_delete_key_missing_raises(self, mock_pkcs11):
        """Test deleting a non-existent key raises KeyError."""
        store = self._make_store(mock_pkcs11)

        with pytest.raises(KeyError, match="No keypair found"):
            store.delete_key("nonexistent")

    def test_verify_valid_signature(self, mock_pkcs11):
        """Test that verify delegates to software Ed25519 verification."""
        store = self._make_store(mock_pkcs11)

        # Use a real software key for verification
        from cryptography.hazmat.primitives.asymmetric import ed25519 as ed

        priv = ed.Ed25519PrivateKey.generate()
        from cryptography.hazmat.primitives import serialization as ser

        pub_bytes = priv.public_key().public_bytes(
            encoding=ser.Encoding.Raw, format=ser.PublicFormat.Raw
        )
        data = b"test data"
        sig = priv.sign(data)

        assert store.verify(pub_bytes, data, sig) is True

    def test_verify_invalid_signature(self, mock_pkcs11):
        """Test that verify returns False for bad signatures."""
        store = self._make_store(mock_pkcs11)
        assert store.verify(b"\x00" * 32, b"data", b"\x00" * 64) is False
