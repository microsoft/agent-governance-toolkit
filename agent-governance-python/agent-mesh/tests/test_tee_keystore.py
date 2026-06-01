# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the TEE key store abstraction (PR 3 / ADR 0010)."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest

from agentmesh.exceptions import KeyAcquisitionError
from agentmesh.identity.attestation import KeyOrigin, public_key_hash_hex
from agentmesh.identity.tee_keystore import (
    LocalTEEKeyStore,
    MockSKRKeyStore,
    SoftwareKeyHandle,
    TEEKeyHandle,
    TEEKeyStore,
    require_tee_bound_key,
)

# ---------------------------------------------------------------------------
# SoftwareKeyHandle
# ---------------------------------------------------------------------------


class TestSoftwareKeyHandle:
    """Tests for the concrete in-memory key handle."""

    @pytest.fixture()
    def _make_handle(self) -> Callable[..., SoftwareKeyHandle]:
        from cryptography.hazmat.primitives.asymmetric import ed25519

        def factory(
            key_id: str = "test-key",
            key_origin: KeyOrigin = KeyOrigin.LOCAL,
            expires_at: datetime | None = None,
        ) -> SoftwareKeyHandle:
            private_key = ed25519.Ed25519PrivateKey.generate()
            return SoftwareKeyHandle(
                key_id=key_id,
                key_origin=key_origin,
                private_key=private_key,
                expires_at=expires_at,
            )

        return factory

    @pytest.mark.asyncio
    async def test_sign_and_verify(
        self, _make_handle: Callable[..., SoftwareKeyHandle]
    ) -> None:
        handle = _make_handle()
        data = b"test-payload"
        signature = await handle.sign(data)

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        pk = Ed25519PublicKey.from_public_bytes(handle.public_key)
        pk.verify(signature, data)

    def test_public_key_is_32_bytes(
        self, _make_handle: Callable[..., SoftwareKeyHandle]
    ) -> None:
        handle = _make_handle()
        assert len(handle.public_key) == 32

    def test_public_key_hash_matches_attestation_binding(
        self, _make_handle: Callable[..., SoftwareKeyHandle]
    ) -> None:
        handle = _make_handle()
        assert handle.public_key_hash() == public_key_hash_hex(handle.public_key)

    def test_key_origin_propagated(
        self, _make_handle: Callable[..., SoftwareKeyHandle]
    ) -> None:
        handle_local = _make_handle(key_origin=KeyOrigin.LOCAL)
        handle_skr = _make_handle(key_origin=KeyOrigin.SKR)
        handle_tee = _make_handle(key_origin=KeyOrigin.TEE_GENERATED)

        assert handle_local.key_origin == KeyOrigin.LOCAL
        assert handle_skr.key_origin == KeyOrigin.SKR
        assert handle_tee.key_origin == KeyOrigin.TEE_GENERATED

    def test_is_expired_false_when_no_expiry(
        self, _make_handle: Callable[..., SoftwareKeyHandle]
    ) -> None:
        handle = _make_handle(expires_at=None)
        assert not handle.is_expired()

    def test_is_expired_false_when_future(
        self, _make_handle: Callable[..., SoftwareKeyHandle]
    ) -> None:
        handle = _make_handle(expires_at=datetime.now(UTC) + timedelta(hours=1))
        assert not handle.is_expired()

    def test_is_expired_true_when_past(
        self, _make_handle: Callable[..., SoftwareKeyHandle]
    ) -> None:
        handle = _make_handle(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        assert handle.is_expired()

    @pytest.mark.asyncio
    async def test_sign_rejects_expired_handle(
        self, _make_handle: Callable[..., SoftwareKeyHandle]
    ) -> None:
        handle = _make_handle(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        with pytest.raises(KeyAcquisitionError, match="expired"):
            await handle.sign(b"data")

    def test_created_at_defaults_to_utc_now(
        self, _make_handle: Callable[..., SoftwareKeyHandle]
    ) -> None:
        before = datetime.now(UTC)
        handle = _make_handle()
        after = datetime.now(UTC)
        assert before <= handle.created_at <= after


# ---------------------------------------------------------------------------
# LocalTEEKeyStore
# ---------------------------------------------------------------------------


class TestLocalTEEKeyStore:
    """Tests for the non-TEE adapter."""

    @pytest.mark.asyncio
    async def test_acquire_returns_local_origin(self) -> None:
        store = LocalTEEKeyStore()
        handle = await store.acquire_key("agent-1")

        assert handle.key_origin == KeyOrigin.LOCAL
        assert handle.key_id == "agent-1"
        assert len(handle.public_key) == 32

    @pytest.mark.asyncio
    async def test_acquire_returns_same_key_on_repeat(self) -> None:
        store = LocalTEEKeyStore()
        h1 = await store.acquire_key("agent-1")
        h2 = await store.acquire_key("agent-1")

        assert h1.public_key == h2.public_key

    @pytest.mark.asyncio
    async def test_acquire_different_ids_get_different_keys(self) -> None:
        store = LocalTEEKeyStore()
        h1 = await store.acquire_key("agent-1")
        h2 = await store.acquire_key("agent-2")

        assert h1.public_key != h2.public_key

    @pytest.mark.asyncio
    async def test_sign_produces_valid_signature(self) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        store = LocalTEEKeyStore()
        handle = await store.acquire_key("agent-1")

        data = b"hello-mesh"
        sig = await handle.sign(data)

        pk = Ed25519PublicKey.from_public_bytes(handle.public_key)
        pk.verify(sig, data)

    def test_key_origin_is_local(self) -> None:
        store = LocalTEEKeyStore()
        assert store.key_origin() == KeyOrigin.LOCAL

    @pytest.mark.asyncio
    async def test_handle_does_not_expire(self) -> None:
        store = LocalTEEKeyStore()
        handle = await store.acquire_key("agent-1")
        assert handle.expires_at is None
        assert not handle.is_expired()


# ---------------------------------------------------------------------------
# MockSKRKeyStore
# ---------------------------------------------------------------------------


class TestMockSKRKeyStore:
    """Tests for the mock Secure Key Release store."""

    @pytest.mark.asyncio
    async def test_acquire_returns_skr_origin(self) -> None:
        store = MockSKRKeyStore()
        handle = await store.acquire_key("payment-key")

        assert handle.key_origin == KeyOrigin.SKR
        assert handle.key_id == "payment-key"
        assert len(handle.public_key) == 32

    @pytest.mark.asyncio
    async def test_default_ttl_sets_expiry(self) -> None:
        store = MockSKRKeyStore(ttl_seconds=60)
        before = datetime.now(UTC)
        handle = await store.acquire_key("k1")
        after = datetime.now(UTC)

        assert handle.expires_at is not None
        assert before + timedelta(seconds=59) <= handle.expires_at
        assert handle.expires_at <= after + timedelta(seconds=61)

    @pytest.mark.asyncio
    async def test_no_ttl_means_no_expiry(self) -> None:
        store = MockSKRKeyStore(ttl_seconds=None)
        handle = await store.acquire_key("k1")
        assert handle.expires_at is None

    @pytest.mark.asyncio
    async def test_error_injection_wraps_in_key_acquisition_error(self) -> None:
        store = MockSKRKeyStore(error=RuntimeError("SKR denied"))
        with pytest.raises(KeyAcquisitionError, match="Mock SKR key acquisition failed"):
            await store.acquire_key("k1")

    @pytest.mark.asyncio
    async def test_direct_key_acquisition_error_raised_as_is(self) -> None:
        custom = KeyAcquisitionError("custom: policy mismatch")
        store = MockSKRKeyStore(error=custom)
        with pytest.raises(KeyAcquisitionError, match="custom: policy mismatch"):
            await store.acquire_key("k1")

    @pytest.mark.asyncio
    async def test_latency_simulation(self) -> None:
        store = MockSKRKeyStore(latency_seconds=0.05)
        start = datetime.now(UTC)
        await store.acquire_key("k1")
        elapsed = (datetime.now(UTC) - start).total_seconds()
        assert elapsed >= 0.04

    @pytest.mark.asyncio
    async def test_same_key_returned_on_repeat(self) -> None:
        store = MockSKRKeyStore()
        h1 = await store.acquire_key("k1")
        h2 = await store.acquire_key("k1")
        assert h1.public_key == h2.public_key

    @pytest.mark.asyncio
    async def test_custom_key_origin(self) -> None:
        store = MockSKRKeyStore(key_origin_value=KeyOrigin.TEE_GENERATED)
        handle = await store.acquire_key("k1")
        assert handle.key_origin == KeyOrigin.TEE_GENERATED

    def test_key_origin_method(self) -> None:
        store = MockSKRKeyStore()
        assert store.key_origin() == KeyOrigin.SKR

    def test_rejects_negative_latency(self) -> None:
        with pytest.raises(ValueError, match="latency_seconds"):
            MockSKRKeyStore(latency_seconds=-1.0)

    def test_rejects_non_positive_ttl(self) -> None:
        with pytest.raises(ValueError, match="ttl_seconds"):
            MockSKRKeyStore(ttl_seconds=0)

    @pytest.mark.asyncio
    async def test_sign_with_skr_handle(self) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        store = MockSKRKeyStore()
        handle = await store.acquire_key("k1")

        data = b"transaction-payload"
        sig = await handle.sign(data)

        pk = Ed25519PublicKey.from_public_bytes(handle.public_key)
        pk.verify(sig, data)


# ---------------------------------------------------------------------------
# require_tee_bound_key helper
# ---------------------------------------------------------------------------


class TestRequireTEEBoundKey:
    """Tests for the policy enforcement helper."""

    @pytest.fixture()
    def _local_handle(self) -> SoftwareKeyHandle:
        from cryptography.hazmat.primitives.asymmetric import ed25519

        pk = ed25519.Ed25519PrivateKey.generate()
        return SoftwareKeyHandle(
            key_id="local-key",
            key_origin=KeyOrigin.LOCAL,
            private_key=pk,
        )

    @pytest.fixture()
    def _skr_handle(self) -> SoftwareKeyHandle:
        from cryptography.hazmat.primitives.asymmetric import ed25519

        pk = ed25519.Ed25519PrivateKey.generate()
        return SoftwareKeyHandle(
            key_id="skr-key",
            key_origin=KeyOrigin.SKR,
            private_key=pk,
        )

    def test_local_key_raises(self, _local_handle: SoftwareKeyHandle) -> None:
        with pytest.raises(KeyAcquisitionError, match="TEE-bound key required"):
            require_tee_bound_key(_local_handle)

    def test_local_key_raises_with_context(
        self, _local_handle: SoftwareKeyHandle
    ) -> None:
        with pytest.raises(KeyAcquisitionError, match="handshake"):
            require_tee_bound_key(_local_handle, context="handshake")

    def test_skr_key_passes(self, _skr_handle: SoftwareKeyHandle) -> None:
        require_tee_bound_key(_skr_handle)

    def test_tee_generated_key_passes(self) -> None:
        from cryptography.hazmat.primitives.asymmetric import ed25519

        pk = ed25519.Ed25519PrivateKey.generate()
        handle = SoftwareKeyHandle(
            key_id="tee-key",
            key_origin=KeyOrigin.TEE_GENERATED,
            private_key=pk,
        )
        require_tee_bound_key(handle)


# ---------------------------------------------------------------------------
# Interface contract checks
# ---------------------------------------------------------------------------


class TestInterfaceContracts:
    """Verify the ABC contracts are satisfied by all implementations."""

    def test_local_store_is_tee_keystore(self) -> None:
        assert issubclass(LocalTEEKeyStore, TEEKeyStore)

    def test_mock_skr_store_is_tee_keystore(self) -> None:
        assert issubclass(MockSKRKeyStore, TEEKeyStore)

    def test_software_handle_is_tee_key_handle(self) -> None:
        assert issubclass(SoftwareKeyHandle, TEEKeyHandle)
