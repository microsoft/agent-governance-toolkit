# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for concurrent MCP replay protection and nonce retention."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from threading import Barrier, Event

import pytest

from agent_os import DuplicateNonceError
from agent_os.mcp_message_signer import MCPMessageSigner
from agent_os.mcp_protocols import InMemoryNonceStore

KEY = b"k" * 32
NOW = datetime(2026, 9, 24, 10, 0, 0, 123456, tzinfo=UTC)


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    now = [NOW]
    monkeypatch.setattr("agent_os.mcp_message_signer._utcnow", lambda: now[0])

    def nonce_store(**kwargs):
        return InMemoryNonceStore(clock=lambda: now[0], **kwargs)

    monkeypatch.setattr("agent_os.mcp_message_signer.InMemoryNonceStore", nonce_store)
    return now


def test_same_receiver_accepts_only_one_concurrent_delivery(monkeypatch):
    receiver = MCPMessageSigner(KEY)
    signed = receiver.sign_message("payload")
    barrier = Barrier(4)
    compute_signature = receiver._compute_signature

    def synchronized_signature(**kwargs):
        signature = compute_signature(**kwargs)
        barrier.wait(timeout=10)
        return signature

    monkeypatch.setattr(receiver, "_compute_signature", synchronized_signature)
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(receiver.verify_message, [signed] * 4))

    assert sum(result.is_valid for result in results) == 1
    assert receiver.cached_nonce_count == 1
    assert all(
        result.is_valid or result.failure_reason == "Duplicate nonce (replay detected)."
        for result in results
    )


def test_shared_store_accepts_only_one_concurrent_delivery(monkeypatch, clock):
    store = InMemoryNonceStore(clock=lambda: clock[0])
    receivers = [MCPMessageSigner(KEY, nonce_store=store) for _ in range(4)]
    signed = MCPMessageSigner(KEY).sign_message("payload")
    barrier = Barrier(4)
    has_nonce = store.has

    def synchronized_has(nonce):
        found = has_nonce(nonce)
        barrier.wait(timeout=10)
        return found

    monkeypatch.setattr(store, "has", synchronized_has)
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(lambda receiver: receiver.verify_message(signed), receivers))

    assert sum(result.is_valid for result in results) == 1
    assert store.count() == 1
    assert all(
        result.is_valid or result.failure_reason == "Duplicate nonce (replay detected)."
        for result in results
    )


@pytest.mark.parametrize("max_entries", [1, 2])
@pytest.mark.parametrize("at_expiry", [False, True])
@pytest.mark.parametrize("replacement_offset", [-1, 1])
def test_duplicate_claim_preserves_retention(max_entries, at_expiry, replacement_offset, clock):
    store = InMemoryNonceStore(clock=lambda: clock[0], max_entries=max_entries)
    expires_at = NOW + timedelta(minutes=5)
    store.add("nonce", expires_at)
    if at_expiry:
        clock[0] = expires_at

    with pytest.raises(DuplicateNonceError):
        store.add("nonce", expires_at + replacement_offset * timedelta(minutes=5))

    assert store.count() == 1
    clock[0] = expires_at
    assert store.has("nonce")
    assert store.cleanup() == 0
    clock[0] += timedelta(microseconds=1)
    assert not store.has("nonce")
    store.add("nonce", clock[0] + timedelta(minutes=5))
    assert store.has("nonce")
    assert store.count() == 1


def test_atomic_claim_replaces_strictly_expired_nonce_at_capacity(clock):
    store = InMemoryNonceStore(clock=lambda: clock[0], max_entries=1)
    expires_at = NOW + timedelta(minutes=5)
    store.add("nonce", expires_at)
    clock[0] = expires_at + timedelta(microseconds=1)

    store.add("nonce", clock[0] + timedelta(minutes=5))

    assert store.has("nonce")
    assert store.count() == 1


def test_falsy_injected_nonce_store_is_not_replaced(clock):
    class EmptyStore(InMemoryNonceStore):
        def __bool__(self):
            return bool(self.count())

    store = EmptyStore(clock=lambda: clock[0])
    receiver = MCPMessageSigner(KEY, nonce_store=store)
    signed = MCPMessageSigner(KEY).sign_message("payload")

    assert receiver.verify_message(signed).is_valid
    assert store.has(signed.nonce)
    assert not MCPMessageSigner(KEY, nonce_store=store).verify_message(signed).is_valid


def test_invalid_signature_never_accesses_replay_store(monkeypatch, clock):
    store = InMemoryNonceStore(clock=lambda: clock[0])
    receiver = MCPMessageSigner(
        KEY, nonce_store=store, nonce_cache_cleanup_interval=timedelta(seconds=1)
    )
    signed = receiver.sign_message("payload")
    clock[0] += timedelta(seconds=1)
    calls = []

    def forbidden_store_access(*args):
        calls.append(args)
        raise AssertionError("Unauthenticated replay-store access")

    with monkeypatch.context() as patch:
        for method in ("has", "add", "cleanup"):
            patch.setattr(store, method, forbidden_store_access)
        result = receiver.verify_message(replace(signed, signature="invalid"))

    assert not result.is_valid
    assert result.failure_reason == "Invalid signature."
    assert result.payload is None
    assert result.sender_id is None
    assert calls == []
    assert receiver.cached_nonce_count == 0
    assert receiver.verify_message(signed).is_valid


def test_message_expiring_during_signature_verification_is_rejected(monkeypatch, clock):
    receiver = MCPMessageSigner(KEY)
    signed = receiver.sign_message("payload")
    compute_signature = receiver._compute_signature

    def slow_signature(**kwargs):
        signature = compute_signature(**kwargs)
        clock[0] += timedelta(minutes=5, microseconds=1)
        return signature

    monkeypatch.setattr(receiver, "_compute_signature", slow_signature)
    result = receiver.verify_message(signed)

    assert not result.is_valid
    assert result.failure_reason == "Message timestamp outside replay window."
    assert receiver.cached_nonce_count == 0


def test_message_expiring_while_waiting_for_signer_lock_is_rejected(monkeypatch, clock):
    receiver = MCPMessageSigner(KEY)
    signed = receiver.sign_message("payload")
    lock = receiver._lock
    waiting = Event()

    class ObservedLock:
        def __enter__(self):
            waiting.set()
            lock.acquire()
            return self

        def __exit__(self, *_exc):
            lock.release()

    monkeypatch.setattr(receiver, "_lock", ObservedLock())
    with ThreadPoolExecutor(max_workers=1) as executor:
        lock.acquire()
        try:
            future = executor.submit(receiver.verify_message, signed)
            assert waiting.wait(timeout=10)
            clock[0] += timedelta(minutes=5, microseconds=1)
        finally:
            lock.release()
        result = future.result(timeout=10)

    assert not result.is_valid
    assert result.failure_reason == "Message timestamp outside replay window."
    assert receiver.cached_nonce_count == 0


@pytest.mark.parametrize("offset", [-1, 1])
def test_replay_window_rejects_past_and_future_messages(offset):
    signed = MCPMessageSigner(KEY).sign_message("payload")
    timestamp = NOW + offset * (timedelta(minutes=5) + timedelta(microseconds=1))
    signer = MCPMessageSigner(KEY)
    signed = replace(
        signed,
        timestamp=timestamp,
        signature=signer._compute_signature(
            nonce=signed.nonce, timestamp=timestamp, sender_id=None, payload=signed.payload
        ),
    )

    result = signer.verify_message(signed)

    assert not result.is_valid
    assert result.failure_reason == "Message timestamp outside replay window."
    assert signer.cached_nonce_count == 0


@pytest.mark.parametrize("offset", [-1, 1])
def test_replay_window_boundaries_accept_once(offset):
    signer = MCPMessageSigner(KEY)
    signed = signer.sign_message("payload")
    timestamp = NOW + offset * timedelta(minutes=5)
    signed = replace(
        signed,
        timestamp=timestamp,
        signature=signer._compute_signature(
            nonce=signed.nonce, timestamp=timestamp, sender_id=None, payload=signed.payload
        ),
    )

    assert signer.verify_message(signed).is_valid
    assert not signer.verify_message(signed).is_valid
    assert signer.cached_nonce_count == 1


@pytest.mark.parametrize("automatic", [False, True])
def test_cleanup_never_reopens_a_live_replay_window(automatic, clock):
    store = InMemoryNonceStore(clock=lambda: clock[0], max_entries=1)
    signer = MCPMessageSigner(
        KEY, nonce_store=store, nonce_cache_cleanup_interval=timedelta(seconds=1)
    )
    first = signer.sign_message("first")
    assert signer.verify_message(first).is_valid
    clock[0] += timedelta(minutes=5)
    if not automatic:
        assert signer.cleanup_nonce_cache() == 0
    at_capacity = signer.verify_message(signer.sign_message("at boundary"))
    assert not at_capacity.is_valid
    assert at_capacity.failure_reason == "Nonce store at capacity (fail-closed)."
    assert not signer.verify_message(first).is_valid
    clock[0] += timedelta(seconds=1)
    if not automatic:
        assert signer.cleanup_nonce_cache() == 1
    second = signer.sign_message("second")

    assert signer.verify_message(second).is_valid
    assert store.count() == 1
    assert not signer.verify_message(first).is_valid
    assert not signer.verify_message(second).is_valid


@pytest.mark.parametrize("method", ["has", "add", "cleanup"])
def test_store_errors_fail_closed(method, monkeypatch, clock):
    store = InMemoryNonceStore(clock=lambda: clock[0])
    receiver = MCPMessageSigner(
        KEY, nonce_store=store, nonce_cache_cleanup_interval=timedelta(seconds=1)
    )
    signed = MCPMessageSigner(KEY).sign_message("payload")
    clock[0] += timedelta(seconds=1)

    def unavailable_store(*args):
        raise OSError("nonce store unavailable")

    with monkeypatch.context() as patch:
        patch.setattr(store, method, unavailable_store)
        result = receiver.verify_message(signed)

    assert not result.is_valid
    assert result.payload is None
    assert result.sender_id is None
    assert "fail-closed" in result.failure_reason
    assert store.count() == 0
    assert receiver.verify_message(signed).is_valid


def test_duplicate_warning_does_not_log_nonce(caplog):
    nonce = "attacker-controlled\nnonce"
    signer = MCPMessageSigner(KEY, nonce_generator=lambda: nonce)
    signed = signer.sign_message("payload")

    assert signer.verify_message(signed).is_valid
    assert not signer.verify_message(signed).is_valid
    assert "Duplicate MCP nonce detected." in caplog.text
    assert nonce not in caplog.text
