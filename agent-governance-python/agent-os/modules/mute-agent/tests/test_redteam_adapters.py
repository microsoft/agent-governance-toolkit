# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Red-team regression tests for the layer adapters.

Findings covered: H2 (client_factory bypass), H3 (mock_mode mutation),
H4 (driver credential leak via _last_error), M1 (None client passes as
connected).

On the pre-fix tree (commit 888d26f7 — listener and handshake already
hardened; adapters still at 5997d781) all 4 tests fail for the
documented reason.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.listener.adapters.iatp_adapter import SecurityAdapter  # noqa: E402


# --- H2: client_factory bypass without mock_mode ------------------------

def test_H2_client_factory_only_fires_in_mock_mode():
    """H2: ``config['client_factory']`` is a test hook. It must only
    be honored when the adapter was constructed with ``mock_mode=True``.

    Pre-fix: ``_create_client`` calls ``client_factory(self.config)``
    unconditionally if the config field is set — a malicious in-process
    caller (or a misconfigured operator YAML) can swap the production
    backend for an attacker-controlled client.
    Post-fix: the factory hook only fires through ``_mock_client`` and
    therefore requires explicit ``mock_mode=True`` opt-in.
    """
    calls = []

    def hostile_factory(_config):
        calls.append("called")
        return object()

    # No mock_mode → factory must NOT run.
    adapter = SecurityAdapter(
        config={"client_factory": hostile_factory},
        mock_mode=False,
    )
    adapter.connect()  # may fail because IATP backend missing — that's fine
    assert calls == [], (
        f"client_factory was called without mock_mode opt-in: {calls!r}"
    )


# --- H3: mock_mode must be frozen after construction --------------------

def test_H3_mock_mode_cannot_be_flipped_post_construction():
    """H3: an in-process attacker should not be able to enable
    ``mock_mode`` at runtime to short-circuit the real backend.

    Pre-fix: ``self.mock_mode = mock_mode`` is a plain attribute.
    ``adapter.mock_mode = True`` after construction will cause the next
    ``connect()`` to silently return a MockIATPClient.
    Post-fix: __setattr__ guards _IMMUTABLE_ATTRS once __init__
    finishes; mutation raises AttributeError.
    """
    adapter = SecurityAdapter(mock_mode=False)
    import pytest
    with pytest.raises(AttributeError):
        adapter.mock_mode = True
    # Effective state must remain False.
    assert adapter.mock_mode is False


# --- H4: _last_error must not leak driver-supplied credentials ----------

def test_H4_last_error_does_not_leak_driver_credentials():
    """H4: backend driver exceptions routinely embed bearer tokens,
    connection strings, or other secrets in their messages. ``_last_error``
    must NOT propagate ``str(e)`` from third-party exceptions — only
    the exception type name plus a static remediation hint.

    Pre-fix: ``self._last_error = f'{type(e).__name__}: {e}'`` includes
    the full driver message verbatim — a memory dump or audit log
    inspection leaks the secret.
    Post-fix: ``_last_error`` is constructed from class-level
    ``_remediation_hint`` and the exception type only.
    """
    SECRET = "Bearer eyJhbGciOiJIUzI1Ni-SUPER-SECRET-TOKEN"

    # Drive the leak through the standard connect() failure path: a third-
    # party driver typically raises with credentials in str(e). Subclass
    # _create_client to raise so we don't depend on client_factory semantics.
    class LeakyAdapter(SecurityAdapter):
        def _create_client(self):
            raise RuntimeError(f"upstream auth failed: token={SECRET}")

    adapter = LeakyAdapter(mock_mode=False)
    result = adapter.connect()
    assert result is False  # connect should report failure either way

    assert SECRET not in (adapter._last_error or ""), (
        f"_last_error leaked SECRET from driver exception: {adapter._last_error!r}"
    )

    status = adapter.health_check()
    assert SECRET not in (status.error or ""), (
        f"AdapterStatus.error leaked SECRET: {status.error!r}"
    )


# --- M1: connect() must return False when _create_client returns None ----

def test_M1_connect_fails_closed_when_create_client_returns_none():
    """M1: a subclass / mock that returns None from ``_create_client``
    must NOT leave the adapter in a connected state with a None client.

    Pre-fix: ``self._client = self._create_client()`` then
    ``self._connected = True`` unconditionally — downstream calls
    operate on ``None.method(...)`` and explode.
    Post-fix: connect() checks ``client is None`` and fails closed
    (returns False, _connected stays False, _last_error explains).
    """
    class NoneAdapter(SecurityAdapter):
        def _create_client(self):
            return None

    adapter = NoneAdapter(mock_mode=False)
    result = adapter.connect()
    assert result is False
    assert adapter.is_connected is False
