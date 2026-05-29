# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Base Adapter Protocol

Defines the common interface that all layer adapters must implement.
This ensures consistent integration patterns across the stack.

Security model
~~~~~~~~~~~~~~

Adapters bridge mute-agent to third-party backends. Several invariants
are enforced here so that compromised in-process callers or malicious
configs cannot relax the adapter's security posture:

* ``mock_mode`` is captured at construction time and is **immutable
  thereafter**. Setting ``adapter.mock_mode = True`` or
  ``adapter._mock_mode = True`` post-construction raises
  ``AttributeError``.
* ``config["client_factory"]`` is a *test-only* override seam.
  Subclasses that honor it must guard it on ``mock_mode is True``;
  see e.g. ``iatp_adapter._create_client``. The hook is ignored in
  production mode so a malicious YAML config cannot inject a permissive
  client.
* ``_last_error`` (and ``AdapterStatus.error``) never include the raw
  ``str(e)`` text of a backend driver exception. They only carry the
  exception *type name* plus an adapter-controlled static remediation
  hint, so credentials, tokens, or URLs that the driver embedded in
  its error message do not leak to the listener's audit trail or to
  log sinks. The full exception (with stack) is logged via
  ``logger.exception`` to the adapter's own logger.
* ``connect()`` validates that ``_create_client`` / ``_mock_client``
  returned a non-``None`` client before reporting success. A subclass
  that accidentally returns ``None`` causes ``connect`` to fail-closed
  rather than silently leaving ``is_connected=True`` with no client.
"""

import logging
from typing import Dict, Any, Optional, Protocol, runtime_checkable
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime


logger = logging.getLogger(__name__)

# Attributes guarded by the immutable post-init __setattr__ check.
# Any write to these names after ``_initialized`` is set raises.
_IMMUTABLE_ATTRS = frozenset({"mock_mode", "_mock_mode"})


@dataclass
class AdapterStatus:
    """Status of a layer adapter connection."""

    connected: bool
    layer_name: str
    version: Optional[str] = None
    last_health_check: Optional[datetime] = None
    latency_ms: Optional[float] = None
    error: Optional[str] = None


@runtime_checkable
class AdapterProtocol(Protocol):
    """Protocol that all layer adapters must implement."""

    def connect(self) -> bool:
        """Establish connection to the layer service."""
        ...

    def disconnect(self) -> None:
        """Disconnect from the layer service."""
        ...

    def health_check(self) -> AdapterStatus:
        """Check health of the layer connection."""
        ...

    def get_layer_name(self) -> str:
        """Get the name of the layer this adapter connects to."""
        ...


def _safe_error_text(adapter: "BaseLayerAdapter", exc: BaseException) -> str:
    """Build the user-facing error string for an exception.

    Includes ONLY the exception type name and the adapter's static
    remediation hint. Never includes ``str(exc)`` because driver
    exceptions routinely embed credentials, tokens, or internal URLs.
    """
    hint = getattr(adapter, "_remediation_hint", None) or "see adapter logs for detail"
    return f"{type(exc).__name__} ({hint})"


class BaseLayerAdapter(ABC):
    """
    Abstract base class for layer adapters.

    Provides common functionality for connecting to and interacting
    with lower-layer services in the stack.
    """

    # Subclasses MAY override this with a layer-specific remediation
    # hint. Keep this static, adapter-controlled text only — NEVER
    # interpolate untrusted strings into it.
    _remediation_hint: str = "see adapter logs for detail"

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        mock_mode: bool = False,
    ):
        """
        Initialize the adapter.

        Args:
            config: Optional configuration for the layer connection
            mock_mode: If True, use mock implementation (for testing)

        ``mock_mode`` is captured here and becomes immutable. Subclasses
        that want to test ``client_factory`` injection MUST opt in by
        passing ``mock_mode=True`` at construction.
        """
        # NOTE: Set _initialized=False FIRST so the post-init __setattr__
        # guard treats every assignment below as construction-time.
        object.__setattr__(self, "_initialized", False)
        self.config = config or {}
        self._mock_mode = bool(mock_mode)
        self._connected = False
        self._last_health_check: Optional[datetime] = None
        self._client: Optional[Any] = None
        self._last_error: Optional[str] = None
        object.__setattr__(self, "_initialized", True)

    def __setattr__(self, name: str, value: Any) -> None:
        # Enforce immutability of mock_mode after construction.
        if name in _IMMUTABLE_ATTRS and getattr(self, "_initialized", False):
            raise AttributeError(
                f"{name} is immutable after construction; pass mock_mode=True "
                "to the constructor instead"
            )
        object.__setattr__(self, name, value)

    @property
    def mock_mode(self) -> bool:
        """Whether this adapter was constructed in mock mode (read-only)."""
        return self._mock_mode

    @abstractmethod
    def get_layer_name(self) -> str:
        """Get the name of the layer this adapter connects to."""
        pass

    @abstractmethod
    def _create_client(self) -> Any:
        """Create the client for connecting to the layer service."""
        pass

    @abstractmethod
    def _mock_client(self) -> Any:
        """Create a mock client for testing."""
        pass

    def connect(self) -> bool:
        """
        Establish connection to the layer service.

        Returns:
            True if connection successful, False otherwise

        Note:
            ``_create_client`` and ``_mock_client`` may delegate to arbitrary
            third-party driver/SDK code that raises any exception type. We
            therefore catch ``Exception`` here intentionally so the adapter
            never propagates an unrelated failure as a hard crash. Every
            failure is logged with ``exc_info=True`` and a
            ``_safe_error_text`` form (type name + static remediation hint,
            never raw driver text) is persisted to ``self._last_error``.
            ``KeyboardInterrupt``/``SystemExit`` are not caught.
        """
        if self._connected:
            return True

        try:
            if self._mock_mode:
                client = self._mock_client()
            else:
                client = self._create_client()

            # M1: subclass returning None must not leave the adapter in
            # a "connected" state with no client.
            if client is None:
                self._connected = False
                self._client = None
                self._last_error = (
                    f"{self.get_layer_name()}: backing client is None "
                    f"({self._remediation_hint})"
                )
                logger.error(
                    "Adapter %s: _create_client/_mock_client returned None",
                    self.get_layer_name(),
                )
                return False

            self._client = client
            self._connected = True
            self._last_health_check = datetime.now()
            self._last_error = None
            return True

        except Exception as e:
            self._connected = False
            self._last_error = _safe_error_text(self, e)
            logger.exception(
                "Adapter %s failed to connect", self.get_layer_name()
            )
            return False

    def disconnect(self) -> None:
        """
        Disconnect from the layer service.

        Driver ``close()`` implementations are also third-party code; a broad
        ``except`` keeps shutdown best-effort but failures are logged with
        full stack and recorded as ``_safe_error_text`` in
        ``self._last_error`` so they aren't silently lost.
        """
        if self._client and hasattr(self._client, 'close'):
            try:
                self._client.close()
            except Exception as e:
                self._last_error = _safe_error_text(self, e)
                logger.exception(
                    "Adapter %s raised while closing client",
                    self.get_layer_name(),
                )

        self._client = None
        self._connected = False

    def health_check(self) -> AdapterStatus:
        """
        Check health of the layer connection.

        Returns:
            AdapterStatus with connection details

        Note:
            ``_health_ping`` may invoke arbitrary driver code, so we catch
            ``Exception`` here as well. Every failure is logged with
            ``exc_info=True`` and surfaced through ``_safe_error_text`` to
            both ``self._last_error`` and ``AdapterStatus.error``.
        """
        self._last_health_check = datetime.now()

        if not self._connected or not self._client:
            return AdapterStatus(
                connected=False,
                layer_name=self.get_layer_name(),
                error=self._last_error or "Not connected",
            )

        try:
            # Attempt a lightweight operation to verify connection
            start = datetime.now()
            self._health_ping()
            latency = (datetime.now() - start).total_seconds() * 1000

            return AdapterStatus(
                connected=True,
                layer_name=self.get_layer_name(),
                version=self._get_version(),
                last_health_check=self._last_health_check,
                latency_ms=latency,
            )

        except Exception as e:
            self._connected = False
            self._last_error = _safe_error_text(self, e)
            logger.exception(
                "Adapter %s health_check failed", self.get_layer_name()
            )
            return AdapterStatus(
                connected=False,
                layer_name=self.get_layer_name(),
                last_health_check=self._last_health_check,
                error=self._last_error,
            )

    def _health_ping(self) -> None:
        """
        Perform a health ping to verify connection.
        Override in subclasses for layer-specific health checks.
        """
        pass

    def _get_version(self) -> Optional[str]:
        """
        Get the version of the connected layer service.
        Override in subclasses for layer-specific version retrieval.
        """
        return None

    @property
    def is_connected(self) -> bool:
        """Check if adapter is connected."""
        return self._connected

    def ensure_connected(self) -> None:
        """Ensure adapter is connected, raising if not."""
        if not self._connected:
            if not self.connect():
                detail = f": {self._last_error}" if self._last_error else ""
                raise ConnectionError(
                    f"Failed to connect to {self.get_layer_name()}{detail}"
                )
