# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Durable store contract for pending approvals (ADR-0030 section 5).

The coordinator persists requests, hash-linked chain entries, and resolutions
outside process memory so a worker can resume a pending request after restart
and so a single allow can be consumed exactly once. :class:`ApprovalStore` is
the protocol production deployments implement against a real backend;
:class:`InMemoryApprovalStore` is a thread-safe reference implementation used by
tests and single-process embedders.
"""

from __future__ import annotations

import threading
from typing import Optional, Protocol, runtime_checkable

from .models import (
    ApprovalChainEntry,
    ApprovalRequest,
    ApprovalResolution,
    ApprovalStatus,
)


@runtime_checkable
class ApprovalStore(Protocol):
    """Persistence contract for the approval coordinator."""

    def save_request(self, request: ApprovalRequest) -> None: ...

    def get_request(self, approval_request_id: str) -> Optional[ApprovalRequest]: ...

    def set_status(self, approval_request_id: str, status: ApprovalStatus) -> None: ...

    def append_entry(self, entry: ApprovalChainEntry) -> None: ...

    def get_entries(self, approval_request_id: str) -> list[ApprovalChainEntry]: ...

    def save_resolution(self, resolution: ApprovalResolution) -> None: ...

    def get_resolution(self, approval_request_id: str) -> Optional[ApprovalResolution]: ...

    def consume(self, approval_request_id: str) -> bool:
        """Atomically mark an ``ALLOWED`` request ``CONSUMED``.

        Returns ``True`` exactly once for a given request; subsequent calls
        return ``False``. This is the one-time-use guard that stops two workers
        from racing to reuse a single approval (ADR-0030 section 6).
        """
        ...


class InMemoryApprovalStore:
    """Thread-safe, in-process :class:`ApprovalStore` reference implementation."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._requests: dict[str, ApprovalRequest] = {}
        self._entries: dict[str, list[ApprovalChainEntry]] = {}
        self._resolutions: dict[str, ApprovalResolution] = {}

    def save_request(self, request: ApprovalRequest) -> None:
        with self._lock:
            self._requests[request.approval_request_id] = request
            self._entries.setdefault(request.approval_request_id, [])

    def get_request(self, approval_request_id: str) -> Optional[ApprovalRequest]:
        with self._lock:
            return self._requests.get(approval_request_id)

    def set_status(self, approval_request_id: str, status: ApprovalStatus) -> None:
        with self._lock:
            request = self._requests.get(approval_request_id)
            if request is not None:
                request.status = status

    def append_entry(self, entry: ApprovalChainEntry) -> None:
        with self._lock:
            self._entries.setdefault(entry.approval_request_id, []).append(entry)

    def get_entries(self, approval_request_id: str) -> list[ApprovalChainEntry]:
        with self._lock:
            return list(self._entries.get(approval_request_id, []))

    def save_resolution(self, resolution: ApprovalResolution) -> None:
        with self._lock:
            self._resolutions[resolution.approval_request_id] = resolution

    def get_resolution(self, approval_request_id: str) -> Optional[ApprovalResolution]:
        with self._lock:
            return self._resolutions.get(approval_request_id)

    def consume(self, approval_request_id: str) -> bool:
        with self._lock:
            request = self._requests.get(approval_request_id)
            if request is None or request.status != ApprovalStatus.ALLOWED:
                return False
            request.status = ApprovalStatus.CONSUMED
            return True
