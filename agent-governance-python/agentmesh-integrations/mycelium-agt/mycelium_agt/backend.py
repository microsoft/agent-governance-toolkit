# Copyright (c) giskard09 (Rama / Mycelium)
# Licensed under the Apache License, Version 2.0.
"""MyceliumBackend — Mycelium Trails adapter for AGT.

Implements the EvidenceAnchor protocol so that every agent action produces
a tamper-evident TrailRecord, independently verifiable without trusting
the operator's logs or database.

action_ref derivation (JCS RFC 8785 + SHA-256):

    preimage  = JCS({
        "action_type": action_type,
        "agent_id":    agent_id,
        "scope":       scope,
        "timestamp":   "2026-05-15T10:00:00.123Z",   # RFC 3339 UTC, 3-digit ms
    })
    action_ref = SHA-256(preimage) → lowercase hex

The four preimage fields are included in every AnchorReceipt so any party
can independently recompute and verify the action_ref.

Verification::

    curl 'https://argentum-api.rgiskard.xyz/trails/verify?agent_id=<id>&action_ref=<ref>'
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")

logger = logging.getLogger(__name__)

_DEFAULT_MYCELIUM_URL = "https://argentum-api.rgiskard.xyz"


# ---------------------------------------------------------------------------
# action_ref canonical derivation — JCS RFC 8785 + SHA-256
# ---------------------------------------------------------------------------

def _jcs_encode(d: dict[str, str]) -> bytes:
    """RFC 8785 JCS for a flat dict of string values.

    Key ordering is lexicographic Unicode code point order.
    Non-ASCII above U+001F emitted as literal UTF-8 bytes (RFC 8785 §3.2.3).
    """
    return json.dumps(
        dict(sorted(d.items())),
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _format_timestamp(dt: datetime.datetime) -> str:
    """RFC 3339 UTC with exactly 3 millisecond digits.

    Output: "2026-05-15T10:00:00.123Z"
    """
    ms = dt.microsecond // 1000
    return dt.strftime(f"%Y-%m-%dT%H:%M:%S.{ms:03d}Z")


def compute_action_ref(
    agent_id: str,
    action_type: str,
    scope: str,
    timestamp: str,
) -> str:
    """Derive action_ref from the four canonical preimage fields.

    Canonical derivation (JCS RFC 8785 + SHA-256):

    1. Build a dict of the four fields.
    2. Serialize with JCS: keys in Unicode code-point order, no whitespace, UTF-8.
    3. Return ``SHA-256(canonical_bytes)`` as 64 lowercase hex characters.

    Args:
        agent_id:    Stable agent identifier (DID, username, or opaque string).
        action_type: Verb that describes the action (e.g. ``"file:write"``).
        scope:       Resource or context the action targets (may be empty string).
        timestamp:   RFC 3339 UTC with exactly 3 ms digits: ``"2026-05-15T10:00:00.123Z"``.
                     Use :func:`_format_timestamp` to produce this from a datetime object.

    Returns:
        64-character lowercase hex SHA-256 digest.

    Raises:
        ValueError: If ``timestamp`` does not match the required RFC 3339 format.

    Example::

        ref = compute_action_ref(
            agent_id="nobulex-gogani",
            action_type="payment.send",
            scope="payment:usdc:50",
            timestamp="2025-05-18T10:00:00.000Z",
        )
        # "31ddbd9f89f0e54700744addc7fa23f41518cf8c9d63d206e6da5cc3669defdd"
    """
    if not _TS_RE.match(timestamp):
        raise ValueError(
            f"timestamp must be RFC 3339 UTC with 3-digit ms (e.g. '2026-05-15T10:00:00.123Z'), got: {timestamp!r}"
        )
    canonical = _jcs_encode({
        "action_type": action_type,
        "agent_id": agent_id,
        "scope": scope,
        "timestamp": timestamp,
    })
    return hashlib.sha256(canonical).hexdigest()


# ---------------------------------------------------------------------------
# AnchorReceipt — what the backend returns after recording a trail
# ---------------------------------------------------------------------------

class AnchorReceipt:
    """Immutable result of a Mycelium trail anchoring attempt.

    An ``AnchorReceipt`` is returned by :meth:`MyceliumBackend.anchor` for every
    call, whether or not the HTTP submission succeeded.  Callers should always
    check :attr:`anchored` before trusting :attr:`trail_id` or :attr:`tx_hash`.

    Independent verification — without trusting this object — is possible because
    :attr:`preimage` contains the four fields used to derive :attr:`action_ref`:

    .. code-block:: python

        recomputed = compute_action_ref(
            r.preimage["agent_id"],
            r.preimage["action_type"],
            r.preimage["scope"],
            r.preimage["timestamp"],
        )
        assert recomputed == r.action_ref

    Attributes:
        anchored:      ``True`` if the trail record was accepted by Mycelium.
        action_ref:    SHA-256 hex digest of the JCS-canonical preimage (64 chars).
                       Deterministic — recomputable from :attr:`preimage` fields.
        trail_id:      UUID assigned by Mycelium; ``None`` on failure.
        trail_status:  ``"committed"`` | ``"pending"`` | ``"failed"``.
        tx_hash:       On-chain anchor transaction hash; ``None`` until committed.
        verify_url:    Public URL to verify this trail without authentication.
        preimage:      Dict with keys ``agent_id``, ``action_type``, ``scope``,
                       ``timestamp`` — the four canonical fields.
        error:         Error message string on failure; ``None`` on success.
        evaluation_ms: Wall-clock time for the backend HTTP call (milliseconds).
    """

    def __init__(
        self,
        anchored: bool,
        action_ref: str,
        trail_id: Optional[str] = None,
        trail_status: str = "failed",
        tx_hash: Optional[str] = None,
        verify_url: Optional[str] = None,
        preimage: Optional[dict[str, str]] = None,
        error: Optional[str] = None,
        evaluation_ms: float = 0.0,
    ) -> None:
        self.anchored = anchored
        self.action_ref = action_ref
        self.trail_id = trail_id
        self.trail_status = trail_status
        self.tx_hash = tx_hash
        self.verify_url = verify_url
        self.preimage = preimage or {}
        self.error = error
        self.evaluation_ms = evaluation_ms

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"AnchorReceipt(anchored={self.anchored}, "
            f"trail_status={self.trail_status!r}, "
            f"action_ref={self.action_ref[:16]}...)"
        )


# ---------------------------------------------------------------------------
# MyceliumBackend
# ---------------------------------------------------------------------------

class MyceliumBackend:
    """AGT evidence backend that anchors actions as Mycelium TrailRecords.

    Implements the ``EvidenceAnchor`` protocol — exposes :attr:`name` and
    :meth:`anchor` — so it can be registered with
    ``EvidenceCollector.add_backend()`` without any changes to AGT core.

    Every action produces a tamper-evident TrailRecord with:

    - A deterministic ``action_ref`` (JCS RFC 8785 + SHA-256) any party can
      independently recompute from the four preimage fields.
    - An on-chain anchor (``tx_hash``) on Base mainnet or Arbitrum One once
      the trail transitions to ``COMMITTED``.

    Trail states (per guarantee-model spec):

    - ``committed`` — anchored on-chain. Independently verifiable via ``tx_hash``.
    - ``pending``   — anchor in progress. ``tx_hash`` present or ``None`` (degraded).
    - ``failed``    — terminal. No anchor produced.

    Usage::

        from agent_os.audit import EvidenceCollector
        from mycelium_agt import MyceliumBackend

        collector = EvidenceCollector()
        collector.add_backend(MyceliumBackend(agent_id="my-agent-001"))
        receipt = collector.record({"action_type": "file:write", "scope": "audit"})

    Args:
        agent_id:        Stable agent identifier (DID, username, or opaque string).
        mycelium_url:    Mycelium API base URL. Defaults to the public endpoint.
        service:         Service label for the TrailRecord (default: ``"agentmesh"``).
        timeout_seconds: HTTP timeout per request (seconds).
    """

    def __init__(
        self,
        agent_id: str,
        mycelium_url: str = _DEFAULT_MYCELIUM_URL,
        service: str = "agentmesh",
        timeout_seconds: float = 10.0,
    ) -> None:
        self._agent_id = agent_id
        self._base_url = mycelium_url.rstrip("/")
        self._service = service
        self._timeout = timeout_seconds

    @property
    def name(self) -> str:
        return "mycelium"

    def anchor(self, context: dict[str, Any]) -> AnchorReceipt:
        """Anchor *context* as a Mycelium TrailRecord.

        Computes action_ref from context fields, submits to the Mycelium API,
        and returns an AnchorReceipt with full preimage for independent
        verification.
        """
        start = datetime.datetime.now(datetime.timezone.utc)
        action_type = str(context.get("action_type", "unknown"))
        scope = str(context.get("scope", ""))
        ts = _format_timestamp(start)
        action_ref = compute_action_ref(self._agent_id, action_type, scope, ts)
        preimage = {
            "agent_id": self._agent_id,
            "action_type": action_type,
            "scope": scope,
            "timestamp": ts,
        }
        verify_url = (
            f"{self._base_url}/trails/verify"
            f"?agent_id={urllib.parse.quote(self._agent_id)}"
            f"&action_ref={action_ref}"
        )

        try:
            receipt = self._submit_trail(action_ref, action_type, scope, ts)
            elapsed = (
                datetime.datetime.now(datetime.timezone.utc) - start
            ).total_seconds() * 1000
            return AnchorReceipt(
                anchored=receipt.get("trail_id") is not None,
                action_ref=action_ref,
                trail_id=receipt.get("trail_id"),
                trail_status=receipt.get("trail_status", "pending"),
                tx_hash=receipt.get("tx_hash"),
                verify_url=verify_url,
                preimage=preimage,
                evaluation_ms=elapsed,
            )
        except Exception as exc:
            elapsed = (
                datetime.datetime.now(datetime.timezone.utc) - start
            ).total_seconds() * 1000
            logger.error("Mycelium anchoring failed: %s", exc)
            return AnchorReceipt(
                anchored=False,
                action_ref=action_ref,
                trail_status="failed",
                verify_url=verify_url,
                preimage=preimage,
                error=str(exc),
                evaluation_ms=elapsed,
            )

    def verify(self, action_ref: str) -> dict[str, Any]:
        """Query the Mycelium verify endpoint for a known action_ref.

        Returns the raw API response. ``verified: true`` means the trail
        exists; ``tx_hash`` is the on-chain anchor when present.

        Example::

            result = backend.verify("31ddbd9f...")
            # {"verified": true, "trail_status": "committed", "tx_hash": "0x..."}
        """
        url = (
            f"{self._base_url}/trails/verify"
            f"?agent_id={urllib.parse.quote(self._agent_id)}"
            f"&action_ref={action_ref}"
        )
        req = urllib.request.Request(url, method="GET")  # noqa: S310
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return {"verified": False, "error": f"HTTP {exc.code}"}
        except Exception as exc:
            return {"verified": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _submit_trail(
        self,
        action_ref: str,
        action_type: str,
        scope: str,
        timestamp: str,
    ) -> dict[str, Any]:
        """POST a NEXUS-compatible receipt to /nexus/trail."""
        payload = json.dumps({
            "action_ref": action_ref,
            "service": self._service,
            "hash_algo": "sha256",
            "preimage_format": "jcs-rfc8785",
            "preimage": {
                "agent_id": self._agent_id,
                "action_type": action_type,
                "scope": scope,
                "ts": timestamp,
            },
        }).encode("utf-8")

        url = f"{self._base_url}/nexus/trail"
        req = urllib.request.Request(  # noqa: S310
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))
