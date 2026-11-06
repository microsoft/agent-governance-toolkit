# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Server identity discovery and verification for the trust-gated MCP client.

This module implements Phase 1 of
https://github.com/microsoft/agent-governance-toolkit/issues/4528:
fetching a server's identity document, binding it to a registry-issued
identity, and proving possession of the private key. Every failure mode is
fail-closed: any unsuccessful step yields ``verified=False`` with a reason,
never an exception the caller could mistake for success.

Protocol decision (``/.well-known/agent.json``)
-----------------------------------------------
The discovery endpoint mirrors the existing AI Card convention
(``/.well-known/ai-card.json``, see
:mod:`agentmesh.integrations.ai_card.discovery`), which keeps one
well-known discovery pattern across integrations instead of inventing a
second one. The document schema is intentionally minimal:

.. code-block:: json

    {
        "did": "did:mesh:<hex>",
        "public_key": "<base64 Ed25519 public key>",
        "key_id": "key-<hex>",
        "issued_at": "2026-11-06T18:00:00+00:00",
        "challenge_endpoint": "https://host/.well-known/agent-challenge",
        "signature": "<base64 Ed25519 signature>"
    }

Only ``did`` and ``public_key`` are required. ``signature`` covers the
canonical JSON encoding (sorted keys, no insignificant whitespace,
version-prefixed) of ``did``, ``public_key``, ``key_id``, ``issued_at``,
and ``challenge_endpoint``. ``challenge_endpoint`` is optional; when
present it must be same-origin HTTPS and enables the interactive
challenge-response path.

Trust model
-----------
``did:mesh`` identifiers are random, not key-derived (see
:meth:`agentmesh.identity.agent_id.AgentDID.generate`), so a DID is not
self-certifying. A caller-supplied public key can never authenticate a
server on its own. Verification keys MUST be resolved from a trusted
:class:`~agentmesh.identity.agent_id.IdentityRegistry` keyed by DID, and
the document-supplied key MUST equal the registry key. See
:mod:`agentmesh.integrations.request_auth` and ``AGENTS.md`` ("Never
accept public keys without proof-of-possession").
"""

from __future__ import annotations

import base64
import ipaddress
import json
import logging
import secrets
import socket
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Optional
from urllib.parse import urlparse

from agentmesh.identity.agent_id import AgentDID, IdentityRegistry
from agentmesh.integrations.request_auth import (
    InMemoryReplayCache,
    ReplayCacheFull,
    decode_nonce,
    decode_public_key,
    decode_signature,
    parse_timestamp,
    replay_key,
    sanitize_did,
)

logger = logging.getLogger(__name__)

#: Well-known path serving the server identity document.
SERVER_IDENTITY_PATH = "/.well-known/agent.json"

#: Version prefix for signed identity documents. Part of the signed bytes so
#: a signature minted for another protocol version cannot be transplanted.
DOCUMENT_SIGNATURE_VERSION = "agentmesh-server-identity-v1"

#: Version prefix for interactive challenge responses. Kept distinct from
#: the document version so a document signature can never satisfy a
#: challenge and vice versa.
CHALLENGE_SIGNATURE_VERSION = "agentmesh-server-challenge-v1"

#: Default network budget for a single discovery fetch, in seconds.
DEFAULT_TIMEOUT_SECONDS = 5.0

#: Default cap on an identity document response body, in bytes. A DID plus
#: a key plus a signature is well under one kilobyte; anything larger is
#: either misconfiguration or abuse.
DEFAULT_MAX_BYTES = 65_536

#: Default maximum age of a signed identity document, in seconds. Bounds
#: how long a captured document can be replayed by a host that does not
#: hold the private key.
DEFAULT_MAX_DOC_AGE_SECONDS = 300

#: Default freshness window for an interactive challenge response.
DEFAULT_CHALLENGE_WINDOW_SECONDS = 60

#: Hosts that must never be fetched, even over HTTPS. Extends the
#: loopback set already enforced by ``TrustGatedMCPClient.connect`` with
#: cloud metadata endpoints. Literal private IPs are rejected separately
#: via :mod:`ipaddress`.
_BLOCKED_HOSTS = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        "169.254.169.254",
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
    }
)


@dataclass(frozen=True)
class ServerIdentityDocument:
    """A parsed ``agent.json`` identity document (untrusted until verified)."""

    did: str
    public_key: str
    key_id: Optional[str] = None
    issued_at: Optional[str] = None
    challenge_endpoint: Optional[str] = None
    signature: Optional[str] = None


@dataclass(frozen=True)
class ServerVerificationResult:
    """Outcome of server identity verification. Fail-closed by construction."""

    verified: bool
    did: Optional[str] = None
    reason: str = "not verified"
    # ``detail`` carries operator-safe context (DIDs, hostnames, reason
    # codes). It MUST NOT contain key material, tokens, or document bodies.
    detail: str = ""


@dataclass
class DiscoveryConfig:
    """Network and freshness policy for server identity discovery."""

    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_bytes: int = DEFAULT_MAX_BYTES
    require_https: bool = True
    max_doc_age_seconds: int = DEFAULT_MAX_DOC_AGE_SECONDS
    challenge_window_seconds: int = DEFAULT_CHALLENGE_WINDOW_SECONDS
    # Upper bound on DNS answers inspected per lookup. Lookups resolving to
    # more addresses are rejected rather than partially evaluated.
    max_dns_answers: int = 16


def build_document_payload(document: ServerIdentityDocument) -> bytes:
    """Build the canonical bytes covered by a document signature.

    Canonical JSON (sorted keys, no insignificant whitespace,
    ASCII-escaped by :mod:`json`) with a version prefix, so no field value
    can be shifted into a neighboring field the way delimiter-joined
    strings allow (cf. issues #3507 and #4199).
    """
    envelope = {
        "challenge_endpoint": document.challenge_endpoint or "",
        "did": document.did,
        "issued_at": document.issued_at or "",
        "key_id": document.key_id or "",
        "public_key": document.public_key,
    }
    canonical = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
    return f"{DOCUMENT_SIGNATURE_VERSION}\n{canonical}".encode("utf-8")


def build_challenge_payload(
    *,
    server_did: str,
    client_did: str,
    client_nonce: str,
    timestamp: str,
    audience: str,
) -> bytes:
    """Build the canonical bytes a server signs in a challenge response.

    Binds the server identity, the client-supplied nonce, freshness, and
    the intended audience, so a captured response cannot be replayed
    against a different client, server, or service.
    """
    envelope = {
        "audience": audience,
        "client_did": client_did,
        "client_nonce": client_nonce,
        "server_did": server_did,
        "timestamp": timestamp,
    }
    canonical = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
    return f"{CHALLENGE_SIGNATURE_VERSION}\n{canonical}".encode("utf-8")


def parse_server_document(raw: bytes | str) -> ServerIdentityDocument | None:
    """Parse and structurally validate an identity document.

    Returns ``None`` for any malformed input: non-JSON bodies, non-object
    JSON, missing ``did``/``public_key``, implausible DIDs, or malformed
    keys. Cryptographic checks happen in :func:`verify_server_document`;
    this function only establishes that the document is well-formed.
    """
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
    else:
        text = raw
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None

    did = data.get("did")
    public_key = data.get("public_key")
    if not isinstance(did, str) or sanitize_did(did) is None:
        return None
    try:
        AgentDID.from_string(did)
    except ValueError:
        return None
    if not isinstance(public_key, str) or decode_public_key(public_key) is None:
        return None

    def _optional_str(name: str) -> Optional[str]:
        value = data.get(name)
        return value if isinstance(value, str) and value else None

    challenge_endpoint = _optional_str("challenge_endpoint")
    if challenge_endpoint is not None and len(challenge_endpoint) > 2048:
        return None
    return ServerIdentityDocument(
        did=did,
        public_key=public_key,
        key_id=_optional_str("key_id"),
        issued_at=_optional_str("issued_at"),
        challenge_endpoint=challenge_endpoint,
        signature=_optional_str("signature"),
    )


def _is_safe_literal_ip(host: str) -> bool:
    """Return whether ``host`` is a literal IP safe to contact.

    Non-literal hostnames return ``True`` here: they are resolved and
    re-checked by :func:`resolve_and_check_host`. Literal IPs must be
    globally routable — loopback, private, reserved, multicast, and
    unspecified addresses are rejected.
    """
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return True
    return address.is_global


def resolve_and_check_host(host: str, port: int, max_answers: int) -> bool:
    """Resolve ``host`` and require every answer to be globally routable.

    This runs before the HTTP fetch so DNS names pointing at internal
    infrastructure fail closed instead of being fetched. It cannot fully
    prevent DNS rebinding between resolution and connection (TOCTOU); the
    signature checks in :func:`verify_server_document` are the binding
    defense, since rebinding still cannot forge a registry-signed
    document. Resolution failures fail closed.
    """
    if not host or max_answers <= 0:
        return False
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError, UnicodeError):
        return False
    if not answers or len(answers) > max_answers:
        return False
    for answer in answers:
        sockaddr = answer[4]
        if not sockaddr:
            return False
        try:
            if not ipaddress.ip_address(sockaddr[0]).is_global:
                return False
        except ValueError:
            return False
    return True


def discovery_url(server_url: str, config: DiscoveryConfig) -> str | None:
    """Build the ``agent.json`` URL for ``server_url``, or ``None``.

    Rejects URLs whose scheme, host, or resolved addresses are unsafe to
    fetch: wrong scheme, blocked hosts, non-global literal IPs, or DNS
    answers that are not all globally routable. Redirects are never
    followed by the fetcher, so the returned URL is the only one fetched.
    """
    try:
        parsed = urlparse(server_url)
    except (ValueError, TypeError):
        return None
    if config.require_https and parsed.scheme != "https":
        return None
    if parsed.scheme not in ("http", "https"):
        return None
    host = (parsed.hostname or "").lower()
    if not host or host in _BLOCKED_HOSTS:
        return None
    if not _is_safe_literal_ip(host):
        return None
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not resolve_and_check_host(host, port, config.max_dns_answers):
        return None
    return f"{parsed.scheme}://{parsed.netloc}{SERVER_IDENTITY_PATH}"


async def afetch_server_document(
    server_url: str,
    config: DiscoveryConfig | None = None,
    transport: Any = None,
) -> bytes | None:
    """Fetch the raw ``agent.json`` document for ``server_url``.

    Fail-closed: returns ``None`` when the URL is unsafe, ``httpx`` is
    unavailable, the request times out, the status is not 200, the
    content type is not JSON, or the body exceeds ``max_bytes``.
    Redirects are never followed — a server that redirects discovery is
    treated as unverifiable rather than chased across origins.

    ``transport`` accepts an ``httpx.AsyncBaseTransport`` for tests; it is
    typed as :data:`typing.Any` so importing this module never requires
    ``httpx`` at import time.
    """
    cfg = config or DiscoveryConfig()
    target = discovery_url(server_url, cfg)
    if target is None:
        return None
    try:
        import httpx
    except ImportError:
        logger.warning("Server discovery unavailable: httpx is not installed")
        return None
    try:
        timeout = httpx.Timeout(cfg.timeout_seconds)
        async with httpx.AsyncClient(
            transport=transport,
            timeout=timeout,
            follow_redirects=False,
            max_redirects=0,
        ) as client:
            response = await client.get(target, headers={"Accept": "application/json"})
    except Exception:  # noqa: BLE001 — any transport failure fails closed
        logger.warning("Server identity fetch failed for %s", urlparse(server_url).hostname)
        return None
    if response.status_code != 200:
        return None
    content_type = response.headers.get("content-type", "").split(";")[0].strip()
    if content_type not in ("application/json", "application/agent-json"):
        return None
    body = response.content
    if len(body) > cfg.max_bytes:
        return None
    return body


def verify_server_document(
    document: ServerIdentityDocument,
    registry: IdentityRegistry,
    config: DiscoveryConfig | None = None,
    now: datetime | None = None,
) -> ServerVerificationResult:
    """Verify a parsed identity document against the trusted registry.

    Checks in order, all fail-closed:

    1. The DID is registered.
    2. The registry identity is active (not revoked/suspended/expired).
    3. The registry identity is trusted.
    4. The document public key equals the registry public key — the
       document key is never trusted on its own (``did:mesh`` is not
       self-certifying).
    5. The document carries a signature verifiable with the registry key.
    6. The document ``issued_at`` timestamp is present and within
       ``max_doc_age_seconds``, bounding replay of captured documents.

    ``now`` is a seam for deterministic tests; production callers leave it
    ``None``. Only the DID and a reason code are returned — never key
    material or document bodies.
    """
    cfg = config or DiscoveryConfig()
    moment = now or datetime.now(UTC)

    identity = registry.get(document.did)
    if identity is None:
        return ServerVerificationResult(False, document.did, "unknown-did")
    if not identity.is_active():
        return ServerVerificationResult(False, document.did, "identity-inactive")
    if not registry.is_trusted(document.did):
        return ServerVerificationResult(False, document.did, "identity-untrusted")
    if document.public_key != identity.public_key:
        return ServerVerificationResult(False, document.did, "key-mismatch")
    if document.key_id and document.key_id != identity.verification_key_id:
        return ServerVerificationResult(False, document.did, "key-id-mismatch")
    if not document.signature or decode_signature(document.signature) is None:
        return ServerVerificationResult(False, document.did, "missing-signature")
    issued = parse_timestamp(
        document.issued_at or "", window_seconds=cfg.max_doc_age_seconds, now=moment
    )
    if issued is None:
        return ServerVerificationResult(False, document.did, "stale-or-missing-issued-at")
    payload = build_document_payload(document)
    if not identity.verify_signature(payload, document.signature):
        return ServerVerificationResult(False, document.did, "bad-signature")
    return ServerVerificationResult(True, document.did, "verified")


@dataclass(frozen=True)
class ServerChallenge:
    """A client-minted challenge for interactive proof-of-possession."""

    server_did: str
    client_did: str
    # base64url-encoded 32-byte nonce, minted fresh per challenge.
    client_nonce: str
    timestamp: str
    audience: str


@dataclass(frozen=True)
class ChallengeResponse:
    """A server's answer to :class:`ServerChallenge` (untrusted until verified)."""

    server_did: str
    client_nonce: str
    timestamp: str
    signature: str


def mint_challenge(server_did: str, client_did: str, audience: str) -> ServerChallenge:
    """Mint a fresh challenge binding server, client, nonce, and audience."""
    nonce_bytes = secrets.token_bytes(32)
    nonce = base64.urlsafe_b64encode(nonce_bytes).rstrip(b"=").decode("ascii")
    return ServerChallenge(
        server_did=server_did,
        client_did=client_did,
        client_nonce=nonce,
        timestamp=datetime.now(UTC).isoformat(),
        audience=audience,
    )


def verify_challenge_response(
    challenge: ServerChallenge,
    response: ChallengeResponse,
    registry: IdentityRegistry,
    replay_cache: InMemoryReplayCache,
    config: DiscoveryConfig | None = None,
    now: datetime | None = None,
) -> ServerVerificationResult:
    """Verify an interactive challenge response. All fail-closed.

    Checks: the response answers this challenge (DID and nonce echo), the
    response timestamp is within ``challenge_window_seconds``, the nonce
    decodes with sufficient entropy, the nonce was never seen before for
    this (server, audience) pair (single-use via :func:`replay_key`), the
    server is registered/active/trusted, and the Ed25519 signature over
    the canonical envelope verifies with the registry key.
    """
    cfg = config or DiscoveryConfig()
    moment = now or datetime.now(UTC)

    if response.server_did != challenge.server_did:
        return ServerVerificationResult(False, challenge.server_did, "challenge-did-mismatch")
    if not response.client_nonce or response.client_nonce != challenge.client_nonce:
        return ServerVerificationResult(False, challenge.server_did, "challenge-nonce-mismatch")
    nonce_bytes = decode_nonce(response.client_nonce)
    if nonce_bytes is None:
        return ServerVerificationResult(False, challenge.server_did, "challenge-bad-nonce")
    answered_at = parse_timestamp(
        response.timestamp, window_seconds=cfg.challenge_window_seconds, now=moment
    )
    if answered_at is None:
        return ServerVerificationResult(False, challenge.server_did, "challenge-stale")

    identity = registry.get(response.server_did)
    if identity is None:
        return ServerVerificationResult(False, challenge.server_did, "unknown-did")
    if not identity.is_active():
        return ServerVerificationResult(False, challenge.server_did, "identity-inactive")
    if not registry.is_trusted(response.server_did):
        return ServerVerificationResult(False, challenge.server_did, "identity-untrusted")

    try:
        first_use = replay_cache.add(
            replay_key(response.server_did, challenge.audience, nonce_bytes),
            cfg.challenge_window_seconds,
        )
    except ReplayCacheFull:
        return ServerVerificationResult(False, challenge.server_did, "replay-cache-full")
    if not first_use:
        return ServerVerificationResult(False, challenge.server_did, "replay-detected")

    payload = build_challenge_payload(
        server_did=response.server_did,
        client_did=challenge.client_did,
        client_nonce=response.client_nonce,
        timestamp=response.timestamp,
        audience=challenge.audience,
    )
    if decode_signature(response.signature) is None:
        return ServerVerificationResult(False, challenge.server_did, "missing-signature")
    if not identity.verify_signature(payload, response.signature):
        return ServerVerificationResult(False, challenge.server_did, "bad-signature")
    return ServerVerificationResult(True, response.server_did, "verified")


def _challenge_endpoint_for(server_url: str, document: ServerIdentityDocument) -> str | None:
    """Return the advertised challenge endpoint if it is same-origin HTTPS."""
    if not document.challenge_endpoint:
        return None
    try:
        server = urlparse(server_url)
        endpoint = urlparse(document.challenge_endpoint)
    except (ValueError, TypeError):
        return None
    if endpoint.scheme != "https" or server.scheme != "https":
        return None
    if (endpoint.hostname or "").lower() != (server.hostname or "").lower():
        return None
    server_port = server.port or 443
    if (endpoint.port or 443) != server_port:
        return None
    return document.challenge_endpoint


async def verify_server(
    server_url: str,
    registry: IdentityRegistry,
    client_did: str,
    config: DiscoveryConfig | None = None,
    replay_cache: InMemoryReplayCache | None = None,
    transport: Any = None,
    now: datetime | None = None,
) -> ServerVerificationResult:
    """Run the full Phase 1 verification pipeline for ``server_url``.

    Fetch → parse → registry-bind → signature → freshness, then the
    interactive challenge when the document advertises a same-origin
    HTTPS challenge endpoint. Any step failing yields
    ``verified=False``; nothing raises for adversary-controlled input.
    """
    cfg = config or DiscoveryConfig()
    raw = await afetch_server_document(server_url, cfg, transport)
    if raw is None:
        return ServerVerificationResult(False, None, "discovery-failed")
    document = parse_server_document(raw)
    if document is None:
        return ServerVerificationResult(False, None, "malformed-document")
    result = verify_server_document(document, registry, cfg, now)
    if not result.verified:
        return result

    endpoint = _challenge_endpoint_for(server_url, document)
    if endpoint is None:
        # No challenge endpoint advertised: the freshness-bounded document
        # signature is the possession evidence. Only the key holder can
        # mint a fresh document, and the age window bounds replay.
        return result

    cache = replay_cache or InMemoryReplayCache()
    challenge = mint_challenge(document.did, client_did, server_url)
    answered = await _post_challenge(endpoint, challenge, cfg, transport)
    if answered is None:
        return ServerVerificationResult(False, document.did, "challenge-transport-failed")
    return verify_challenge_response(challenge, answered, registry, cache, cfg, now)


async def _post_challenge(
    endpoint: str,
    challenge: ServerChallenge,
    config: DiscoveryConfig,
    transport: Any = None,
) -> ChallengeResponse | None:
    """POST a challenge and parse the response. ``None`` on any failure."""
    try:
        import httpx
    except ImportError:
        return None
    body = json.dumps(
        {
            "client_did": challenge.client_did,
            "client_nonce": challenge.client_nonce,
            "server_did": challenge.server_did,
            "timestamp": challenge.timestamp,
        }
    ).encode("utf-8")
    try:
        timeout = httpx.Timeout(config.timeout_seconds)
        async with httpx.AsyncClient(
            transport=transport,
            timeout=timeout,
            follow_redirects=False,
            max_redirects=0,
        ) as client:
            response = await client.post(
                endpoint,
                content=body,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
            )
    except Exception:  # noqa: BLE001 — any transport failure fails closed
        return None
    if response.status_code != 200 or len(response.content) > config.max_bytes:
        return None
    try:
        data = json.loads(response.content.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    server_did = data.get("server_did")
    client_nonce = data.get("client_nonce")
    timestamp = data.get("timestamp")
    signature = data.get("signature")
    if not all(isinstance(v, str) and v for v in (server_did, client_nonce, timestamp, signature)):
        return None
    return ChallengeResponse(
        server_did=server_did,
        client_nonce=client_nonce,
        timestamp=timestamp,
        signature=signature,
    )


__all__ = [
    "CHALLENGE_SIGNATURE_VERSION",
    "DEFAULT_CHALLENGE_WINDOW_SECONDS",
    "DEFAULT_MAX_BYTES",
    "DEFAULT_MAX_DOC_AGE_SECONDS",
    "DEFAULT_TIMEOUT_SECONDS",
    "DOCUMENT_SIGNATURE_VERSION",
    "SERVER_IDENTITY_PATH",
    "ChallengeResponse",
    "DiscoveryConfig",
    "ServerChallenge",
    "ServerIdentityDocument",
    "ServerVerificationResult",
    "afetch_server_document",
    "build_challenge_payload",
    "build_document_payload",
    "discovery_url",
    "mint_challenge",
    "parse_server_document",
    "replay_key",
    "resolve_and_check_host",
    "verify_challenge_response",
    "verify_server",
    "verify_server_document",
]
