# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Authentication helpers for the Nexus Cloud Board API."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from hashlib import sha256 as _sha256
from hmac import compare_digest as _constant_time_eq

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = logging.getLogger(__name__)

bearer_scheme = HTTPBearer(auto_error=False)
BEARER_AUTH = Depends(bearer_scheme)

ADMIN_TOKENS_ENV = "NEXUS_CLOUD_BOARD_ADMIN_TOKENS"
ADMIN_TOKEN_ENV = "NEXUS_CLOUD_BOARD_ADMIN_TOKEN"
AGENT_TOKENS_ENV = "NEXUS_CLOUD_BOARD_AGENT_TOKENS"

# Reject overlong bearer tokens before the SHA-256 hash so that an attacker
# cannot force expensive hashing work with multi-megabyte tokens. 256 bytes
# is far above any reasonable opaque token / JWT in practice.
MAX_BEARER_TOKEN_BYTES = 256


@dataclass(frozen=True)
class AuthPrincipal:
    """Authenticated Cloud Board caller."""

    role: str
    agent_did: str | None = None

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


def require_admin(
    credentials: HTTPAuthorizationCredentials | None = BEARER_AUTH,
) -> AuthPrincipal:
    """Require an administrator bearer token.

    Returns ``401`` for **any** non-admin credential — including valid
    agent tokens — so that the endpoint cannot be used as a binary oracle
    to classify an exfiltrated token as a valid agent token.
    """
    _ensure_admin_auth_configured()
    token = _extract_bearer_token(credentials)

    if _matches_any_token(token, _admin_tokens()):
        return AuthPrincipal(role="admin")

    raise _invalid_credentials()


def require_agent(
    credentials: HTTPAuthorizationCredentials | None = BEARER_AUTH,
) -> AuthPrincipal:
    """Require an agent-scoped bearer token, with administrator fallback."""
    _ensure_agent_auth_configured()
    token = _extract_bearer_token(credentials)

    if _matches_any_token(token, _admin_tokens()):
        return AuthPrincipal(role="admin")

    agent_did = _agent_did_for_token(token)
    if agent_did is not None:
        return AuthPrincipal(role="agent", agent_did=agent_did)

    raise _invalid_credentials()


ADMIN_AUTH = Depends(require_admin)
AGENT_AUTH = Depends(require_agent)


def try_authenticate(
    credentials: HTTPAuthorizationCredentials | None,
) -> AuthPrincipal | None:
    """Best-effort authentication for endpoints that allow anonymous access.

    Returns an ``AuthPrincipal`` when valid credentials are supplied, ``None``
    when no credentials are supplied, and raises ``401`` when credentials are
    supplied but invalid (so we never silently downgrade bad tokens to
    anonymous).
    """
    if credentials is None:
        return None
    if (credentials.scheme or "").lower() != "bearer" or not credentials.credentials:
        raise _invalid_credentials()

    token = credentials.credentials
    if _admin_tokens() and _matches_any_token(token, _admin_tokens()):
        return AuthPrincipal(role="admin")
    if _agent_token_entries():
        agent_did = _agent_did_for_token(token)
        if agent_did is not None:
            return AuthPrincipal(role="agent", agent_did=agent_did)

    raise _invalid_credentials()


def authorize_agent(agent_did: str, principal: AuthPrincipal) -> None:
    """Authorize an authenticated principal for a specific agent DID."""
    if principal.is_admin or principal.agent_did == agent_did:
        return

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={
            "error": "FORBIDDEN",
            "message": f"Token is not authorized for agent {agent_did}",
        },
    )


def _ensure_admin_auth_configured() -> None:
    if not _admin_tokens():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "AUTH_NOT_CONFIGURED",
                "message": f"Set {ADMIN_TOKENS_ENV} before using administrator endpoints",
            },
        )


def _ensure_agent_auth_configured() -> None:
    if _admin_tokens() or _agent_token_entries():
        return

    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={
            "error": "AUTH_NOT_CONFIGURED",
            "message": (
                f"Set {ADMIN_TOKENS_ENV} or {AGENT_TOKENS_ENV} before using protected "
                "Cloud Board endpoints"
            ),
        },
    )


def _extract_bearer_token(
    credentials: HTTPAuthorizationCredentials | None,
) -> str:
    if credentials is None or not credentials.credentials:
        raise _missing_credentials()

    if credentials.scheme.lower() != "bearer":
        raise _missing_credentials()

    token = credentials.credentials
    if len(token.encode("utf-8")) > MAX_BEARER_TOKEN_BYTES:
        # Refuse before hashing to avoid CPU DoS via giant tokens. Use 401
        # (same shape as any other invalid-token response) to avoid creating
        # an oracle for "you guessed an admin token with this length".
        raise _invalid_credentials()
    return token


def _missing_credentials() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": "UNAUTHENTICATED", "message": "Bearer token required"},
        headers={"WWW-Authenticate": "Bearer"},
    )


def _invalid_credentials() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": "INVALID_TOKEN", "message": "Bearer token is invalid"},
        headers={"WWW-Authenticate": "Bearer"},
    )


def _admin_tokens() -> list[str]:
    values = _split_env_tokens(os.environ.get(ADMIN_TOKENS_ENV, ""))
    legacy_value = os.environ.get(ADMIN_TOKEN_ENV, "").strip()
    if legacy_value:
        values.append(legacy_value)
    return values


def _agent_did_for_token(token: str) -> str | None:
    for agent_did, expected_token in _agent_token_entries():
        if _token_matches(token, expected_token):
            return agent_did
    return None


def _agent_token_entries() -> list[tuple[str, str]]:
    raw_env = os.environ.get(AGENT_TOKENS_ENV, "")
    cached = _AGENT_TOKEN_CACHE.get(raw_env)
    if cached is not None:
        return cached

    raw_entries = _split_env_tokens(raw_env)
    entries: list[tuple[str, str]] = []

    for entry in raw_entries:
        agent_did, separator, token = entry.partition("=")
        agent_did = agent_did.strip()
        token = token.strip()
        # A single malformed entry must not 503 the entire authenticated
        # surface (including the admin plane). Skip the entry with a
        # warning so misconfiguration degrades gracefully rather than DoSing
        # every authenticated request.
        if separator != "=" or not agent_did or not token:
            logger.warning(
                "Skipping malformed %s entry (expected '<did>=<token>')",
                AGENT_TOKENS_ENV,
            )
            continue
        if not agent_did.startswith("did:nexus:"):
            logger.warning(
                "Skipping %s entry with non-did:nexus DID: %r",
                AGENT_TOKENS_ENV,
                agent_did,
            )
            continue
        if len(token.encode("utf-8")) > MAX_BEARER_TOKEN_BYTES:
            logger.warning(
                "Skipping %s entry for %s: token exceeds %d-byte cap",
                AGENT_TOKENS_ENV,
                agent_did,
                MAX_BEARER_TOKEN_BYTES,
            )
            continue
        entries.append((agent_did, token))

    _AGENT_TOKEN_CACHE.clear()
    _AGENT_TOKEN_CACHE[raw_env] = entries
    return entries


def _matches_any_token(token: str, expected_tokens: list[str]) -> bool:
    return any(_token_matches(token, expected_token) for expected_token in expected_tokens)


def _token_matches(token: str, expected_token: str) -> bool:
    token_digest = _sha256(token.encode("utf-8")).digest()
    expected_digest = _sha256(expected_token.encode("utf-8")).digest()
    return _constant_time_eq(token_digest, expected_digest)


def _split_env_tokens(value: str) -> list[str]:
    # NOTE: Tokens that themselves contain ',' cannot be expressed in this
    # env format because comma is the separator. Operators who need such
    # tokens must rotate them; values containing commas are silently
    # truncated by ``split(",")``. This limitation is documented in the
    # service README under the security boundary section.
    return [item.strip() for item in value.split(",") if item.strip()]


# Module-level cache for parsed agent-token entries keyed by the raw env
# string. The cache avoids re-parsing the env on every authenticated request
# (which both adds latency and previously turned a single misconfiguration
# into a per-request 503). The cache key is the raw env value, so tests and
# operators changing the env are picked up on the next call.
_AGENT_TOKEN_CACHE: dict[str, list[tuple[str, str]]] = {}
