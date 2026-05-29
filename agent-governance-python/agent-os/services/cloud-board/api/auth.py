# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Authentication helpers for the Nexus Cloud Board API."""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

bearer_scheme = HTTPBearer(auto_error=False)
BEARER_AUTH = Depends(bearer_scheme)

ADMIN_TOKENS_ENV = "NEXUS_CLOUD_BOARD_ADMIN_TOKENS"
ADMIN_TOKEN_ENV = "NEXUS_CLOUD_BOARD_ADMIN_TOKEN"
AGENT_TOKENS_ENV = "NEXUS_CLOUD_BOARD_AGENT_TOKENS"


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
    """Require an administrator bearer token."""
    _ensure_admin_auth_configured()
    token = _extract_bearer_token(credentials)

    if _matches_any_token(token, _admin_tokens()):
        return AuthPrincipal(role="admin")

    if _agent_did_for_token(token) is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "FORBIDDEN", "message": "Administrator token required"},
        )

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

    return credentials.credentials


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
    raw_entries = _split_env_tokens(os.environ.get(AGENT_TOKENS_ENV, ""))
    entries: list[tuple[str, str]] = []

    for entry in raw_entries:
        agent_did, separator, token = entry.partition("=")
        if separator != "=" or not agent_did or not token:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "error": "AUTH_CONFIG_INVALID",
                    "message": f"{AGENT_TOKENS_ENV} entries must use '<did>=<token>'",
                },
            )
        if not agent_did.startswith("did:nexus:"):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "error": "AUTH_CONFIG_INVALID",
                    "message": f"{AGENT_TOKENS_ENV} agent IDs must be did:nexus DIDs",
                },
            )
        entries.append((agent_did, token))

    return entries


def _matches_any_token(token: str, expected_tokens: list[str]) -> bool:
    return any(_token_matches(token, expected_token) for expected_token in expected_tokens)


def _token_matches(token: str, expected_token: str) -> bool:
    token_digest = hashlib.sha256(token.encode("utf-8")).digest()
    expected_digest = hashlib.sha256(expected_token.encode("utf-8")).digest()
    return hmac.compare_digest(token_digest, expected_digest)


def _split_env_tokens(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]
