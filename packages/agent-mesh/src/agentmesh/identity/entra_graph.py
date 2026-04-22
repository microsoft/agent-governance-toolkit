# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Microsoft Graph API client for Entra Agent ID integration.

Provides group membership queries and capability scope synchronization
using only the Python standard library (urllib).
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"


class GraphAPIError(Exception):
    """Raised when a Graph API call fails."""

    def __init__(self, message: str, status_code: int = 0) -> None:
        super().__init__(message)
        self.status_code = status_code


class EntraGraphClient:
    """
    Lightweight Microsoft Graph API client for agent identity operations.

    Accepts an injected access token so callers can use any auth flow
    (managed identity, client credentials, workload identity federation).

    Usage::

        token = entra_agent_id.get_agent_token(
            scope="https://graph.microsoft.com/.default"
        )
        client = EntraGraphClient(access_token=token)
        groups = client.get_group_memberships("service-principal-object-id")
    """

    def __init__(self, access_token: str, *, timeout: int = 10) -> None:
        if not access_token:
            raise ValueError("access_token must not be empty")
        self._token = access_token
        self._timeout = timeout

    # -- public API ------------------------------------------------------------

    def get_group_memberships(self, object_id: str) -> list[dict[str, Any]]:
        """
        Fetch Entra group memberships for a service principal.

        Calls ``GET /servicePrincipals/{id}/memberOf/microsoft.graph.group``
        and follows ``@odata.nextLink`` pagination automatically.

        Returns a list of group dicts with at least ``id`` and ``displayName``.
        """
        if not object_id:
            raise ValueError("object_id must not be empty")

        url = (
            f"{GRAPH_BASE}/servicePrincipals/{object_id}"
            f"/memberOf/microsoft.graph.group"
            f"?$select=id,displayName,description"
        )
        groups: list[dict[str, Any]] = []

        while url:
            data = self._get(url)
            for item in data.get("value", []):
                groups.append({
                    "id": item["id"],
                    "displayName": item.get("displayName", ""),
                    "description": item.get("description", ""),
                })
            url = data.get("@odata.nextLink")

        return groups

    def get_app_role_assignments(self, object_id: str) -> list[dict[str, Any]]:
        """
        Fetch app role assignments for a service principal.

        Returns a list of role assignment dicts.
        """
        if not object_id:
            raise ValueError("object_id must not be empty")

        url = (
            f"{GRAPH_BASE}/servicePrincipals/{object_id}/appRoleAssignments"
            f"?$select=id,appRoleId,resourceDisplayName"
        )
        roles: list[dict[str, Any]] = []

        while url:
            data = self._get(url)
            for item in data.get("value", []):
                roles.append({
                    "id": item["id"],
                    "appRoleId": item.get("appRoleId", ""),
                    "resourceDisplayName": item.get("resourceDisplayName", ""),
                })
            url = data.get("@odata.nextLink")

        return roles

    # -- internals -------------------------------------------------------------

    def _get(self, url: str) -> dict[str, Any]:
        """Execute a GET request against Graph API."""
        req = Request(url, headers={  # noqa: S310 — Microsoft Graph API URL
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "ConsistencyLevel": "eventual",
        })
        try:
            with urlopen(req, timeout=self._timeout) as resp:  # noqa: S310 — Microsoft Graph API URL
                return json.loads(resp.read().decode())
        except HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode()[:500]
            except Exception:  # noqa: S110 — intentional silent catch for error body read
                pass
            raise GraphAPIError(
                f"Graph API returned {exc.code}: {body}",
                status_code=exc.code,
            ) from exc
        except URLError as exc:
            raise GraphAPIError(
                f"Failed to reach Graph API: {exc.reason}"
            ) from exc


def build_group_scope_map(
    mappings: dict[str, list[str]],
) -> dict[str, list[str]]:
    """
    Validate and normalize a group-to-capability mapping.

    Keys are Entra group **object IDs** (UUIDs). Values are lists of
    AGT capability strings to grant when the agent is a member.

    Example::

        map = build_group_scope_map({
            "aaa-bbb-ccc": ["read:customer-data", "read:reports"],
            "ddd-eee-fff": ["write:reports"],
        })
    """
    if not mappings:
        raise ValueError("group_scope_map must not be empty")

    normalized: dict[str, list[str]] = {}
    for group_id, caps in mappings.items():
        if not group_id:
            raise ValueError("Group ID must not be empty")
        if not caps:
            raise ValueError(f"Capabilities list for group {group_id!r} must not be empty")
        normalized[group_id] = list(caps)

    return normalized


def sync_memberships_to_capabilities(
    groups: list[dict[str, Any]],
    group_scope_map: dict[str, list[str]],
    *,
    preserve_existing: Optional[list[str]] = None,
) -> list[str]:
    """
    Map Entra group memberships to AGT capabilities.

    Only groups present in ``group_scope_map`` contribute capabilities.
    Unknown groups are logged and skipped. Manually assigned capabilities
    in ``preserve_existing`` are preserved (union merge).

    Returns a deduplicated, sorted list of capabilities.
    """
    derived: set[str] = set()

    matched = 0
    for group in groups:
        group_id = group.get("id", "")
        caps = group_scope_map.get(group_id)
        if caps:
            derived.update(caps)
            matched += 1
        else:
            logger.debug(
                "Skipping unmapped group %r (%s)",
                group.get("displayName", ""),
                group_id,
            )

    if matched == 0:
        logger.warning(
            "No Entra groups matched the scope map (%d groups checked)",
            len(groups),
        )

    # Preserve manually assigned capabilities
    if preserve_existing:
        derived.update(preserve_existing)

    return sorted(derived)
