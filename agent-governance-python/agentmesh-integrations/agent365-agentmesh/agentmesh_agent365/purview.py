# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Microsoft Purview data security checks for agent prompts and tool payloads.

Uses the Microsoft Graph ``dataSecurityAndGovernance`` APIs (v1.0):

1. ``POST /users/{id}/dataSecurityAndGovernance/protectionScopes/compute``
   returns the activities and locations that Purview policies cover for a
   user, plus an ``ETag`` identifying the policy state.
2. ``POST /users/{id}/dataSecurityAndGovernance/processContent`` evaluates
   text against DLP policy. The cached ``ETag`` is sent as ``If-None-Match``;
   a ``protectionScopeState`` of ``modified`` means the cached scopes are stale.

A ``restrictAccess`` policy action with ``restrictionAction: block`` blocks
the content. The client calls ``processContent`` only when a cached scope
covers the activity and requests inline evaluation; otherwise it returns
``applicable=False`` and leaves the decision to other controls.

``processContent`` requires ``Content.Process.User`` (least privileged) or
``Content.Process.All``; ``protectionScopes/compute`` requires the
``ProtectionScopes.Compute.*`` permission. Check the Microsoft Graph
permissions reference for the current least-privileged choice.
"""

from __future__ import annotations

import logging
import threading
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
ACTIVITY_UPLOAD_TEXT = "uploadText"
ACTIVITY_DOWNLOAD_TEXT = "downloadText"


@dataclass(frozen=True)
class AgentInfo:
    """Agent attribution sent with content entries (``aiAgentInfo``)."""

    identifier: str
    name: str
    blueprint_id: str | None = None
    version: str | None = None

    def to_graph(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "@odata.type": "microsoft.graph.aiAgentInfo",
            "identifier": self.identifier,
            "name": self.name,
        }
        if self.blueprint_id:
            body["blueprintId"] = self.blueprint_id
        if self.version:
            body["version"] = self.version
        return body


@dataclass(frozen=True)
class PurviewVerdict:
    """Outcome of a Purview content check."""

    blocked: bool
    applicable: bool
    reason: str
    policy_actions: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class _Scopes:
    etag: str | None
    scopes: list[dict[str, Any]]


class PurviewClient:
    """Thin, fail-closed client for Purview protection scopes and processContent.

    Args:
        http: An ``httpx.Client`` (inject a mock transport in tests).
        token_provider: Returns a Graph access token for the call.
        app_id: Entra application ID registered as the Purview policy location.
        app_name: Application display name reported to Purview.
        app_version: Application version reported to Purview.
        fail_closed: When True (default), Graph errors block the content.
    """

    def __init__(
        self,
        http: Any,
        token_provider: Callable[[], str],
        *,
        app_id: str,
        app_name: str,
        app_version: str = "1.0",
        fail_closed: bool = True,
        base_url: str = GRAPH_BASE,
    ) -> None:
        self._http = http
        self._token = token_provider
        self.app_id = app_id
        self.app_name = app_name
        self.app_version = app_version
        self.fail_closed = fail_closed
        self._base = base_url.rstrip("/")
        self._cache: dict[str, _Scopes] = {}
        self._lock = threading.Lock()

    def _headers(self, extra: Mapping[str, str] | None = None) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self._token()}",
            "Content-Type": "application/json",
            "Client-Request-Id": str(uuid.uuid4()),
        }
        headers.update(extra or {})
        return headers

    def _location(self) -> dict[str, Any]:
        return {"@odata.type": "microsoft.graph.policyLocationApplication", "value": self.app_id}

    def compute_protection_scopes(self, user_id: str) -> list[dict[str, Any]]:
        """Fetch and cache protection scopes for *user_id*."""
        response = self._http.post(
            f"{self._base}/users/{user_id}/dataSecurityAndGovernance/protectionScopes/compute",
            headers=self._headers(),
            json={
                "activities": f"{ACTIVITY_UPLOAD_TEXT},{ACTIVITY_DOWNLOAD_TEXT}",
                "locations": [self._location()],
            },
            timeout=10.0,
        )
        response.raise_for_status()
        scopes = response.json().get("value", [])
        with self._lock:
            self._cache[user_id] = _Scopes(response.headers.get("ETag"), list(scopes))
        return list(scopes)

    def invalidate(self, user_id: str | None = None) -> None:
        """Drop cached scopes for one user, or all users."""
        with self._lock:
            if user_id is None:
                self._cache.clear()
            else:
                self._cache.pop(user_id, None)

    def _scope_for(self, user_id: str, activity: str) -> tuple[_Scopes, dict[str, Any] | None]:
        with self._lock:
            cached = self._cache.get(user_id)
        if cached is None:
            self.compute_protection_scopes(user_id)
            with self._lock:
                cached = self._cache[user_id]
        for scope in cached.scopes:
            activities = str(scope.get("activities", "")).replace(" ", "").split(",")
            if activity in activities:
                return cached, scope
        return cached, None

    def check_text(
        self,
        user_id: str,
        text: str,
        *,
        activity: str = ACTIVITY_UPLOAD_TEXT,
        agent: AgentInfo | None = None,
        correlation_id: str | None = None,
        name: str = "agent message",
    ) -> PurviewVerdict:
        """Evaluate *text* for *user_id* against Purview DLP policy."""
        try:
            cached, scope = self._scope_for(user_id, activity)
            if scope is None:
                return PurviewVerdict(False, False, f"No Purview scope covers {activity}")
            if scope.get("executionMode") not in (None, "evaluateInline"):
                return PurviewVerdict(False, False, "Purview scope is evaluated offline")
            now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            entry: dict[str, Any] = {
                "@odata.type": "microsoft.graph.processConversationMetadata",
                "identifier": str(uuid.uuid4()),
                "content": {"@odata.type": "microsoft.graph.textContent", "data": text},
                "name": name,
                "correlationId": correlation_id or str(uuid.uuid4()),
                "sequenceNumber": 0,
                "isTruncated": False,
                "createdDateTime": now,
                "modifiedDateTime": now,
            }
            if agent is not None:
                entry["agents"] = [agent.to_graph()]
            extra = {"If-None-Match": cached.etag} if cached.etag else None
            response = self._http.post(
                f"{self._base}/users/{user_id}/dataSecurityAndGovernance/processContent",
                headers=self._headers(extra),
                json={
                    "contentToProcess": {
                        "contentEntries": [entry],
                        "activityMetadata": {"activity": activity},
                        "deviceMetadata": {},
                        "protectedAppMetadata": {
                            "name": self.app_name,
                            "version": self.app_version,
                            "applicationLocation": self._location(),
                        },
                        "integratedAppMetadata": {"name": self.app_name, "version": self.app_version},
                    }
                },
                timeout=10.0,
            )
            response.raise_for_status()
            if response.status_code in (202, 204) or not response.content:
                return PurviewVerdict(False, True, "Purview accepted content without inline actions")
            body = response.json()
        except Exception as exc:
            logger.warning("Purview check failed | user=%s error=%s", user_id, type(exc).__name__)
            if self.fail_closed:
                return PurviewVerdict(True, True, "Purview check failed (fail closed)")
            return PurviewVerdict(False, False, "Purview check failed (fail open)")

        if body.get("protectionScopeState") == "modified":
            self.invalidate(user_id)
        actions = [a for a in body.get("policyActions", []) if isinstance(a, Mapping)]
        blocked = any(
            a.get("action") == "restrictAccess" and a.get("restrictionAction") == "block" for a in actions
        )
        reason = "Blocked by Purview DLP policy" if blocked else "Allowed by Purview"
        return PurviewVerdict(blocked, True, reason, [dict(a) for a in actions])
