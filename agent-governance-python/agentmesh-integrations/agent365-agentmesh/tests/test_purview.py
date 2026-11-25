# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the Purview client."""
from __future__ import annotations

import json
from typing import Any

import httpx

from agentmesh_agent365 import AgentInfo, PurviewClient

USER = "5def8f26-aff8-4db6-a08c-0fcf8f1aa2ba"
APP = "83ef198a-0396-4893-9d4f-d36efbffc8bd"
INLINE_SCOPE = {"activities": "uploadText", "executionMode": "evaluateInline", "locations": []}
BLOCK = {"@odata.type": "#microsoft.graph.restrictAccessAction", "action": "restrictAccess", "restrictionAction": "block"}


class _Graph:
    def __init__(self, scopes: list[dict[str, Any]], process_body: dict[str, Any] | None = None, process_status: int = 200) -> None:
        self.scopes = scopes
        self.process_body = process_body or {"protectionScopeState": "notModified", "policyActions": []}
        self.process_status = process_status
        self.requests: list[httpx.Request] = []
        self.etag = 'W/"v1"'

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.path.endswith("/protectionScopes/compute"):
            return httpx.Response(200, json={"value": self.scopes}, headers={"ETag": self.etag})
        if request.url.path.endswith("/processContent"):
            return httpx.Response(self.process_status, json=self.process_body)
        return httpx.Response(404)

    def calls(self, suffix: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.path.endswith(suffix)]


def _client(graph: _Graph, **kwargs: Any) -> PurviewClient:
    return PurviewClient(
        httpx.Client(transport=httpx.MockTransport(graph)),
        lambda: "tok",
        app_id=APP,
        app_name="AGT gateway",
        **kwargs,
    )


def test_block_action_blocks_and_request_is_well_formed() -> None:
    graph = _Graph([INLINE_SCOPE], {"protectionScopeState": "notModified", "policyActions": [BLOCK]})
    verdict = _client(graph).check_text(USER, "ssn 000-11-2222", agent=AgentInfo("agent-1", "Claims", blueprint_id="bp-1"))
    assert verdict.blocked and verdict.applicable
    process = graph.calls("/processContent")[0]
    assert process.headers["If-None-Match"] == 'W/"v1"'
    assert process.headers["Authorization"] == "Bearer tok"
    body = json.loads(process.content)["contentToProcess"]
    entry = body["contentEntries"][0]
    assert entry["content"]["data"] == "ssn 000-11-2222"
    assert entry["agents"][0]["blueprintId"] == "bp-1"
    assert body["activityMetadata"] == {"activity": "uploadText"}
    assert body["protectedAppMetadata"]["applicationLocation"]["value"] == APP


def test_scopes_are_cached_until_policy_state_changes() -> None:
    graph = _Graph([INLINE_SCOPE])
    client = _client(graph)
    assert client.check_text(USER, "hello").blocked is False
    assert client.check_text(USER, "hello").blocked is False
    assert len(graph.calls("/protectionScopes/compute")) == 1
    graph.process_body = {"protectionScopeState": "modified", "policyActions": []}
    client.check_text(USER, "hello")
    client.check_text(USER, "hello")
    assert len(graph.calls("/protectionScopes/compute")) == 2


def test_uncovered_or_offline_activity_skips_process_content() -> None:
    graph = _Graph([{"activities": "downloadText", "executionMode": "evaluateInline"}])
    verdict = _client(graph).check_text(USER, "hello")
    assert verdict.applicable is False and verdict.blocked is False
    offline = _Graph([{"activities": "uploadText", "executionMode": "evaluateOffline"}])
    assert _client(offline).check_text(USER, "hello").applicable is False
    assert graph.calls("/processContent") == [] and offline.calls("/processContent") == []


def test_graph_errors_fail_closed_by_default() -> None:
    graph = _Graph([INLINE_SCOPE], process_status=503)
    assert _client(graph).check_text(USER, "hello").blocked is True
    assert _client(_Graph([INLINE_SCOPE], process_status=503), fail_closed=False).check_text(USER, "hello").blocked is False


def test_non_blocking_actions_allow() -> None:
    audit_only = {"action": "restrictAccess", "restrictionAction": "warn"}
    graph = _Graph([INLINE_SCOPE], {"protectionScopeState": "notModified", "policyActions": [audit_only]})
    verdict = _client(graph).check_text(USER, "hello")
    assert verdict.blocked is False
    assert verdict.policy_actions == [audit_only]
