# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Entra Graph API client and group membership sync."""

import json
from unittest.mock import MagicMock, patch

import pytest
from agentmesh.identity.entra import (
    EntraAgentRegistry,
    EntraAgentStatus,
)
from agentmesh.identity.entra_graph import (
    EntraGraphClient,
    GraphAPIError,
    build_group_scope_map,
    sync_memberships_to_capabilities,
)

TENANT_ID = "contoso-tenant-001"
SPONSOR = "alice@contoso.com"

# -- Helper to mock urlopen ---------------------------------------------------


def _mock_response(data: dict, status: int = 200) -> MagicMock:
    """Create a mock that works as a context manager returning JSON data."""
    mock = MagicMock()
    mock.read.return_value = json.dumps(data).encode()
    mock.__enter__ = MagicMock(return_value=mock)
    mock.__exit__ = MagicMock(return_value=False)
    return mock


# =============================================================================
# EntraGraphClient tests
# =============================================================================


class TestEntraGraphClientInit:
    def test_valid(self):
        client = EntraGraphClient("token-abc")
        assert client._token == "token-abc"

    def test_empty_token_rejected(self):
        with pytest.raises(ValueError, match="access_token"):
            EntraGraphClient("")


class TestGetGroupMemberships:
    def test_single_page(self):
        response = {
            "value": [
                {"id": "grp-1", "displayName": "Analysts", "description": "Data analysts"},
                {"id": "grp-2", "displayName": "Reporters", "description": ""},
            ]
        }
        with patch(
            "agentmesh.identity.entra_graph.urlopen",
            return_value=_mock_response(response),
        ):
            client = EntraGraphClient("token")
            groups = client.get_group_memberships("sp-obj-001")

        assert len(groups) == 2
        assert groups[0]["id"] == "grp-1"
        assert groups[0]["displayName"] == "Analysts"
        assert groups[1]["id"] == "grp-2"

    def test_pagination(self):
        page1 = {
            "value": [{"id": "grp-1", "displayName": "G1", "description": ""}],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/next-page",
        }
        page2 = {
            "value": [{"id": "grp-2", "displayName": "G2", "description": ""}],
        }
        pages = iter([_mock_response(page1), _mock_response(page2)])

        with patch(
            "agentmesh.identity.entra_graph.urlopen",
            side_effect=lambda *a, **kw: next(pages),
        ):
            client = EntraGraphClient("token")
            groups = client.get_group_memberships("sp-obj-002")

        assert len(groups) == 2
        assert groups[0]["id"] == "grp-1"
        assert groups[1]["id"] == "grp-2"

    def test_empty_response(self):
        with patch(
            "agentmesh.identity.entra_graph.urlopen",
            return_value=_mock_response({"value": []}),
        ):
            client = EntraGraphClient("token")
            groups = client.get_group_memberships("sp-obj-003")

        assert groups == []

    def test_empty_object_id_rejected(self):
        client = EntraGraphClient("token")
        with pytest.raises(ValueError, match="object_id"):
            client.get_group_memberships("")

    def test_http_error(self):
        from urllib.error import HTTPError

        err = HTTPError(
            url="https://graph.microsoft.com/v1.0/...",
            code=403,
            msg="Forbidden",
            hdrs={},
            fp=MagicMock(read=MagicMock(return_value=b"Insufficient privileges")),
        )
        with patch(
            "agentmesh.identity.entra_graph.urlopen",
            side_effect=err,
        ):
            client = EntraGraphClient("token")
            with pytest.raises(GraphAPIError, match="403") as exc_info:
                client.get_group_memberships("sp-obj-004")
            assert exc_info.value.status_code == 403

    def test_url_error(self):
        from urllib.error import URLError

        with patch(
            "agentmesh.identity.entra_graph.urlopen",
            side_effect=URLError("timeout"),
        ):
            client = EntraGraphClient("token")
            with pytest.raises(GraphAPIError, match="Failed to reach"):
                client.get_group_memberships("sp-obj-005")


class TestGetAppRoleAssignments:
    def test_single_page(self):
        response = {
            "value": [
                {"id": "role-1", "appRoleId": "ar-1", "resourceDisplayName": "Graph"},
            ]
        }
        with patch(
            "agentmesh.identity.entra_graph.urlopen",
            return_value=_mock_response(response),
        ):
            client = EntraGraphClient("token")
            roles = client.get_app_role_assignments("sp-obj-010")

        assert len(roles) == 1
        assert roles[0]["appRoleId"] == "ar-1"


# =============================================================================
# build_group_scope_map tests
# =============================================================================


class TestBuildGroupScopeMap:
    def test_valid(self):
        result = build_group_scope_map({
            "grp-1": ["read:data", "read:reports"],
            "grp-2": ["write:reports"],
        })
        assert result == {
            "grp-1": ["read:data", "read:reports"],
            "grp-2": ["write:reports"],
        }

    def test_empty_map_rejected(self):
        with pytest.raises(ValueError, match="must not be empty"):
            build_group_scope_map({})

    def test_empty_group_id_rejected(self):
        with pytest.raises(ValueError, match="Group ID"):
            build_group_scope_map({"": ["read:data"]})

    def test_empty_capabilities_rejected(self):
        with pytest.raises(ValueError, match="Capabilities list"):
            build_group_scope_map({"grp-1": []})


# =============================================================================
# sync_memberships_to_capabilities tests
# =============================================================================


class TestSyncMembershipsToCapabilities:
    def test_basic_mapping(self):
        groups = [
            {"id": "grp-1", "displayName": "Analysts"},
            {"id": "grp-2", "displayName": "Writers"},
        ]
        scope_map = {
            "grp-1": ["read:data"],
            "grp-2": ["write:reports"],
        }
        result = sync_memberships_to_capabilities(groups, scope_map)
        assert result == ["read:data", "write:reports"]

    def test_unmapped_groups_skipped(self):
        groups = [
            {"id": "grp-1", "displayName": "Analysts"},
            {"id": "grp-unknown", "displayName": "Random"},
        ]
        scope_map = {"grp-1": ["read:data"]}
        result = sync_memberships_to_capabilities(groups, scope_map)
        assert result == ["read:data"]

    def test_no_matches_returns_empty(self):
        groups = [{"id": "grp-unknown", "displayName": "Random"}]
        scope_map = {"grp-1": ["read:data"]}
        result = sync_memberships_to_capabilities(groups, scope_map)
        assert result == []

    def test_preserve_existing(self):
        groups = [{"id": "grp-1", "displayName": "Analysts"}]
        scope_map = {"grp-1": ["read:data"]}
        result = sync_memberships_to_capabilities(
            groups, scope_map, preserve_existing=["manual:cap"]
        )
        assert result == ["manual:cap", "read:data"]

    def test_deduplication(self):
        groups = [
            {"id": "grp-1", "displayName": "G1"},
            {"id": "grp-2", "displayName": "G2"},
        ]
        scope_map = {
            "grp-1": ["read:data", "shared:cap"],
            "grp-2": ["write:data", "shared:cap"],
        }
        result = sync_memberships_to_capabilities(groups, scope_map)
        assert result == ["read:data", "shared:cap", "write:data"]

    def test_empty_groups(self):
        result = sync_memberships_to_capabilities([], {"grp-1": ["read:data"]})
        assert result == []


# =============================================================================
# EntraAgentRegistry.sync_group_memberships tests
# =============================================================================


class TestRegistrySyncGroupMemberships:
    def _make_registry_with_agent(self):
        reg = EntraAgentRegistry(tenant_id=TENANT_ID)
        reg.register(
            agent_did="did:mesh:sync-agent",
            agent_name="Sync Agent",
            entra_object_id="sp-obj-100",
            sponsor_email=SPONSOR,
            capabilities=["manual:cap"],
            scopes=["Files.Read"],
        )
        return reg

    def test_sync_updates_capabilities(self):
        reg = self._make_registry_with_agent()

        graph_response = {
            "value": [
                {"id": "grp-1", "displayName": "Analysts", "description": ""},
            ]
        }
        with patch(
            "agentmesh.identity.entra_graph.urlopen",
            return_value=_mock_response(graph_response),
        ):
            client = EntraGraphClient("token")
            caps = reg.sync_group_memberships(
                "did:mesh:sync-agent",
                client,
                {"grp-1": ["read:data"]},
            )

        assert "read:data" in caps
        assert "manual:cap" in caps  # preserved

        agent = reg.get_by_did("did:mesh:sync-agent")
        assert agent.capabilities == caps
        # scopes should be untouched
        assert agent.scopes == ["Files.Read"]

    def test_sync_audit_log(self):
        reg = self._make_registry_with_agent()

        with patch(
            "agentmesh.identity.entra_graph.urlopen",
            return_value=_mock_response({"value": []}),
        ):
            client = EntraGraphClient("token")
            reg.sync_group_memberships(
                "did:mesh:sync-agent", client, {"grp-1": ["read:data"]}
            )

        log = reg.get_audit_log()
        sync_events = [e for e in log if e["event_type"] == "sync_group_memberships"]
        assert len(sync_events) == 1
        assert "groups_found" in sync_events[0]

    def test_sync_unknown_agent_raises(self):
        reg = EntraAgentRegistry(tenant_id=TENANT_ID)
        client = EntraGraphClient("token")
        with pytest.raises(KeyError, match="not found"):
            reg.sync_group_memberships(
                "did:mesh:nonexistent", client, {"grp-1": ["read:data"]}
            )


# =============================================================================
# EntraAgentRegistry.validate_bridge_configuration tests
# =============================================================================


class TestValidateBridgeConfiguration:
    def test_valid_configuration(self):
        reg = EntraAgentRegistry(tenant_id=TENANT_ID)
        reg.register(
            agent_did="did:mesh:valid-agent",
            agent_name="Valid",
            entra_object_id="obj-001",
            sponsor_email=SPONSOR,
        )
        # Set entra_app_id for full validation
        agent = reg.get_by_did("did:mesh:valid-agent")
        agent.entra_app_id = "app-001"

        valid, issues = reg.validate_bridge_configuration("did:mesh:valid-agent")
        assert valid
        assert issues == []

    def test_missing_entra_app_id_warns(self):
        reg = EntraAgentRegistry(tenant_id=TENANT_ID)
        reg.register(
            agent_did="did:mesh:no-app-id",
            agent_name="NoAppId",
            entra_object_id="obj-002",
            sponsor_email=SPONSOR,
        )
        valid, issues = reg.validate_bridge_configuration("did:mesh:no-app-id")
        assert not valid
        assert any("entra_app_id" in i for i in issues)

    def test_suspended_agent(self):
        reg = EntraAgentRegistry(tenant_id=TENANT_ID)
        reg.register(
            agent_did="did:mesh:suspended",
            agent_name="Suspended",
            entra_object_id="obj-003",
            sponsor_email=SPONSOR,
        )
        reg.suspend_agent("did:mesh:suspended")
        valid, issues = reg.validate_bridge_configuration("did:mesh:suspended")
        assert not valid
        assert any("suspended" in i for i in issues)

    def test_unregistered_agent(self):
        reg = EntraAgentRegistry(tenant_id=TENANT_ID)
        valid, issues = reg.validate_bridge_configuration("did:mesh:unknown")
        assert not valid
        assert any("not found" in i for i in issues)
