# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Microsoft Entra Agent ID adapter and native Entra Agent ID integration."""

import base64
import io
import json
import os
import time
from unittest.mock import MagicMock, patch
from urllib.error import URLError

import pytest
from agentmesh.identity.entra import (
    EntraAgentBlueprint,
    EntraAgentIdentity,
    EntraAgentRegistry,
    EntraAgentStatus,
)
from agentmesh.identity.entra_agent_id import EntraAgentID


TENANT_ID = "contoso-tenant-001"
SPONSOR = "alice@contoso.com"


class TestEntraAgentIdentity:
    """Tests for EntraAgentIdentity."""

    def test_create_basic(self):
        identity = EntraAgentIdentity.create(
            agent_did="did:mesh:researcher-1",
            agent_name="Researcher Agent",
            entra_object_id="obj-001",
            tenant_id=TENANT_ID,
            sponsor_email=SPONSOR,
        )
        assert identity.agent_did == "did:mesh:researcher-1"
        assert identity.entra_object_id == "obj-001"
        assert identity.tenant_id == TENANT_ID
        assert identity.sponsor_email == SPONSOR
        assert identity.status == EntraAgentStatus.ACTIVE
        assert identity.is_active()

    def test_create_with_capabilities_and_scopes(self):
        identity = EntraAgentIdentity.create(
            agent_did="did:mesh:writer-1",
            agent_name="Writer",
            entra_object_id="obj-002",
            tenant_id=TENANT_ID,
            sponsor_email=SPONSOR,
            capabilities=["read:docs", "write:reports"],
            scopes=["Files.Read", "Mail.Send"],
        )
        assert identity.capabilities == ["read:docs", "write:reports"]
        assert identity.scopes == ["Files.Read", "Mail.Send"]

    def test_create_from_blueprint(self):
        blueprint = EntraAgentBlueprint(
            display_name="research-agent",
            description="Standard research agent",
            default_capabilities=["read:kb", "search:web"],
            conditional_access_policy="cap-001",
        )
        identity = EntraAgentIdentity.create(
            agent_did="did:mesh:r1",
            agent_name="R1",
            entra_object_id="obj-003",
            tenant_id=TENANT_ID,
            sponsor_email=SPONSOR,
            blueprint=blueprint,
        )
        assert identity.capabilities == ["read:kb", "search:web"]
        assert identity.conditional_access_policy == "cap-001"
        assert identity.blueprint_name == "research-agent"

    def test_suspend_and_reactivate(self):
        identity = EntraAgentIdentity.create(
            agent_did="did:mesh:a1",
            agent_name="A1",
            entra_object_id="obj-004",
            tenant_id=TENANT_ID,
            sponsor_email=SPONSOR,
        )
        assert identity.is_active()

        identity.suspend("anomaly detected")
        assert not identity.is_active()
        assert identity.status == EntraAgentStatus.SUSPENDED

        identity.reactivate()
        assert identity.is_active()

    def test_disable(self):
        identity = EntraAgentIdentity.create(
            agent_did="did:mesh:a2",
            agent_name="A2",
            entra_object_id="obj-005",
            tenant_id=TENANT_ID,
            sponsor_email=SPONSOR,
        )
        identity.disable()
        assert identity.status == EntraAgentStatus.DISABLED
        assert not identity.is_active()

    def test_has_scope(self):
        identity = EntraAgentIdentity.create(
            agent_did="did:mesh:a3",
            agent_name="A3",
            entra_object_id="obj-006",
            tenant_id=TENANT_ID,
            sponsor_email=SPONSOR,
            scopes=["Files.Read", "Mail.Send"],
        )
        assert identity.has_scope("Files.Read")
        assert identity.has_scope("Mail.Send")
        assert not identity.has_scope("User.ReadWrite")

    def test_record_activity(self):
        identity = EntraAgentIdentity.create(
            agent_did="did:mesh:a4",
            agent_name="A4",
            entra_object_id="obj-007",
            tenant_id=TENANT_ID,
            sponsor_email=SPONSOR,
        )
        assert identity.last_activity is None
        identity.record_activity()
        assert identity.last_activity is not None

    def test_to_audit_record(self):
        identity = EntraAgentIdentity.create(
            agent_did="did:mesh:a5",
            agent_name="A5",
            entra_object_id="obj-008",
            tenant_id=TENANT_ID,
            sponsor_email=SPONSOR,
            capabilities=["read:data"],
            scopes=["Files.Read"],
        )
        record = identity.to_audit_record()
        assert record["agent_did"] == "did:mesh:a5"
        assert record["entra_object_id"] == "obj-008"
        assert record["tenant_id"] == TENANT_ID
        assert record["status"] == "active"
        assert record["capabilities"] == ["read:data"]


class TestEntraAgentRegistry:
    """Tests for EntraAgentRegistry."""

    def _make_registry(self):
        return EntraAgentRegistry(tenant_id=TENANT_ID)

    def test_register_agent(self):
        reg = self._make_registry()
        identity = reg.register(
            agent_did="did:mesh:r1",
            agent_name="R1",
            entra_object_id="obj-100",
            sponsor_email=SPONSOR,
        )
        assert identity.agent_did == "did:mesh:r1"
        assert identity.tenant_id == TENANT_ID

    def test_lookup_by_did(self):
        reg = self._make_registry()
        reg.register("did:mesh:r2", "R2", "obj-101", SPONSOR)
        found = reg.get_by_did("did:mesh:r2")
        assert found is not None
        assert found.entra_object_id == "obj-101"

    def test_lookup_by_entra_id(self):
        reg = self._make_registry()
        reg.register("did:mesh:r3", "R3", "obj-102", SPONSOR)
        found = reg.get_by_entra_id("obj-102")
        assert found is not None
        assert found.agent_did == "did:mesh:r3"

    def test_lookup_not_found(self):
        reg = self._make_registry()
        assert reg.get_by_did("did:mesh:nonexistent") is None
        assert reg.get_by_entra_id("obj-nonexistent") is None

    def test_suspend_and_reactivate_agent(self):
        reg = self._make_registry()
        reg.register("did:mesh:r4", "R4", "obj-103", SPONSOR)

        assert reg.suspend_agent("did:mesh:r4", "anomaly")
        agent = reg.get_by_did("did:mesh:r4")
        assert agent.status == EntraAgentStatus.SUSPENDED

        assert reg.reactivate_agent("did:mesh:r4")
        assert agent.status == EntraAgentStatus.ACTIVE

    def test_disable_agent(self):
        reg = self._make_registry()
        reg.register("did:mesh:r5", "R5", "obj-104", SPONSOR)
        assert reg.disable_agent("did:mesh:r5")
        assert reg.get_by_did("did:mesh:r5").status == EntraAgentStatus.DISABLED

    def test_verify_access_granted(self):
        reg = self._make_registry()
        reg.register("did:mesh:r6", "R6", "obj-105", SPONSOR, scopes=["Files.Read"])
        allowed, reason = reg.verify_access("did:mesh:r6", "Files.Read")
        assert allowed
        assert reason == "Access granted"

    def test_verify_access_denied_scope(self):
        reg = self._make_registry()
        reg.register("did:mesh:r7", "R7", "obj-106", SPONSOR, scopes=["Files.Read"])
        allowed, reason = reg.verify_access("did:mesh:r7", "Mail.Send")
        assert not allowed
        assert "lacks scope" in reason

    def test_verify_access_denied_suspended(self):
        reg = self._make_registry()
        reg.register("did:mesh:r8", "R8", "obj-107", SPONSOR, scopes=["Files.Read"])
        reg.suspend_agent("did:mesh:r8")
        allowed, reason = reg.verify_access("did:mesh:r8", "Files.Read")
        assert not allowed
        assert "suspended" in reason

    def test_verify_access_unregistered(self):
        reg = self._make_registry()
        allowed, reason = reg.verify_access("did:mesh:unknown", "Files.Read")
        assert not allowed
        assert "not registered" in reason

    def test_list_agents(self):
        reg = self._make_registry()
        reg.register("did:mesh:a1", "A1", "obj-201", SPONSOR)
        reg.register("did:mesh:a2", "A2", "obj-202", SPONSOR)
        reg.register("did:mesh:a3", "A3", "obj-203", SPONSOR)
        reg.suspend_agent("did:mesh:a2")

        all_agents = reg.list_agents()
        assert len(all_agents) == 3

        active = reg.list_agents(status=EntraAgentStatus.ACTIVE)
        assert len(active) == 2

        suspended = reg.list_agents(status=EntraAgentStatus.SUSPENDED)
        assert len(suspended) == 1

    def test_get_sponsor_agents(self):
        reg = self._make_registry()
        reg.register("did:mesh:s1", "S1", "obj-301", "alice@contoso.com")
        reg.register("did:mesh:s2", "S2", "obj-302", "bob@contoso.com")
        reg.register("did:mesh:s3", "S3", "obj-303", "alice@contoso.com")

        alice_agents = reg.get_sponsor_agents("alice@contoso.com")
        assert len(alice_agents) == 2
        bob_agents = reg.get_sponsor_agents("bob@contoso.com")
        assert len(bob_agents) == 1

    def test_blueprint_registration(self):
        reg = self._make_registry()
        bp = EntraAgentBlueprint(
            display_name="secure-agent",
            default_capabilities=["read:kb"],
            require_sponsor=True,
            conditional_access_policy="cap-strict",
        )
        reg.register_blueprint(bp)
        identity = reg.register(
            "did:mesh:bp1", "BP1", "obj-401", SPONSOR, blueprint_name="secure-agent"
        )
        assert identity.capabilities == ["read:kb"]
        assert identity.conditional_access_policy == "cap-strict"

    def test_blueprint_requires_sponsor(self):
        reg = self._make_registry()
        bp = EntraAgentBlueprint(
            display_name="strict-agent",
            require_sponsor=True,
        )
        reg.register_blueprint(bp)
        with pytest.raises(ValueError, match="requires a sponsor"):
            reg.register(
                "did:mesh:bp2",
                "BP2",
                "obj-402",
                "",
                blueprint_name="strict-agent",
            )

    def test_audit_log(self):
        reg = self._make_registry()
        reg.register("did:mesh:al1", "AL1", "obj-501", SPONSOR)
        reg.suspend_agent("did:mesh:al1", "testing")
        reg.reactivate_agent("did:mesh:al1")

        log = reg.get_audit_log()
        assert len(log) == 3
        assert log[0]["event_type"] == "register"
        assert log[1]["event_type"] == "suspend"
        assert log[1]["reason"] == "testing"
        assert log[2]["event_type"] == "reactivate"


# ---------------------------------------------------------------------------
# Tests for EntraAgentID (native Entra Agent ID integration)
# ---------------------------------------------------------------------------

def _make_jwt(payload: dict, header: dict | None = None) -> str:
    """Build a fake JWT with the given payload (no real signature)."""
    if header is None:
        header = {"alg": "RS256", "typ": "JWT"}

    def _b64url(data: dict) -> str:
        return base64.urlsafe_b64encode(
            json.dumps(data).encode()
        ).rstrip(b"=").decode()

    return f"{_b64url(header)}.{_b64url(payload)}.fake-signature"


AGENT_DID = "did:mesh:entra-test-agent"
TEST_TENANT = "test-tenant-id-123"
TEST_CLIENT = "test-client-id-456"


class TestEntraAgentIDInit:
    """Constructor validation."""

    def test_valid_construction(self):
        agent = EntraAgentID(AGENT_DID, TEST_TENANT, TEST_CLIENT)
        assert agent.agent_did == AGENT_DID
        assert agent.tenant_id == TEST_TENANT
        assert agent.client_id == TEST_CLIENT

    @pytest.mark.parametrize("did,tid,cid", [
        ("", TEST_TENANT, TEST_CLIENT),
        (AGENT_DID, "", TEST_CLIENT),
        (AGENT_DID, TEST_TENANT, ""),
    ])
    def test_rejects_empty_values(self, did, tid, cid):
        with pytest.raises(ValueError):
            EntraAgentID(did, tid, cid)


class TestEntraAgentIDFromEnvironment:
    """from_environment factory with mocked env vars."""

    def test_success(self):
        with patch.dict(os.environ, {
            "AZURE_TENANT_ID": TEST_TENANT,
            "AZURE_CLIENT_ID": TEST_CLIENT,
        }):
            agent = EntraAgentID.from_environment(AGENT_DID)
            assert agent.agent_did == AGENT_DID
            assert agent.tenant_id == TEST_TENANT
            assert agent.client_id == TEST_CLIENT

    def test_missing_tenant_id(self):
        with patch.dict(os.environ, {"AZURE_CLIENT_ID": TEST_CLIENT}, clear=True):
            with pytest.raises(EnvironmentError, match="AZURE_TENANT_ID"):
                EntraAgentID.from_environment(AGENT_DID)

    def test_missing_client_id(self):
        with patch.dict(os.environ, {"AZURE_TENANT_ID": TEST_TENANT}, clear=True):
            with pytest.raises(EnvironmentError, match="AZURE_CLIENT_ID"):
                EntraAgentID.from_environment(AGENT_DID)


class TestEntraAgentIDValidateToken:
    """validate_token with mock JWTs — no real Azure calls."""

    def _agent(self) -> EntraAgentID:
        return EntraAgentID(AGENT_DID, TEST_TENANT, TEST_CLIENT)

    def test_valid_token_v2_issuer(self):
        token = _make_jwt({
            "iss": f"https://login.microsoftonline.com/{TEST_TENANT}/v2.0",
            "aud": TEST_CLIENT,
            "exp": time.time() + 3600,
            "sub": "user-001",
        })
        claims = self._agent().validate_token(token)
        assert claims["sub"] == "user-001"
        assert claims["aud"] == TEST_CLIENT

    def test_valid_token_v1_issuer(self):
        token = _make_jwt({
            "iss": f"https://sts.windows.net/{TEST_TENANT}/",
            "aud": TEST_CLIENT,
            "exp": time.time() + 3600,
        })
        claims = self._agent().validate_token(token)
        assert claims["aud"] == TEST_CLIENT

    def test_expired_token(self):
        token = _make_jwt({
            "iss": f"https://login.microsoftonline.com/{TEST_TENANT}/v2.0",
            "aud": TEST_CLIENT,
            "exp": time.time() - 100,
        })
        with pytest.raises(ValueError, match="expired"):
            self._agent().validate_token(token)

    def test_not_yet_valid_token(self):
        token = _make_jwt({
            "iss": f"https://login.microsoftonline.com/{TEST_TENANT}/v2.0",
            "aud": TEST_CLIENT,
            "exp": time.time() + 7200,
            "nbf": time.time() + 3600,
        })
        with pytest.raises(ValueError, match="not yet valid"):
            self._agent().validate_token(token)

    def test_wrong_issuer(self):
        token = _make_jwt({
            "iss": "https://login.microsoftonline.com/other-tenant/v2.0",
            "aud": TEST_CLIENT,
            "exp": time.time() + 3600,
        })
        with pytest.raises(ValueError, match="issuer"):
            self._agent().validate_token(token)

    def test_wrong_audience_string(self):
        token = _make_jwt({
            "iss": f"https://login.microsoftonline.com/{TEST_TENANT}/v2.0",
            "aud": "wrong-client",
            "exp": time.time() + 3600,
        })
        with pytest.raises(ValueError, match="audience"):
            self._agent().validate_token(token)

    def test_wrong_audience_list(self):
        token = _make_jwt({
            "iss": f"https://login.microsoftonline.com/{TEST_TENANT}/v2.0",
            "aud": ["other-app-1", "other-app-2"],
            "exp": time.time() + 3600,
        })
        with pytest.raises(ValueError, match="audience"):
            self._agent().validate_token(token)

    def test_audience_list_match(self):
        token = _make_jwt({
            "iss": f"https://login.microsoftonline.com/{TEST_TENANT}/v2.0",
            "aud": ["other-app", TEST_CLIENT],
            "exp": time.time() + 3600,
        })
        claims = self._agent().validate_token(token)
        assert TEST_CLIENT in claims["aud"]

    def test_invalid_jwt_format(self):
        with pytest.raises(ValueError, match="Invalid JWT"):
            self._agent().validate_token("not.a-jwt")


class TestEntraAgentIDMapping:
    """to_did_mapping returns the correct structure."""

    def test_structure(self):
        agent = EntraAgentID(AGENT_DID, TEST_TENANT, TEST_CLIENT)
        mapping = agent.to_did_mapping()
        assert mapping["agent_did"] == AGENT_DID
        assert mapping["entra"]["tenant_id"] == TEST_TENANT
        assert mapping["entra"]["client_id"] == TEST_CLIENT
        assert mapping["mapping_version"] == "1.0"

    def test_all_keys_present(self):
        mapping = EntraAgentID(AGENT_DID, TEST_TENANT, TEST_CLIENT).to_did_mapping()
        assert set(mapping.keys()) == {"agent_did", "entra", "mapping_version"}
        assert set(mapping["entra"].keys()) == {"tenant_id", "client_id"}


class TestEntraAgentIDFromManagedIdentity:
    """from_managed_identity with fully mocked IMDS."""

    def test_success(self):
        compute_resp = json.dumps({"tenantId": TEST_TENANT}).encode()
        bootstrap_token = _make_jwt({"appid": TEST_CLIENT})
        token_resp = json.dumps({"access_token": bootstrap_token}).encode()

        mock_responses = iter([
            _ctx_mock(compute_resp),
            _ctx_mock(token_resp),
        ])

        with patch(
            "agentmesh.identity.entra_agent_id.urlopen",
            side_effect=lambda *a, **kw: next(mock_responses),
        ):
            agent = EntraAgentID.from_managed_identity(AGENT_DID)
            assert agent.tenant_id == TEST_TENANT
            assert agent.client_id == TEST_CLIENT

    def test_imds_unreachable(self):
        with patch(
            "agentmesh.identity.entra_agent_id.urlopen",
            side_effect=URLError("unreachable"),
        ):
            with pytest.raises(RuntimeError, match="IMDS"):
                EntraAgentID.from_managed_identity(AGENT_DID)


class TestEntraAgentIDGetToken:
    """get_agent_token with mocked IMDS token endpoint."""

    def test_success(self):
        expected_token = "mocked-access-token-xyz"
        resp_bytes = json.dumps({"access_token": expected_token}).encode()

        with patch(
            "agentmesh.identity.entra_agent_id.urlopen",
            return_value=_ctx_mock(resp_bytes),
        ):
            agent = EntraAgentID(AGENT_DID, TEST_TENANT, TEST_CLIENT)
            token = agent.get_agent_token()
            assert token == expected_token

    def test_failure(self):
        with patch(
            "agentmesh.identity.entra_agent_id.urlopen",
            side_effect=URLError("timeout"),
        ):
            agent = EntraAgentID(AGENT_DID, TEST_TENANT, TEST_CLIENT)
            with pytest.raises(RuntimeError, match="Failed to acquire token"):
                agent.get_agent_token()


class TestEntraAgentIDRepr:
    def test_repr(self):
        agent = EntraAgentID(AGENT_DID, TEST_TENANT, TEST_CLIENT)
        r = repr(agent)
        assert AGENT_DID in r
        assert TEST_TENANT in r
        assert TEST_CLIENT in r


def _ctx_mock(data: bytes) -> MagicMock:
    """Create a mock that works as a context manager returning *data* on read()."""
    mock = MagicMock()
    mock.read.return_value = data
    mock.__enter__ = MagicMock(return_value=mock)
    mock.__exit__ = MagicMock(return_value=False)
    return mock
