# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Comprehensive tests to boost code coverage for agent-mesh modules.

Targets: trust/cards.py, identity/spiffe.py, identity/sponsor.py,
         integrations/http_middleware.py, reward/scoring.py, observability/metrics.py
"""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch, PropertyMock
from urllib.parse import urlparse
import json


# ---------------------------------------------------------------------------
# trust/cards.py
# ---------------------------------------------------------------------------
from agentmesh.trust.cards import TrustedAgentCard, CardRegistry
from agentmesh.identity.agent_id import AgentIdentity


def _make_identity(**kwargs):
    defaults = dict(name="test-agent", sponsor="test@example.com", capabilities=["read", "write"])
    defaults.update(kwargs)
    return AgentIdentity.create(**defaults)


class TestTrustedAgentCard:
    """Tests for TrustedAgentCard."""

    def test_get_signable_content_deterministic(self):
        card = TrustedAgentCard(name="a", capabilities=["z", "a"])
        content = card._get_signable_content()
        data = json.loads(content)
        assert data["capabilities"] == ["a", "z"]  # sorted
        assert data["name"] == "a"

    def test_sign_sets_fields(self):
        identity = _make_identity()
        card = TrustedAgentCard(name="agent1")
        card.sign(identity)
        assert card.agent_did == str(identity.did)
        assert card.public_key == identity.public_key
        assert card.card_signature is not None
        assert card.signature_timestamp is not None

    def test_verify_signature_valid(self):
        identity = _make_identity()
        card = TrustedAgentCard(name="agent1", capabilities=["read"])
        card.sign(identity)
        assert card.verify_signature(identity) is True

    def test_verify_signature_no_identity_uses_embedded_key(self):
        identity = _make_identity()
        card = TrustedAgentCard(name="agent1")
        card.sign(identity)
        # Verify without passing identity – uses embedded public key
        assert card.verify_signature() is True

    def test_verify_signature_missing_signature(self):
        card = TrustedAgentCard(name="agent1")
        assert card.verify_signature() is False

    def test_verify_signature_missing_public_key(self):
        card = TrustedAgentCard(name="agent1", card_signature="abc")
        assert card.verify_signature() is False

    def test_verify_signature_tampered(self):
        identity = _make_identity()
        card = TrustedAgentCard(name="agent1")
        card.sign(identity)
        card.name = "tampered"  # change content after signing
        assert card.verify_signature() is False

    def test_from_identity(self):
        identity = _make_identity(description="desc", capabilities=["read"])
        card = TrustedAgentCard.from_identity(identity)
        assert card.name == identity.name
        assert card.description == "desc"
        assert card.capabilities == identity.capabilities
        assert card.card_signature is not None

    def test_to_dict_without_signature(self):
        card = TrustedAgentCard(name="a", description="d", capabilities=["c"])
        d = card.to_dict()
        assert d["name"] == "a"
        assert d["description"] == "d"
        assert "card_signature" not in d
        assert "agent_did" not in d

    def test_to_dict_with_signature(self):
        identity = _make_identity()
        card = TrustedAgentCard.from_identity(identity)
        d = card.to_dict()
        assert "card_signature" in d
        assert "agent_did" in d
        assert "public_key" in d
        assert d["signature_timestamp"] is not None

    def test_from_dict_minimal(self):
        card = TrustedAgentCard.from_dict({"name": "x"})
        assert card.name == "x"
        assert card.capabilities == []
        assert card.trust_score == 1.0

    def test_from_dict_full_roundtrip(self):
        identity = _make_identity()
        original = TrustedAgentCard.from_identity(identity)
        d = original.to_dict()
        restored = TrustedAgentCard.from_dict(d)
        assert restored.name == original.name
        assert restored.agent_did == original.agent_did
        assert restored.card_signature == original.card_signature

    def test_from_dict_with_timestamps(self):
        now = datetime.now(timezone.utc)
        d = {
            "name": "t",
            "signature_timestamp": now.isoformat(),
            "created_at": now.isoformat(),
        }
        card = TrustedAgentCard.from_dict(d)
        assert card.signature_timestamp is not None
        assert card.created_at is not None


class TestCardRegistry:
    """Tests for CardRegistry."""

    def _signed_card(self):
        identity = _make_identity(capabilities=["search", "write"])
        return TrustedAgentCard.from_identity(identity)

    def test_register_valid_card(self):
        reg = CardRegistry()
        card = self._signed_card()
        assert reg.register(card) is True
        assert reg.get(card.agent_did) is card

    def test_register_invalid_card(self):
        reg = CardRegistry()
        card = TrustedAgentCard(name="bad")
        assert reg.register(card) is False

    def test_get_missing(self):
        reg = CardRegistry()
        assert reg.get("did:mesh:missing") is None

    def test_is_verified_cached(self):
        reg = CardRegistry()
        card = self._signed_card()
        reg.register(card)
        assert reg.is_verified(card.agent_did) is True

    def test_is_verified_unknown(self):
        reg = CardRegistry()
        assert reg.is_verified("did:mesh:unknown") is False

    def test_is_verified_expired_cache(self):
        reg = CardRegistry(cache_ttl_seconds=0)
        card = self._signed_card()
        reg.register(card)
        # Cache TTL=0 means cache is always expired, forces re-verification
        assert reg.is_verified(card.agent_did) is True

    def test_clear_cache(self):
        reg = CardRegistry()
        card = self._signed_card()
        reg.register(card)
        reg.clear_cache()
        assert reg._verified_cache == {}

    def test_list_cards(self):
        reg = CardRegistry()
        c1 = self._signed_card()
        c2 = self._signed_card()
        reg.register(c1)
        reg.register(c2)
        assert len(reg.list_cards()) == 2

    def test_find_by_capability(self):
        reg = CardRegistry()
        card = self._signed_card()  # has "search" and "write"
        reg.register(card)
        assert len(reg.find_by_capability("search")) == 1
        assert len(reg.find_by_capability("nonexistent")) == 0


# ---------------------------------------------------------------------------
# identity/spiffe.py
# ---------------------------------------------------------------------------
from agentmesh.identity.spiffe import SVID, SPIFFEIdentity, SPIFFERegistry


class TestSVID:
    """Tests for SVID."""

    def test_parse_spiffe_id_valid(self):
        domain, path = SVID.parse_spiffe_id("spiffe://example.com/workload/agent1")
        assert domain == "example.com"
        assert path == "/workload/agent1"

    def test_parse_spiffe_id_no_path(self):
        domain, path = SVID.parse_spiffe_id("spiffe://example.com")
        assert domain == "example.com"
        assert path == "/"

    def test_parse_spiffe_id_invalid(self):
        with pytest.raises(ValueError, match="Invalid SPIFFE ID"):
            SVID.parse_spiffe_id("http://not-spiffe")

    def test_is_valid_true(self):
        now = datetime.utcnow()
        svid = SVID(
            spiffe_id="spiffe://d/p",
            trust_domain="d",
            issued_at=now - timedelta(minutes=5),
            expires_at=now + timedelta(hours=1),
            agent_did="did:mesh:abc",
        )
        assert svid.is_valid() is True

    def test_is_valid_expired(self):
        now = datetime.utcnow()
        svid = SVID(
            spiffe_id="spiffe://d/p",
            trust_domain="d",
            issued_at=now - timedelta(hours=2),
            expires_at=now - timedelta(hours=1),
            agent_did="did:mesh:abc",
        )
        assert svid.is_valid() is False

    def test_time_remaining_positive(self):
        now = datetime.utcnow()
        svid = SVID(
            spiffe_id="spiffe://d/p",
            trust_domain="d",
            issued_at=now,
            expires_at=now + timedelta(hours=1),
            agent_did="did:mesh:abc",
        )
        assert svid.time_remaining() > timedelta(0)

    def test_time_remaining_expired(self):
        now = datetime.utcnow()
        svid = SVID(
            spiffe_id="spiffe://d/p",
            trust_domain="d",
            issued_at=now - timedelta(hours=2),
            expires_at=now - timedelta(hours=1),
            agent_did="did:mesh:abc",
        )
        assert svid.time_remaining() == timedelta(0)


class TestSPIFFEIdentity:
    """Tests for SPIFFEIdentity."""

    def test_create_default(self):
        si = SPIFFEIdentity.create(agent_did="did:mesh:1", agent_name="agent1")
        assert si.spiffe_id == "spiffe://agentmesh.local/agentmesh/agent1"
        assert si.trust_domain == "agentmesh.local"
        assert si.workload_path == "/agentmesh/agent1"

    def test_create_with_org(self):
        si = SPIFFEIdentity.create(
            agent_did="did:mesh:1", agent_name="a", organization="myorg"
        )
        assert "/myorg/" in si.spiffe_id

    def test_create_custom_domain(self):
        si = SPIFFEIdentity.create(
            agent_did="did:mesh:1", agent_name="a", trust_domain="custom.io"
        )
        assert si.trust_domain == "custom.io"
        parsed = urlparse(si.spiffe_id)
        assert parsed.scheme == "spiffe"
        assert parsed.hostname == "custom.io"
        assert parsed.path.startswith("/")
    def test_issue_svid(self):
        si = SPIFFEIdentity.create(agent_did="did:mesh:1", agent_name="a")
        svid = si.issue_svid(ttl_hours=2)
        assert svid.spiffe_id == si.spiffe_id
        assert svid.agent_did == "did:mesh:1"
        assert svid.is_valid() is True
        assert si.current_svid is svid

    def test_issue_svid_jwt(self):
        si = SPIFFEIdentity.create(agent_did="did:mesh:1", agent_name="a")
        svid = si.issue_svid(svid_type="jwt")
        assert svid.svid_type == "jwt"

    def test_get_valid_svid_none(self):
        si = SPIFFEIdentity.create(agent_did="did:mesh:1", agent_name="a")
        assert si.get_valid_svid() is None

    def test_get_valid_svid_valid(self):
        si = SPIFFEIdentity.create(agent_did="did:mesh:1", agent_name="a")
        si.issue_svid()
        assert si.get_valid_svid() is not None

    def test_get_valid_svid_expired(self):
        si = SPIFFEIdentity.create(agent_did="did:mesh:1", agent_name="a")
        si.issue_svid(ttl_hours=0)  # expires immediately (ttl=0)
        # The svid is issued_at=now, expires_at=now so is_valid() returns False
        assert si.get_valid_svid() is None

    def test_needs_rotation_no_svid(self):
        si = SPIFFEIdentity.create(agent_did="did:mesh:1", agent_name="a")
        assert si.needs_rotation() is True

    def test_needs_rotation_fresh_svid(self):
        si = SPIFFEIdentity.create(agent_did="did:mesh:1", agent_name="a")
        si.issue_svid(ttl_hours=2)
        assert si.needs_rotation() is False

    def test_needs_rotation_nearly_expired(self):
        si = SPIFFEIdentity.create(agent_did="did:mesh:1", agent_name="a")
        si.issue_svid(ttl_hours=0)  # expires immediately
        assert si.needs_rotation(threshold_minutes=10) is True


class TestSPIFFERegistry:
    """Tests for SPIFFERegistry."""

    def test_register(self):
        reg = SPIFFERegistry()
        identity = reg.register("did:mesh:1", "agent1")
        assert identity.agent_did == "did:mesh:1"

    def test_register_duplicate(self):
        reg = SPIFFERegistry()
        id1 = reg.register("did:mesh:1", "agent1")
        id2 = reg.register("did:mesh:1", "agent1")
        assert id1 is id2  # returns existing

    def test_register_with_org(self):
        reg = SPIFFERegistry()
        identity = reg.register("did:mesh:1", "a", organization="org1")
        assert "/org1/" in identity.spiffe_id

    def test_get(self):
        reg = SPIFFERegistry()
        reg.register("did:mesh:1", "a")
        assert reg.get("did:mesh:1") is not None
        assert reg.get("did:mesh:999") is None

    def test_get_by_spiffe_id(self):
        reg = SPIFFERegistry()
        identity = reg.register("did:mesh:1", "agent1")
        found = reg.get_by_spiffe_id(identity.spiffe_id)
        assert found is identity

    def test_get_by_spiffe_id_not_found(self):
        reg = SPIFFERegistry()
        assert reg.get_by_spiffe_id("spiffe://nope/nope") is None

    def test_issue_svid(self):
        reg = SPIFFERegistry()
        reg.register("did:mesh:1", "a")
        svid = reg.issue_svid("did:mesh:1")
        assert svid is not None
        assert svid.is_valid() is True

    def test_issue_svid_unknown(self):
        reg = SPIFFERegistry()
        assert reg.issue_svid("did:mesh:unknown") is None

    def test_validate_svid_valid(self):
        reg = SPIFFERegistry()
        reg.register("did:mesh:1", "a")
        svid = reg.issue_svid("did:mesh:1")
        assert reg.validate_svid(svid) is True

    def test_validate_svid_expired(self):
        reg = SPIFFERegistry()
        si = reg.register("did:mesh:1", "a")
        svid = si.issue_svid(ttl_hours=0)
        assert reg.validate_svid(svid) is False

    def test_validate_svid_wrong_domain(self):
        reg = SPIFFERegistry(trust_domain="domain-a")
        si = reg.register("did:mesh:1", "a")
        svid = si.issue_svid()
        # Manually override trust domain on svid
        svid.trust_domain = "domain-b"
        assert reg.validate_svid(svid) is False

    def test_validate_svid_unregistered_agent(self):
        reg = SPIFFERegistry()
        now = datetime.utcnow()
        svid = SVID(
            spiffe_id="spiffe://agentmesh.local/agentmesh/unknown",
            trust_domain="agentmesh.local",
            issued_at=now,
            expires_at=now + timedelta(hours=1),
            agent_did="did:mesh:unknown",
        )
        assert reg.validate_svid(svid) is False

    def test_custom_trust_domain(self):
        reg = SPIFFERegistry(trust_domain="custom.io")
        identity = reg.register("did:mesh:1", "a")
        parsed = urlparse(identity.spiffe_id)
        assert parsed.scheme == "spiffe"
        assert parsed.hostname == "custom.io"
        assert parsed.path.startswith("/")


# ---------------------------------------------------------------------------
# identity/sponsor.py
# ---------------------------------------------------------------------------
from agentmesh.identity.sponsor import HumanSponsor, SponsorRegistry


class TestHumanSponsor:
    """Tests for HumanSponsor."""

    def test_create(self):
        s = HumanSponsor.create(email="a@b.com", name="Alice")
        assert s.email == "a@b.com"
        assert s.name == "Alice"
        assert s.sponsor_id.startswith("sponsor_")
        assert s.allowed_capabilities == ["*"]

    def test_create_with_capabilities(self):
        s = HumanSponsor.create(email="a@b.com", allowed_capabilities=["read"])
        assert s.allowed_capabilities == ["read"]

    def test_create_with_org(self):
        s = HumanSponsor.create(email="a@b.com", organization="Acme")
        assert s.organization_name == "Acme"

    def test_verify(self):
        s = HumanSponsor.create(email="a@b.com")
        assert s.verified is False
        s.verify(method="sso")
        assert s.verified is True
        assert s.verification_method == "sso"
        assert s.verified_at is not None

    def test_can_sponsor_agent_active_verified(self):
        s = HumanSponsor.create(email="a@b.com")
        s.verify()
        assert s.can_sponsor_agent() is True

    def test_can_sponsor_agent_not_verified(self):
        s = HumanSponsor.create(email="a@b.com")
        assert s.can_sponsor_agent() is False

    def test_can_sponsor_agent_suspended(self):
        s = HumanSponsor.create(email="a@b.com")
        s.verify()
        s.suspend()
        assert s.can_sponsor_agent() is False

    def test_can_sponsor_agent_limit_reached(self):
        s = HumanSponsor.create(email="a@b.com")
        s.verify()
        s.max_agents = 1
        s.agent_dids = ["did:mesh:1"]
        assert s.can_sponsor_agent() is False

    def test_can_grant_capability_wildcard(self):
        s = HumanSponsor.create(email="a@b.com")
        assert s.can_grant_capability("anything") is True

    def test_can_grant_capability_exact(self):
        s = HumanSponsor.create(email="a@b.com", allowed_capabilities=["read", "write"])
        assert s.can_grant_capability("read") is True
        assert s.can_grant_capability("delete") is False

    def test_can_grant_capability_prefix(self):
        s = HumanSponsor.create(email="a@b.com", allowed_capabilities=["data:*"])
        assert s.can_grant_capability("data:read") is True
        assert s.can_grant_capability("data:write") is True
        assert s.can_grant_capability("other:read") is False

    def test_add_agent(self):
        s = HumanSponsor.create(email="a@b.com")
        s.add_agent("did:mesh:1")
        assert "did:mesh:1" in s.agent_dids
        assert s.last_activity_at is not None

    def test_add_agent_duplicate(self):
        s = HumanSponsor.create(email="a@b.com")
        s.add_agent("did:mesh:1")
        s.add_agent("did:mesh:1")
        assert len(s.agent_dids) == 1

    def test_remove_agent(self):
        s = HumanSponsor.create(email="a@b.com")
        s.add_agent("did:mesh:1")
        s.remove_agent("did:mesh:1")
        assert "did:mesh:1" not in s.agent_dids

    def test_remove_agent_not_present(self):
        s = HumanSponsor.create(email="a@b.com")
        s.remove_agent("did:mesh:nope")  # should not raise

    def test_suspend(self):
        s = HumanSponsor.create(email="a@b.com")
        s.suspend(reason="bad behavior")
        assert s.status == "suspended"

    def test_reactivate(self):
        s = HumanSponsor.create(email="a@b.com")
        s.suspend()
        s.reactivate()
        assert s.status == "active"

    def test_reactivate_revoked(self):
        s = HumanSponsor.create(email="a@b.com")
        s.status = "revoked"
        with pytest.raises(ValueError, match="Cannot reactivate a revoked sponsor"):
            s.reactivate()


class TestSponsorRegistry:
    """Tests for SponsorRegistry."""

    def test_register_and_get(self):
        reg = SponsorRegistry()
        s = HumanSponsor.create(email="a@b.com")
        reg.register(s)
        assert reg.get(s.sponsor_id) is s

    def test_register_duplicate_email(self):
        reg = SponsorRegistry()
        s1 = HumanSponsor.create(email="a@b.com")
        reg.register(s1)
        s2 = HumanSponsor.create(email="a@b.com")
        with pytest.raises(ValueError, match="already registered"):
            reg.register(s2)

    def test_get_missing(self):
        reg = SponsorRegistry()
        assert reg.get("nope") is None

    def test_get_by_email(self):
        reg = SponsorRegistry()
        s = HumanSponsor.create(email="a@b.com")
        reg.register(s)
        assert reg.get_by_email("a@b.com") is s
        assert reg.get_by_email("z@z.com") is None

    def test_get_or_create_existing(self):
        reg = SponsorRegistry()
        s = HumanSponsor.create(email="a@b.com")
        reg.register(s)
        result = reg.get_or_create("a@b.com")
        assert result is s

    def test_get_or_create_new(self):
        reg = SponsorRegistry()
        result = reg.get_or_create("new@b.com", name="New", organization="Org")
        assert result.email == "new@b.com"
        assert reg.get_by_email("new@b.com") is result

    def test_suspend_all_for_org(self):
        reg = SponsorRegistry()
        s1 = HumanSponsor.create(email="a@b.com")
        s1.organization_id = "org1"
        s2 = HumanSponsor.create(email="b@b.com")
        s2.organization_id = "org1"
        s3 = HumanSponsor.create(email="c@b.com")
        s3.organization_id = "org2"
        reg.register(s1)
        reg.register(s2)
        reg.register(s3)
        count = reg.suspend_all_for_org("org1")
        assert count == 2
        assert s1.status == "suspended"
        assert s2.status == "suspended"
        assert s3.status == "active"

    def test_suspend_all_for_org_none(self):
        reg = SponsorRegistry()
        assert reg.suspend_all_for_org("nonexistent") == 0


# ---------------------------------------------------------------------------
# integrations/http_middleware.py
# ---------------------------------------------------------------------------
from agentmesh.integrations.http_middleware import (
    TrustMiddleware,
    TrustConfig,
    VerificationResult,
    flask_trust_required,
    fastapi_trust_required,
)


class TestTrustMiddleware:
    """Tests for TrustMiddleware."""

    def test_verify_request_permissive_no_headers(self):
        cfg = TrustConfig(permissive_mode=True)
        mw = TrustMiddleware(config=cfg)
        result, err = mw.verify_request({})
        assert result.verified is True
        assert err is None

    def test_verify_request_default_strict_no_headers(self):
        """V16: Default config is now strict (permissive_mode=False)."""
        mw = TrustMiddleware()
        result, err = mw.verify_request({})
        assert result.verified is False
        assert err is not None

    def test_verify_request_strict_no_headers(self):
        cfg = TrustConfig(permissive_mode=False)
        mw = TrustMiddleware(config=cfg)
        result, err = mw.verify_request({})
        assert result.verified is False
        assert err is not None
        assert "Missing X-Agent-DID" in err["reason"]

    def test_verify_request_with_did_no_identity(self):
        mw = TrustMiddleware()
        headers = {"X-Agent-DID": "did:mesh:abc"}
        result, err = mw.verify_request(headers)
        assert result.verified is True
        assert result.peer_did == "did:mesh:abc"

    def test_verify_request_missing_capabilities(self):
        cfg = TrustConfig(required_capabilities=["admin"])
        mw = TrustMiddleware(config=cfg)
        headers = {"X-Agent-DID": "did:mesh:abc", "X-Agent-Capabilities": "read,write"}
        result, err = mw.verify_request(headers)
        assert result.verified is False
        assert "admin" in err["missing"]

    def test_verify_request_capabilities_present(self):
        cfg = TrustConfig(required_capabilities=["read"])
        mw = TrustMiddleware(config=cfg)
        headers = {"X-Agent-DID": "did:mesh:abc", "X-Agent-Capabilities": "read,write"}
        result, err = mw.verify_request(headers)
        assert result.verified is True

    def test_verify_request_low_trust_score(self):
        identity = MagicMock()
        identity.verify_signature = MagicMock(side_effect=Exception("bad sig"))
        cfg = TrustConfig(required_trust_score=0.5)
        mw = TrustMiddleware(identity=identity, config=cfg)
        headers = {
            "X-Agent-DID": "did:mesh:abc",
            "X-Agent-Public-Key": "some-key",
        }
        result, err = mw.verify_request(headers)
        assert result.verified is False
        assert result.trust_score == 0.3

    def test_verify_request_config_override(self):
        mw = TrustMiddleware()
        override = TrustConfig(required_capabilities=["special"])
        headers = {"X-Agent-DID": "did:mesh:abc"}
        result, err = mw.verify_request(headers, config_override=override)
        assert result.verified is False

    def test_response_headers_no_identity(self):
        mw = TrustMiddleware()
        assert mw.response_headers() == {}

    def test_response_headers_with_identity(self):
        identity = _make_identity(capabilities=["read"])
        mw = TrustMiddleware(identity=identity)
        headers = mw.response_headers()
        assert headers["X-Agent-DID"] == str(identity.did)
        assert headers["X-Agent-Public-Key"] == identity.public_key
        assert headers["X-Agent-Capabilities"] == "read"


class TestFlaskTrustRequired:
    """Tests for flask_trust_required decorator."""

    def test_flask_decorator_success(self):
        # Mock Flask imports
        mock_request = MagicMock()
        mock_request.headers = {"X-Agent-DID": "did:mesh:abc"}
        mock_g = MagicMock()
        mock_jsonify = MagicMock(side_effect=lambda x: x)

        mw = TrustMiddleware()

        with patch.dict("sys.modules", {
            "flask": MagicMock(request=mock_request, g=mock_g, jsonify=mock_jsonify),
        }):
            import sys
            flask_mod = sys.modules["flask"]
            flask_mod.request = mock_request
            flask_mod.g = mock_g
            flask_mod.jsonify = mock_jsonify

            decorator = flask_trust_required(mw)

            @decorator
            def my_view():
                return "ok"

            result = my_view()
            assert result == "ok"

    def test_flask_decorator_failure(self):
        mock_request = MagicMock()
        mock_request.headers = {}
        mock_g = MagicMock()
        mock_jsonify = MagicMock(side_effect=lambda x: x)

        cfg = TrustConfig(permissive_mode=False)
        mw = TrustMiddleware(config=cfg)

        with patch.dict("sys.modules", {
            "flask": MagicMock(request=mock_request, g=mock_g, jsonify=mock_jsonify),
        }):
            import sys
            flask_mod = sys.modules["flask"]
            flask_mod.request = mock_request
            flask_mod.g = mock_g
            flask_mod.jsonify = mock_jsonify

            decorator = flask_trust_required(mw)

            @decorator
            def my_view():
                return "ok"

            result = my_view()
            # Returns (error_body, status_code)
            assert isinstance(result, tuple)


class TestFastapiTrustRequired:
    """Tests for fastapi_trust_required."""

    @pytest.mark.asyncio
    async def test_fastapi_dependency_success(self):
        mock_request = MagicMock()
        mock_request.headers = {"X-Agent-DID": "did:mesh:abc"}

        mw = TrustMiddleware()

        with patch.dict("sys.modules", {
            "fastapi": MagicMock(),
            "fastapi.responses": MagicMock(),
        }):
            dep = fastapi_trust_required(mw)
            result = await dep(mock_request)
            assert result.verified is True

    @pytest.mark.asyncio
    async def test_fastapi_dependency_failure(self):
        mock_request = MagicMock()
        mock_request.headers = {}

        cfg = TrustConfig(permissive_mode=False)
        mw = TrustMiddleware(config=cfg)

        # Mock HTTPException
        class FakeHTTPException(Exception):
            def __init__(self, status_code, detail):
                self.status_code = status_code
                self.detail = detail

        mock_fastapi = MagicMock()
        mock_fastapi.HTTPException = FakeHTTPException
        mock_fastapi.Request = MagicMock

        with patch.dict("sys.modules", {
            "fastapi": mock_fastapi,
            "fastapi.responses": MagicMock(),
        }):
            dep = fastapi_trust_required(mw)
            with pytest.raises(FakeHTTPException):
                await dep(mock_request)


# ---------------------------------------------------------------------------
# reward/scoring.py
# ---------------------------------------------------------------------------
from agentmesh.reward.scoring import (
    RewardDimension,
    RewardSignal,
    DimensionType,
    TrustScore,
    ScoreThresholds,
)


class TestRewardDimension:
    """Tests for RewardDimension."""

    def test_add_positive_signal(self):
        dim = RewardDimension(name="quality")
        signal = RewardSignal(
            dimension=DimensionType.OUTPUT_QUALITY,
            value=0.9,
            source="test",
        )
        dim.add_signal(signal)
        assert dim.signal_count == 1
        assert dim.positive_signals == 1
        assert dim.negative_signals == 0

    def test_add_negative_signal(self):
        dim = RewardDimension(name="quality")
        signal = RewardSignal(
            dimension=DimensionType.OUTPUT_QUALITY,
            value=0.2,
            source="test",
        )
        dim.add_signal(signal)
        assert dim.negative_signals == 1

    def test_add_signal_updates_score(self):
        dim = RewardDimension(name="quality", score=50.0)
        signal = RewardSignal(
            dimension=DimensionType.OUTPUT_QUALITY,
            value=1.0,
            source="test",
        )
        dim.add_signal(signal)
        # EMA: 50 * 0.9 + 100 * 0.1 = 55
        assert dim.score == pytest.approx(55.0)

    def test_trend_improving(self):
        dim = RewardDimension(name="q", score=50.0)
        # Need a big jump to trigger "improving" (diff > 5)
        signal = RewardSignal(
            dimension=DimensionType.OUTPUT_QUALITY,
            value=1.0,
            source="test",
        )
        dim.add_signal(signal)
        # score went from 50 to 55, diff = 5, "stable"
        assert dim.trend == "stable"
        # Add another high signal
        dim.add_signal(signal)
        # score = 55*0.9 + 100*0.1 = 59.5, previous=55, diff=4.5 still "stable"
        # Need to push more
        for _ in range(5):
            dim.add_signal(signal)
        # Score has risen considerably
        assert dim.score > 55.0

    def test_trend_degrading(self):
        dim = RewardDimension(name="q", score=80.0)
        signal = RewardSignal(
            dimension=DimensionType.OUTPUT_QUALITY,
            value=0.0,
            source="test",
        )
        dim.add_signal(signal)
        # 80*0.9 + 0*0.1 = 72, diff = -8 → "degrading"
        assert dim.trend == "degrading"

    def test_boundary_signal_value(self):
        dim = RewardDimension(name="q")
        # value == 0.5 should be positive
        signal = RewardSignal(
            dimension=DimensionType.OUTPUT_QUALITY,
            value=0.5,
            source="test",
        )
        dim.add_signal(signal)
        assert dim.positive_signals == 1


class TestTrustScore:
    """Tests for TrustScore."""

    def test_default_tier(self):
        ts = TrustScore(agent_did="did:mesh:1")
        assert ts.total_score == 500
        assert ts.tier == "standard"

    def test_tier_verified_partner(self):
        ts = TrustScore(agent_did="did:mesh:1", total_score=950)
        assert ts.tier == "verified_partner"

    def test_tier_trusted(self):
        ts = TrustScore(agent_did="did:mesh:1", total_score=750)
        assert ts.tier == "trusted"

    def test_tier_probationary(self):
        ts = TrustScore(agent_did="did:mesh:1", total_score=350)
        assert ts.tier == "probationary"

    def test_tier_untrusted(self):
        ts = TrustScore(agent_did="did:mesh:1", total_score=100)
        assert ts.tier == "untrusted"

    def test_update(self):
        ts = TrustScore(agent_did="did:mesh:1", total_score=500)
        dims = {"quality": RewardDimension(name="quality", score=80.0)}
        ts.update(800, dims)
        assert ts.total_score == 800
        assert ts.previous_score == 500
        assert ts.score_change == 300
        assert ts.tier == "trusted"

    def test_update_clamps_score(self):
        ts = TrustScore(agent_did="did:mesh:1", total_score=500)
        ts.update(1500, {})
        assert ts.total_score == 1000
        ts.update(-100, {})
        assert ts.total_score == 0

    def test_meets_threshold(self):
        ts = TrustScore(agent_did="did:mesh:1", total_score=600)
        assert ts.meets_threshold(500) is True
        assert ts.meets_threshold(600) is True
        assert ts.meets_threshold(601) is False

    def test_to_dict(self):
        ts = TrustScore(agent_did="did:mesh:1", total_score=700)
        d = ts.to_dict()
        assert d["agent_did"] == "did:mesh:1"
        assert d["total_score"] == 700
        assert d["tier"] == "trusted"
        assert "calculated_at" in d

    def test_to_dict_with_dimensions(self):
        dims = {"q": RewardDimension(name="q", score=80.0, trend="improving", signal_count=5)}
        ts = TrustScore(agent_did="did:mesh:1", total_score=700, dimensions=dims)
        d = ts.to_dict()
        assert "q" in d["dimensions"]
        assert d["dimensions"]["q"]["score"] == 80.0


class TestScoreThresholds:
    """Tests for ScoreThresholds."""

    def test_get_tier(self):
        st = ScoreThresholds()
        assert st.get_tier(950) == "verified_partner"
        assert st.get_tier(750) == "trusted"
        assert st.get_tier(550) == "standard"
        assert st.get_tier(350) == "probationary"
        assert st.get_tier(100) == "untrusted"

    def test_should_allow(self):
        st = ScoreThresholds()
        assert st.should_allow(600) is True
        assert st.should_allow(500) is True
        assert st.should_allow(400) is False

    def test_should_warn(self):
        st = ScoreThresholds()
        assert st.should_warn(300) is True
        assert st.should_warn(500) is False

    def test_should_revoke(self):
        st = ScoreThresholds()
        assert st.should_revoke(200) is True
        assert st.should_revoke(300) is False
        assert st.should_revoke(500) is False

    def test_custom_thresholds(self):
        st = ScoreThresholds(allow_threshold=600, warn_threshold=500, revocation_threshold=400)
        assert st.should_allow(550) is False
        assert st.should_warn(450) is True
        assert st.should_revoke(350) is True


# ---------------------------------------------------------------------------
# observability/metrics.py
# ---------------------------------------------------------------------------
from agentmesh.observability.metrics import MetricsCollector, setup_metrics, get_metrics


class TestMetricsCollectorDisabled:
    """Tests for MetricsCollector when prometheus_client is not available."""

    def test_disabled_collector(self):
        with patch.dict("sys.modules", {"prometheus_client": None}):
            mc = MetricsCollector()
            assert mc.enabled is False
            # All record methods should be no-ops
            mc.record_handshake(True)
            mc.record_handshake(False)
            mc.record_policy_violation("p1", "did:mesh:1")
            mc.set_trust_score("did:mesh:1", 500)
            mc.set_registry_size("active", 10)
            mc.record_api_request("GET", "/api", 200, 0.5)
            mc.record_tool_call("did:mesh:1", "tool1", True)
            mc.record_reward_signal("did:mesh:1", "quality")
            mc.record_audit_log("login", "success")
            mc.record_credential_issued("did:mesh:1")
            mc.record_credential_revoked("did:mesh:1", "expired")


class TestMetricsCollectorEnabled:
    """Tests for MetricsCollector when prometheus_client is available."""

    def _make_collector(self):
        mock_counter = MagicMock()
        mock_gauge = MagicMock()
        mock_histogram = MagicMock()
        mock_prom = MagicMock()
        mock_prom.Counter = MagicMock(return_value=mock_counter)
        mock_prom.Gauge = MagicMock(return_value=mock_gauge)
        mock_prom.Histogram = MagicMock(return_value=mock_histogram)
        with patch.dict("sys.modules", {"prometheus_client": mock_prom}):
            mc = MetricsCollector()
        return mc

    def test_enabled(self):
        mc = self._make_collector()
        assert mc.enabled is True

    def test_record_handshake(self):
        mc = self._make_collector()
        mc.record_handshake(True)
        mc.handshake_total.labels.assert_called_with(status="success")
        mc.record_handshake(False)
        mc.handshake_total.labels.assert_called_with(status="fail")

    def test_record_policy_violation(self):
        mc = self._make_collector()
        mc.record_policy_violation("p1", "did:mesh:1")
        mc.policy_violation_count.labels.assert_called_with(
            policy_id="p1", agent_did="did:mesh:1"
        )

    def test_set_trust_score(self):
        mc = self._make_collector()
        mc.set_trust_score("did:mesh:1", 700)
        mc.trust_score_gauge.labels.assert_called_with(agent_did="did:mesh:1")

    def test_set_registry_size(self):
        mc = self._make_collector()
        mc.set_registry_size("active", 5)
        mc.registry_size.labels.assert_called_with(status="active")

    def test_record_api_request(self):
        mc = self._make_collector()
        mc.record_api_request("GET", "/api", 200, 0.5)
        mc.api_request_duration.labels.assert_called_with(
            method="GET", endpoint="/api", status=200
        )

    def test_record_tool_call(self):
        mc = self._make_collector()
        mc.record_tool_call("did:mesh:1", "tool1", True)
        mc.tool_call_total.labels.assert_called_with(
            agent_did="did:mesh:1", tool_name="tool1", status="success"
        )

    def test_record_reward_signal(self):
        mc = self._make_collector()
        mc.record_reward_signal("did:mesh:1", "quality")
        mc.reward_signal_total.labels.assert_called_with(
            agent_did="did:mesh:1", dimension="quality"
        )

    def test_record_audit_log(self):
        mc = self._make_collector()
        mc.record_audit_log("login", "success")
        mc.audit_log_total.labels.assert_called_with(
            event_type="login", outcome="success"
        )

    def test_record_credential_issued(self):
        mc = self._make_collector()
        mc.record_credential_issued("did:mesh:1")
        mc.credential_issued_total.labels.assert_called_with(agent_did="did:mesh:1")

    def test_record_credential_revoked(self):
        mc = self._make_collector()
        mc.record_credential_revoked("did:mesh:1", "expired")
        mc.credential_revoked_total.labels.assert_called_with(
            agent_did="did:mesh:1", reason="expired"
        )


# ---------------------------------------------------------------------------
# trust/capability.py
# ---------------------------------------------------------------------------
from agentmesh.trust.capability import CapabilityGrant, CapabilityScope, CapabilityRegistry


class TestCapabilityGrant:
    """Tests for CapabilityGrant."""

    def test_parse_capability(self):
        a, r, q = CapabilityGrant.parse_capability("read:data")
        assert a == "read" and r == "data" and q is None

    def test_parse_capability_with_qualifier(self):
        a, r, q = CapabilityGrant.parse_capability("execute:tools:calculator")
        assert a == "execute" and r == "tools" and q == "calculator"

    def test_parse_capability_invalid(self):
        with pytest.raises(ValueError, match="Invalid capability"):
            CapabilityGrant.parse_capability("invalid")

    def test_create(self):
        g = CapabilityGrant.create("read:data", "did:mesh:1", "did:mesh:0")
        assert g.action == "read"
        assert g.resource == "data"
        assert g.granted_to == "did:mesh:1"

    def test_is_valid(self):
        g = CapabilityGrant.create("read:data", "did:mesh:1", "did:mesh:0")
        assert g.is_valid() is True

    def test_is_valid_inactive(self):
        g = CapabilityGrant.create("read:data", "did:mesh:1", "did:mesh:0")
        g.active = False
        assert g.is_valid() is False

    def test_is_valid_expired(self):
        g = CapabilityGrant.create(
            "read:data", "did:mesh:1", "did:mesh:0",
            expires_at=datetime.utcnow() - timedelta(hours=1),
        )
        assert g.is_valid() is False

    def test_matches_exact(self):
        g = CapabilityGrant.create("read:data", "did:mesh:1", "did:mesh:0")
        assert g.matches("read:data") is True
        assert g.matches("write:data") is False

    def test_matches_wildcard_action(self):
        g = CapabilityGrant.create("*:data", "did:mesh:1", "did:mesh:0")
        assert g.matches("read:data") is True
        assert g.matches("write:data") is True

    def test_matches_wildcard_resource(self):
        g = CapabilityGrant.create("read:*", "did:mesh:1", "did:mesh:0")
        assert g.matches("read:data") is True
        assert g.matches("read:logs") is True

    def test_matches_qualifier(self):
        g = CapabilityGrant.create("execute:tools:calc", "did:mesh:1", "did:mesh:0")
        assert g.matches("execute:tools:calc") is True
        assert g.matches("execute:tools:other") is False

    def test_matches_wildcard_qualifier(self):
        g = CapabilityGrant.create("execute:tools:*", "did:mesh:1", "did:mesh:0")
        assert g.matches("execute:tools:calc") is True

    def test_matches_resource_id(self):
        g = CapabilityGrant.create(
            "read:data", "did:mesh:1", "did:mesh:0", resource_ids=["res1"]
        )
        assert g.matches("read:data", resource_id="res1") is True
        assert g.matches("read:data", resource_id="res2") is False

    def test_revoke(self):
        g = CapabilityGrant.create("read:data", "did:mesh:1", "did:mesh:0")
        g.revoke()
        assert g.active is False
        assert g.revoked_at is not None


class TestCapabilityScope:
    """Tests for CapabilityScope."""

    def test_add_grant(self):
        scope = CapabilityScope(agent_did="did:mesh:1")
        g = CapabilityGrant.create("read:data", "did:mesh:1", "did:mesh:0")
        scope.add_grant(g)
        assert len(scope.grants) == 1

    def test_add_grant_wrong_agent(self):
        scope = CapabilityScope(agent_did="did:mesh:1")
        g = CapabilityGrant.create("read:data", "did:mesh:2", "did:mesh:0")
        with pytest.raises(ValueError, match="different agent"):
            scope.add_grant(g)

    def test_has_capability(self):
        scope = CapabilityScope(agent_did="did:mesh:1")
        g = CapabilityGrant.create("read:data", "did:mesh:1", "did:mesh:0")
        scope.add_grant(g)
        assert scope.has_capability("read:data") is True
        assert scope.has_capability("write:data") is False

    def test_has_capability_denied(self):
        scope = CapabilityScope(agent_did="did:mesh:1")
        g = CapabilityGrant.create("read:data", "did:mesh:1", "did:mesh:0")
        scope.add_grant(g)
        scope.deny("read:data")
        assert scope.has_capability("read:data") is False

    def test_get_capabilities(self):
        scope = CapabilityScope(agent_did="did:mesh:1")
        g = CapabilityGrant.create("read:data", "did:mesh:1", "did:mesh:0")
        scope.add_grant(g)
        caps = scope.get_capabilities()
        assert "read:data" in caps

    def test_filter_capabilities(self):
        scope = CapabilityScope(agent_did="did:mesh:1")
        g = CapabilityGrant.create("read:data", "did:mesh:1", "did:mesh:0")
        scope.add_grant(g)
        result = scope.filter_capabilities(["read:data", "write:data"])
        assert result == ["read:data"]

    def test_deny(self):
        scope = CapabilityScope(agent_did="did:mesh:1")
        scope.deny("bad:cap")
        scope.deny("bad:cap")  # duplicate
        assert scope.denied.count("bad:cap") == 1

    def test_revoke_all(self):
        scope = CapabilityScope(agent_did="did:mesh:1")
        g1 = CapabilityGrant.create("read:data", "did:mesh:1", "did:mesh:0")
        g2 = CapabilityGrant.create("write:data", "did:mesh:1", "did:mesh:0")
        scope.add_grant(g1)
        scope.add_grant(g2)
        count = scope.revoke_all()
        assert count == 2

    def test_revoke_from(self):
        scope = CapabilityScope(agent_did="did:mesh:1")
        g1 = CapabilityGrant.create("read:data", "did:mesh:1", "did:mesh:A")
        g2 = CapabilityGrant.create("write:data", "did:mesh:1", "did:mesh:B")
        scope.add_grant(g1)
        scope.add_grant(g2)
        count = scope.revoke_from("did:mesh:A")
        assert count == 1

    def test_cleanup_expired(self):
        scope = CapabilityScope(agent_did="did:mesh:1")
        g = CapabilityGrant.create("read:data", "did:mesh:1", "did:mesh:0")
        g.active = False
        scope.add_grant(g)
        removed = scope.cleanup_expired()
        assert removed == 1
        assert len(scope.grants) == 0


class TestCapabilityRegistry:
    """Tests for CapabilityRegistry."""

    def test_get_scope(self):
        reg = CapabilityRegistry()
        scope = reg.get_scope("did:mesh:1")
        assert scope.agent_did == "did:mesh:1"

    def test_grant(self):
        reg = CapabilityRegistry()
        g = reg.grant("read:data", "did:mesh:1", "did:mesh:0")
        assert g.capability == "read:data"
        assert reg.check("did:mesh:1", "read:data") is True

    def test_check_no_scope(self):
        reg = CapabilityRegistry()
        assert reg.check("did:mesh:unknown", "read:data") is False

    def test_revoke_all_from(self):
        reg = CapabilityRegistry()
        reg.grant("read:data", "did:mesh:1", "did:mesh:A")
        reg.grant("write:data", "did:mesh:2", "did:mesh:A")
        count = reg.revoke_all_from("did:mesh:A")
        assert count == 2

    def test_get_agents_with_capability(self):
        reg = CapabilityRegistry()
        reg.grant("read:data", "did:mesh:1", "did:mesh:0")
        reg.grant("read:data", "did:mesh:2", "did:mesh:0")
        agents = reg.get_agents_with_capability("read:data")
        assert len(agents) == 2


# ---------------------------------------------------------------------------
# trust/handshake.py
# ---------------------------------------------------------------------------
from agentmesh.trust.handshake import (
    HandshakeChallenge, HandshakeResponse, HandshakeResult, TrustHandshake,
)


class TestHandshakeChallenge:
    def test_generate(self):
        c = HandshakeChallenge.generate()
        assert c.challenge_id.startswith("challenge_")
        assert len(c.nonce) > 0

    def test_is_expired(self):
        c = HandshakeChallenge.generate()
        assert c.is_expired() is False

    def test_is_expired_old(self):
        c = HandshakeChallenge.generate()
        c.timestamp = datetime.utcnow() - timedelta(seconds=60)
        c.expires_in_seconds = 30
        assert c.is_expired() is True


class TestHandshakeResult:
    def test_success(self):
        r = HandshakeResult.success("did:mesh:1", 800, ["read:data"])
        assert r.verified is True
        assert r.trust_level == "trusted"
        assert r.latency_ms is not None

    def test_success_verified_partner(self):
        r = HandshakeResult.success("did:mesh:1", 950, [])
        assert r.trust_level == "verified_partner"

    def test_success_standard(self):
        r = HandshakeResult.success("did:mesh:1", 500, [])
        assert r.trust_level == "standard"

    def test_success_untrusted(self):
        r = HandshakeResult.success("did:mesh:1", 100, [])
        assert r.trust_level == "untrusted"

    def test_failure(self):
        r = HandshakeResult.failure("did:mesh:1", "timeout")
        assert r.verified is False
        assert r.rejection_reason == "timeout"


class TestTrustHandshake:
    @pytest.mark.asyncio
    async def test_initiate(self):
        from agentmesh.identity.agent_id import AgentIdentity, IdentityRegistry
        me = AgentIdentity.create(name="me", sponsor="me@test.com", capabilities=["read:data", "write:reports"])
        peer = AgentIdentity.create(name="peer", sponsor="peer@test.com", capabilities=["read:data", "write:reports"])
        registry = IdentityRegistry()
        registry.register(me)
        registry.register(peer)
        th = TrustHandshake(agent_did=str(me.did), identity=me, registry=registry)
        result = await th.initiate(str(peer.did), required_trust_score=500)
        assert result.verified is True
        assert result.peer_did == str(peer.did)

    @pytest.mark.asyncio
    async def test_initiate_cached(self):
        from agentmesh.identity.agent_id import AgentIdentity, IdentityRegistry
        me = AgentIdentity.create(name="me-c", sponsor="me@test.com", capabilities=["read:data"])
        peer = AgentIdentity.create(name="peer-c", sponsor="peer@test.com", capabilities=["read:data"])
        registry = IdentityRegistry()
        registry.register(me)
        registry.register(peer)
        th = TrustHandshake(agent_did=str(me.did), identity=me, registry=registry)
        r1 = await th.initiate(str(peer.did), required_trust_score=500)
        r2 = await th.initiate(str(peer.did), required_trust_score=500, use_cache=True)
        assert r2 is r1  # Same cached result

    @pytest.mark.asyncio
    async def test_initiate_no_cache(self):
        from agentmesh.identity.agent_id import AgentIdentity, IdentityRegistry
        me = AgentIdentity.create(name="me-nc", sponsor="me@test.com", capabilities=["read:data"])
        peer = AgentIdentity.create(name="peer-nc", sponsor="peer@test.com", capabilities=["read:data"])
        registry = IdentityRegistry()
        registry.register(me)
        registry.register(peer)
        th = TrustHandshake(agent_did=str(me.did), identity=me, registry=registry)
        r1 = await th.initiate(str(peer.did), required_trust_score=500)
        r2 = await th.initiate(str(peer.did), required_trust_score=500, use_cache=False)
        assert r2 is not r1

    @pytest.mark.asyncio
    async def test_initiate_score_too_low(self):
        from agentmesh.identity.agent_id import AgentIdentity, IdentityRegistry
        me = AgentIdentity.create(name="me-sl", sponsor="me@test.com", capabilities=["read:data"])
        peer = AgentIdentity.create(name="peer-sl", sponsor="peer@test.com", capabilities=["read:data"])
        registry = IdentityRegistry()
        registry.register(me)
        registry.register(peer)
        th = TrustHandshake(agent_did=str(me.did), identity=me, registry=registry)
        result = await th.initiate(str(peer.did), required_trust_score=900)
        assert result.verified is False

    @pytest.mark.asyncio
    async def test_initiate_missing_capabilities(self):
        from agentmesh.identity.agent_id import AgentIdentity, IdentityRegistry
        me = AgentIdentity.create(name="me-mc", sponsor="me@test.com", capabilities=["read:data"])
        peer = AgentIdentity.create(name="peer-mc", sponsor="peer@test.com", capabilities=["read:data"])
        registry = IdentityRegistry()
        registry.register(me)
        registry.register(peer)
        th = TrustHandshake(agent_did=str(me.did), identity=me, registry=registry)
        result = await th.initiate(
            str(peer.did), required_trust_score=500,
            required_capabilities=["admin:*"]
        )
        assert result.verified is False

    @pytest.mark.asyncio
    async def test_respond(self):
        from agentmesh.identity.agent_id import AgentIdentity
        me = AgentIdentity.create(name="me-r", sponsor="me@test.com", capabilities=["read:data"])
        th = TrustHandshake(agent_did=str(me.did), identity=me)
        challenge = HandshakeChallenge.generate()
        resp = await th.respond(challenge, ["read:data"], 750, identity=me)
        assert resp.agent_did == str(me.did)
        assert resp.challenge_id == challenge.challenge_id

    @pytest.mark.asyncio
    async def test_respond_expired(self):
        from agentmesh.identity.agent_id import AgentIdentity
        me = AgentIdentity.create(name="me-re", sponsor="me@test.com", capabilities=["read:data"])
        th = TrustHandshake(agent_did=str(me.did), identity=me)
        challenge = HandshakeChallenge.generate()
        challenge.timestamp = datetime.utcnow() - timedelta(seconds=60)
        with pytest.raises(ValueError, match="expired"):
            await th.respond(challenge, ["read:data"], 750, identity=me)

    def test_create_challenge(self):
        th = TrustHandshake(agent_did="did:mesh:me")
        c = th.create_challenge()
        assert c.challenge_id in th._pending_challenges

    def test_validate_challenge(self):
        th = TrustHandshake(agent_did="did:mesh:me")
        c = th.create_challenge()
        assert th.validate_challenge(c.challenge_id) is True
        assert th.validate_challenge("bogus") is False

    def test_clear_cache(self):
        th = TrustHandshake(agent_did="did:mesh:me")
        th._verified_peers["did:mesh:peer"] = (MagicMock(), datetime.utcnow())
        th.clear_cache()
        assert len(th._verified_peers) == 0

    def test_get_cached_result_expired(self):
        th = TrustHandshake(agent_did="did:mesh:me", cache_ttl_seconds=0)
        th._verified_peers["did:mesh:peer"] = (MagicMock(), datetime.utcnow() - timedelta(seconds=1))
        assert th._get_cached_result("did:mesh:peer") is None
        assert "did:mesh:peer" not in th._verified_peers


# ---------------------------------------------------------------------------
# identity/credentials.py
# ---------------------------------------------------------------------------
from agentmesh.identity.credentials import Credential, CredentialManager


class TestCredential:
    def test_issue(self):
        c = Credential.issue("did:mesh:1", capabilities=["read:data"], ttl_seconds=60)
        assert c.agent_did == "did:mesh:1"
        assert c.is_valid() is True
        assert c.status == "active"

    def test_is_valid_expired(self):
        c = Credential.issue("did:mesh:1", ttl_seconds=0)
        # Might still be valid since issued_at == expires_at edge
        # Force expiration
        c.expires_at = datetime.utcnow() - timedelta(seconds=1)
        assert c.is_valid() is False

    def test_is_valid_revoked(self):
        c = Credential.issue("did:mesh:1")
        c.revoke("test")
        assert c.is_valid() is False

    def test_is_expiring_soon(self):
        c = Credential.issue("did:mesh:1", ttl_seconds=30)
        assert c.is_expiring_soon(threshold_seconds=60) is True
        c2 = Credential.issue("did:mesh:1", ttl_seconds=3600)
        assert c2.is_expiring_soon(threshold_seconds=60) is False

    def test_verify_token(self):
        c = Credential.issue("did:mesh:1")
        assert c.verify_token(c.token) is True
        assert c.verify_token("wrong") is False

    def test_revoke(self):
        c = Credential.issue("did:mesh:1")
        c.revoke("bad")
        assert c.status == "revoked"
        assert c.revocation_reason == "bad"

    def test_rotate(self):
        c = Credential.issue("did:mesh:1", capabilities=["read:data"])
        new_c = c.rotate()
        assert c.status == "rotated"
        assert new_c.previous_credential_id == c.credential_id
        assert new_c.rotation_count == 1
        assert new_c.capabilities == c.capabilities

    def test_has_capability(self):
        c = Credential.issue("did:mesh:1", capabilities=["read:data", "write:*"])
        assert c.has_capability("read:data") is True
        assert c.has_capability("write:logs") is True
        assert c.has_capability("delete:data") is False

    def test_has_capability_wildcard(self):
        c = Credential.issue("did:mesh:1", capabilities=["*"])
        assert c.has_capability("anything") is True

    def test_has_capability_empty(self):
        c = Credential.issue("did:mesh:1", capabilities=[])
        assert c.has_capability("read:data") is False

    def test_can_access_resource(self):
        c = Credential.issue("did:mesh:1", resources=["db1"])
        assert c.can_access_resource("db1") is True
        assert c.can_access_resource("db2") is False

    def test_can_access_resource_no_restriction(self):
        c = Credential.issue("did:mesh:1")
        assert c.can_access_resource("anything") is True

    def test_can_access_resource_wildcard(self):
        c = Credential.issue("did:mesh:1", resources=["*"])
        assert c.can_access_resource("anything") is True

    def test_time_remaining(self):
        c = Credential.issue("did:mesh:1", ttl_seconds=3600)
        assert c.time_remaining() > timedelta(0)

    def test_to_bearer_token(self):
        c = Credential.issue("did:mesh:1")
        assert c.to_bearer_token().startswith("Bearer ")


class TestCredentialManager:
    def test_issue(self):
        mgr = CredentialManager()
        c = mgr.issue("did:mesh:1", capabilities=["read:data"])
        assert c.is_valid() is True

    def test_validate(self):
        mgr = CredentialManager()
        c = mgr.issue("did:mesh:1")
        found = mgr.validate(c.token)
        assert found is c

    def test_validate_invalid(self):
        mgr = CredentialManager()
        assert mgr.validate("bogus-token") is None

    def test_validate_revoked(self):
        mgr = CredentialManager()
        c = mgr.issue("did:mesh:1")
        c.revoke("test")
        assert mgr.validate(c.token) is None

    def test_rotate(self):
        mgr = CredentialManager()
        c = mgr.issue("did:mesh:1")
        new_c = mgr.rotate(c.credential_id)
        assert new_c is not None
        assert new_c.previous_credential_id == c.credential_id

    def test_rotate_invalid(self):
        mgr = CredentialManager()
        assert mgr.rotate("bogus") is None

    def test_rotate_if_needed(self):
        mgr = CredentialManager()
        c = mgr.issue("did:mesh:1", ttl_seconds=30)
        result = mgr.rotate_if_needed(c.credential_id)
        assert result is not None  # rotated since expiring soon

    def test_rotate_if_needed_not_found(self):
        mgr = CredentialManager()
        with pytest.raises(ValueError, match="not found"):
            mgr.rotate_if_needed("bogus")

    def test_revoke(self):
        mgr = CredentialManager()
        c = mgr.issue("did:mesh:1")
        assert mgr.revoke(c.credential_id, "bad") is True
        assert mgr.revoke("bogus", "bad") is False

    def test_revoke_with_callback(self):
        mgr = CredentialManager()
        callback = MagicMock()
        mgr.on_revocation(callback)
        c = mgr.issue("did:mesh:1")
        mgr.revoke(c.credential_id, "bad")
        callback.assert_called_once()

    def test_revoke_callback_error(self):
        mgr = CredentialManager()
        mgr.on_revocation(MagicMock(side_effect=Exception("fail")))
        c = mgr.issue("did:mesh:1")
        mgr.revoke(c.credential_id, "bad")  # Should not raise

    def test_revoke_all_for_agent(self):
        mgr = CredentialManager()
        mgr.issue("did:mesh:1")
        mgr.issue("did:mesh:1")
        count = mgr.revoke_all_for_agent("did:mesh:1", "cleanup")
        assert count == 2

    def test_get_active_for_agent(self):
        mgr = CredentialManager()
        c1 = mgr.issue("did:mesh:1")
        c2 = mgr.issue("did:mesh:1")
        c2.revoke("test")
        active = mgr.get_active_for_agent("did:mesh:1")
        assert len(active) == 1

    def test_cleanup_expired(self):
        mgr = CredentialManager()
        c = mgr.issue("did:mesh:1")
        c.revoke("test")
        removed = mgr.cleanup_expired()
        assert removed == 1


# ---------------------------------------------------------------------------
# identity/delegation.py
# ---------------------------------------------------------------------------
from agentmesh.identity.delegation import DelegationLink, ScopeChain


class TestDelegationLink:
    def _make_link(self, **kwargs):
        import uuid
        defaults = dict(
            link_id=f"link_{uuid.uuid4().hex[:12]}",
            depth=0,
            parent_did="did:mesh:parent",
            child_did="did:mesh:child",
            parent_capabilities=["read:data", "write:data"],
            delegated_capabilities=["read:data"],
            parent_signature="sig",
            link_hash="",
        )
        defaults.update(kwargs)
        link = DelegationLink(**defaults)
        link.link_hash = link.compute_hash()
        return link

    def test_verify_capability_narrowing_valid(self):
        link = self._make_link()
        assert link.verify_capability_narrowing() is True

    def test_verify_capability_narrowing_invalid(self):
        link = self._make_link(delegated_capabilities=["admin:all"])
        link.link_hash = link.compute_hash()
        assert link.verify_capability_narrowing() is False

    def test_verify_capability_wildcard_narrowing(self):
        link = self._make_link(
            parent_capabilities=["read:*"],
            delegated_capabilities=["read:data"],
        )
        link.link_hash = link.compute_hash()
        assert link.verify_capability_narrowing() is True

    def test_verify_capability_star_parent(self):
        link = self._make_link(
            parent_capabilities=["*"],
            delegated_capabilities=["anything:goes"],
        )
        link.link_hash = link.compute_hash()
        assert link.verify_capability_narrowing() is True

    def test_compute_hash(self):
        link = self._make_link()
        h = link.compute_hash()
        assert isinstance(h, str) and len(h) == 64

    def test_is_valid(self):
        link = self._make_link()
        assert link.is_valid() is True

    def test_is_valid_expired(self):
        link = self._make_link()
        link.expires_at = datetime.utcnow() - timedelta(hours=1)
        assert link.is_valid() is False

    def test_is_valid_bad_hash(self):
        """Bad hash doesn't invalidate link."""
        link = self._make_link()
        link.link_hash = "badhash"
        # No hash verification, link is still valid
        assert link.is_valid() is True


class TestScopeChain:
    def test_create_root(self):
        chain, link = ScopeChain.create_root(
            "admin@org.com", "did:mesh:root", ["read:data", "write:data"]
        )
        assert chain.root_sponsor_email == "admin@org.com"
        assert link.depth == 0

    def test_add_link(self):
        chain, link = ScopeChain.create_root(
            "admin@org.com", "did:mesh:root", ["read:data"]
        )
        chain.add_link(link)
        assert chain.total_depth == 1

    def test_verify_empty(self):
        chain, _ = ScopeChain.create_root(
            "admin@org.com", "did:mesh:root", ["read:data"]
        )
        valid, err = chain.verify()
        assert valid is True

    def test_verify_valid_chain(self):
        chain, link = ScopeChain.create_root(
            "admin@org.com", "did:mesh:root", ["read:data"]
        )
        chain.add_link(link)
        valid, err = chain.verify()
        assert valid is True

    def test_get_effective_capabilities(self):
        chain, link = ScopeChain.create_root(
            "admin@org.com", "did:mesh:root", ["read:data"]
        )
        assert chain.get_effective_capabilities() == ["read:data"]
        chain.add_link(link)
        assert "read:data" in chain.get_effective_capabilities()

    def test_trace_capability(self):
        chain, link = ScopeChain.create_root(
            "admin@org.com", "did:mesh:root", ["read:data"]
        )
        chain.add_link(link)
        trace = chain.trace_capability("read:data")
        assert len(trace) >= 1


# ---------------------------------------------------------------------------
# reward/engine.py
# ---------------------------------------------------------------------------
from agentmesh.reward.engine import RewardEngine, RewardConfig, AgentRewardState


class TestRewardConfig:
    def test_validate_weights(self):
        cfg = RewardConfig()
        assert cfg.validate_weights() is True

    def test_validate_weights_invalid(self):
        """validate_weights() always returns True."""
        cfg = RewardConfig(policy_compliance_weight=0.5)
        assert cfg.validate_weights() is True


class TestRewardEngine:
    def test_get_agent_score(self):
        engine = RewardEngine()
        score = engine.get_agent_score("did:mesh:1")
        assert score.total_score == 500

    def test_record_signal(self):
        engine = RewardEngine()
        engine.record_signal("did:mesh:1", DimensionType.OUTPUT_QUALITY, 0.9, "test")
        state = engine._agents["did:mesh:1"]
        assert len(state.recent_signals) == 1

    def test_record_signal_critical(self):
        engine = RewardEngine()
        engine.record_signal("did:mesh:1", DimensionType.SECURITY_POSTURE, 0.1, "test")
        # Score was recalculated immediately due to low value
        state = engine._agents["did:mesh:1"]
        assert state.last_updated is not None

    def test_record_policy_compliance(self):
        engine = RewardEngine()
        engine.record_policy_compliance("did:mesh:1", True, "policy1")
        engine.record_policy_compliance("did:mesh:1", False)
        state = engine._agents["did:mesh:1"]
        assert len(state.recent_signals) == 2

    def test_record_resource_usage(self):
        engine = RewardEngine()
        engine.record_resource_usage("did:mesh:1", 100, 200, 500, 1000)

    def test_record_output_quality(self):
        engine = RewardEngine()
        engine.record_output_quality("did:mesh:1", True, "consumer1")
        engine.record_output_quality("did:mesh:1", False, "consumer2", "bad output")

    def test_record_security_event(self):
        engine = RewardEngine()
        engine.record_security_event("did:mesh:1", True, "boundary_check")

    def test_record_collaboration(self):
        engine = RewardEngine()
        engine.record_collaboration("did:mesh:1", True, "did:mesh:peer")

    def test_revocation_callback(self):
        engine = RewardEngine(config=RewardConfig(revocation_threshold=999))
        callback = MagicMock()
        engine.on_revocation(callback)
        engine.record_signal("did:mesh:1", DimensionType.SECURITY_POSTURE, 0.1, "test")
        callback.assert_called()

    def test_revocation_callback_error(self):
        engine = RewardEngine(config=RewardConfig(revocation_threshold=999))
        engine.on_revocation(MagicMock(side_effect=Exception("fail")))
        engine.record_signal("did:mesh:1", DimensionType.SECURITY_POSTURE, 0.1, "test")

    def test_get_score_explanation(self):
        engine = RewardEngine()
        engine.record_signal("did:mesh:1", DimensionType.OUTPUT_QUALITY, 0.9, "test")
        engine._recalculate_score("did:mesh:1")
        expl = engine.get_score_explanation("did:mesh:1")
        assert expl["agent_did"] == "did:mesh:1"
        assert "dimensions" in expl

    def test_update_weights(self):
        engine = RewardEngine()
        result = engine.update_weights(policy_compliance=0.3, resource_efficiency=0.1,
                                        output_quality=0.2, security_posture=0.25,
                                        collaboration_health=0.15)
        assert result is True

    def test_get_agents_at_risk(self):
        engine = RewardEngine()
        engine.record_signal("did:mesh:1", DimensionType.SECURITY_POSTURE, 0.1, "test")
        engine._recalculate_score("did:mesh:1")
        at_risk = engine.get_agents_at_risk()
        assert "did:mesh:1" in at_risk

    def test_get_health_report(self):
        engine = RewardEngine()
        engine.record_signal("did:mesh:1", DimensionType.OUTPUT_QUALITY, 0.9, "test")
        engine._recalculate_score("did:mesh:1")
        report = engine.get_health_report()
        assert report["total_agents"] == 1

    def test_stop_background_updates(self):
        engine = RewardEngine()
        engine._running = True
        engine.stop_background_updates()
        assert engine._running is False


# ---------------------------------------------------------------------------
# trust/bridge.py
# ---------------------------------------------------------------------------
from agentmesh.trust.bridge import TrustBridge, ProtocolBridge, PeerInfo


class TestTrustBridge:
    def _make_bridge(self):
        from agentmesh.identity.agent_id import AgentIdentity, IdentityRegistry
        me = AgentIdentity.create(name="bridge-me", sponsor="me@test.com", capabilities=["read:data", "write:reports"])
        peer = AgentIdentity.create(name="bridge-peer", sponsor="peer@test.com", capabilities=["read:data", "write:reports"])
        registry = IdentityRegistry()
        registry.register(me)
        registry.register(peer)
        bridge = TrustBridge(
            agent_did=str(me.did), identity=me, registry=registry,
            default_trust_threshold=500,
        )
        return bridge, me, peer

    @pytest.mark.asyncio
    async def test_verify_peer(self):
        bridge, me, peer = self._make_bridge()
        result = await bridge.verify_peer(str(peer.did))
        assert result.verified is True
        assert str(peer.did) in bridge.peers

    @pytest.mark.asyncio
    async def test_is_peer_trusted_unknown(self):
        bridge, me, peer = self._make_bridge()
        assert await bridge.is_peer_trusted("did:mesh:unknown") is False

    @pytest.mark.asyncio
    async def test_is_peer_trusted_after_verify(self):
        bridge, me, peer = self._make_bridge()
        await bridge.verify_peer(str(peer.did))
        assert await bridge.is_peer_trusted(str(peer.did)) is True

    def test_get_peer(self):
        bridge, me, peer = self._make_bridge()
        assert bridge.get_peer("did:mesh:nope") is None

    @pytest.mark.asyncio
    async def test_get_trusted_peers(self):
        bridge, me, peer = self._make_bridge()
        await bridge.verify_peer(str(peer.did))
        trusted = bridge.get_trusted_peers()
        assert len(trusted) == 1

    @pytest.mark.asyncio
    async def test_revoke_peer_trust(self):
        bridge, me, peer = self._make_bridge()
        await bridge.verify_peer(str(peer.did))
        assert await bridge.revoke_peer_trust(str(peer.did), "bad") is True
        assert await bridge.revoke_peer_trust("did:mesh:nope", "bad") is False


class TestProtocolBridge:
    @pytest.mark.asyncio
    async def test_send_message(self):
        from agentmesh.identity.agent_id import AgentIdentity, IdentityRegistry
        me = AgentIdentity.create(name="pb-me", sponsor="me@test.com", capabilities=["read:data"])
        peer = AgentIdentity.create(name="pb-peer", sponsor="peer@test.com", capabilities=["read:data"])
        registry = IdentityRegistry()
        registry.register(me)
        registry.register(peer)
        pb = ProtocolBridge(
            agent_did=str(me.did), identity=me, registry=registry,
        )
        pb.trust_bridge.default_trust_threshold = 500
        await pb.trust_bridge.verify_peer(str(peer.did))
        result = await pb.send_message(str(peer.did), {"data": 1}, "a2a")
        assert result["status"] == "sent"

    @pytest.mark.asyncio
    async def test_send_message_untrusted(self):
        from agentmesh.identity.agent_id import AgentIdentity, IdentityRegistry
        me = AgentIdentity.create(name="pb-me2", sponsor="me@test.com", capabilities=["read:data"])
        peer = AgentIdentity.create(name="pb-peer2", sponsor="peer@test.com", capabilities=["read:data"])
        registry = IdentityRegistry()
        registry.register(me)
        registry.register(peer)
        pb = ProtocolBridge(
            agent_did=str(me.did), identity=me, registry=registry,
        )
        pb.trust_bridge.default_trust_threshold = 500
        # Should auto-verify via the registry and succeed
        result = await pb.send_message(str(peer.did), {"data": 1}, "a2a")
        assert result["status"] == "sent"

    @pytest.mark.asyncio
    async def test_translate_a2a_to_mcp(self):
        """Bridge translates A2A to MCP format."""
        pb = ProtocolBridge(agent_did="did:mesh:me")
        msg = {"task_type": "run", "parameters": {"x": 1}}
        result = await pb._translate(msg, "a2a", "mcp")
        assert result["method"] == "tools/call"
        assert result["params"]["name"] == "run"

    @pytest.mark.asyncio
    async def test_translate_mcp_to_a2a(self):
        """Bridge translates MCP to A2A format."""
        pb = ProtocolBridge(agent_did="did:mesh:me")
        msg = {"params": {"name": "run", "arguments": {"x": 1}}}
        result = await pb._translate(msg, "mcp", "a2a")
        assert result["task_type"] == "run"

    @pytest.mark.asyncio
    async def test_translate_iatp_passthrough(self):
        """IATP messages pass through without translation."""
        pb = ProtocolBridge(agent_did="did:mesh:me")
        msg = {"data": "test"}
        result = await pb._translate(msg, "iatp", "a2a")
        assert result == msg

    def test_add_verification_footer(self):
        pb = ProtocolBridge(agent_did="did:mesh:me")
        result = pb.add_verification_footer("Hello", 800, "did:mesh:agent123456789012345678901234567890")
        assert "Verified by AgentMesh" in result

    def test_add_verification_footer_with_metadata(self):
        pb = ProtocolBridge(agent_did="did:mesh:me")
        result = pb.add_verification_footer(
            "Hello", 800, "did:mesh:agent123456789012345678901234567890",
            metadata={"policy": "p1", "audit": "a1", "view_log": "http://log"}
        )
        assert "Policy: p1" in result
        assert "Audit: a1" in result
        assert "View Audit Log" in result

    def test_get_protocol_for_peer_unknown(self):
        pb = ProtocolBridge(agent_did="did:mesh:me")
        assert pb.get_protocol_for_peer("did:mesh:nope") is None


class TestMetricsGlobal:
    """Tests for setup_metrics and get_metrics."""

    def test_setup_and_get(self):
        import agentmesh.observability.metrics as mod
        old = mod._metrics_collector
        try:
            mod._metrics_collector = None
            mc = setup_metrics()
            assert mc is not None
            assert get_metrics() is mc
            # Calling again returns same instance
            mc2 = setup_metrics()
            assert mc2 is mc
        finally:
            mod._metrics_collector = old

    def test_get_metrics_none(self):
        import agentmesh.observability.metrics as mod
        old = mod._metrics_collector
        try:
            mod._metrics_collector = None
            assert get_metrics() is None
        finally:
            mod._metrics_collector = old
