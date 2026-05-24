# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for agent_os.credential_vault (issue #2481)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_os.credential_vault import (
    DENY_REASON,
    PLACEHOLDER_RE,
    CredentialDecision,
    CredentialHandle,
    CredentialInjector,
    CredentialProfile,
    CredentialVault,
    DenyReceipt,
    InjectionContext,
    PolicyOutcome,
    audit_digest,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def vault() -> CredentialVault:
    v = CredentialVault()
    v.put("github_pat", "ghp_real_secret_value_xyz", cred_type="bearer_token")
    v.put("db_password", "p@ss-w0rd!", cred_type="password")
    v.register_profile(
        CredentialProfile(
            agent_did="did:web:agent-ci",
            bindings={
                "github:read_issues": "github_pat",
                "github:push_code": "github_pat",
            },
        )
    )
    v.register_profile(
        CredentialProfile(
            agent_did="did:web:agent-analytics",
            bindings={"db:query": "db_password"},
        )
    )
    return v


@pytest.fixture
def injector(vault: CredentialVault) -> CredentialInjector:
    return CredentialInjector(vault)


# ---------------------------------------------------------------------------
# Vault basics
# ---------------------------------------------------------------------------


class TestVaultAdminSurface:
    def test_put_returns_handle(self) -> None:
        v = CredentialVault()
        h = v.put("k1", "v1")
        assert isinstance(h, CredentialHandle)
        assert h.name == "k1"
        assert h.placeholder() == "{{cred:k1}}"

    def test_put_rejects_bad_name(self) -> None:
        v = CredentialVault()
        with pytest.raises(ValueError):
            v.put("", "v")
        with pytest.raises(ValueError):
            v.put("bad name with spaces", "v")
        with pytest.raises(ValueError):
            v.put("a" * 200, "v")

    def test_list_handles_excludes_values(self, vault: CredentialVault) -> None:
        names = vault.list_handles()
        assert names == ["db_password", "github_pat"]
        # Make sure nothing leaks the value
        for n in names:
            meta = vault.get_metadata(n)
            assert meta is not None
            assert "value" not in meta

    def test_rotate_preserves_handle_and_bumps_version(self, vault: CredentialVault) -> None:
        before = vault.get_metadata("github_pat")
        assert before is not None and before["version"] == 1
        h = vault.rotate("github_pat", "ghp_new")
        after = vault.get_metadata("github_pat")
        assert h.name == "github_pat"
        assert after is not None and after["version"] == 2
        assert after["rotated_at"] is not None

    def test_rotate_unknown_raises(self, vault: CredentialVault) -> None:
        with pytest.raises(KeyError):
            vault.rotate("nope", "x")

    def test_delete(self, vault: CredentialVault) -> None:
        first = vault.delete("db_password")
        second = vault.delete("db_password")
        assert first is True
        assert second is False
        assert "db_password" not in vault.list_handles()

    def test_revoke_profile(self, vault: CredentialVault) -> None:
        assert vault.revoke_profile("did:web:agent-ci") is True
        assert vault.revoke_profile("did:web:agent-ci") is False


# ---------------------------------------------------------------------------
# Profiles and scoping
# ---------------------------------------------------------------------------


class TestScoping:
    def test_check_access_allows_bound_action(self, vault: CredentialVault) -> None:
        assert vault.check_access(
            "did:web:agent-ci", "github_pat", "github:read_issues"
        ) is True

    def test_check_access_denies_unknown_agent(self, vault: CredentialVault) -> None:
        assert vault.check_access(
            "did:web:rogue", "github_pat", "github:read_issues"
        ) is False

    def test_check_access_denies_unbound_action(self, vault: CredentialVault) -> None:
        # agent-ci has no db:query binding
        assert vault.check_access(
            "did:web:agent-ci", "db_password", "db:query"
        ) is False

    def test_check_access_denies_cross_action_reuse(self, vault: CredentialVault) -> None:
        # agent-analytics may use db_password for db:query, NOT for db:admin
        assert vault.check_access(
            "did:web:agent-analytics", "db_password", "db:admin"
        ) is False

    def test_profile_bindings_are_immutable(self) -> None:
        bindings = {"a": "h"}
        p = CredentialProfile(agent_did="did:web:x", bindings=bindings)
        # External mutation of the original dict must not change the profile
        bindings["a"] = "other"
        assert p.capability_for("a") == "h"
        # The profile's bindings view is read-only
        with pytest.raises(TypeError):
            p.bindings["a"] = "z"  # type: ignore[index]


# ---------------------------------------------------------------------------
# Injection: HTTP headers, MCP args, env
# ---------------------------------------------------------------------------


class TestInjection:
    def test_inject_headers_happy_path(self, injector: CredentialInjector) -> None:
        result = injector.inject_headers(
            "did:web:agent-ci",
            {"Authorization": "Bearer {{cred:github_pat}}", "Accept": "application/json"},
            action_class="github:read_issues",
            target_service="api.github.com",
            allowed_handles=["github_pat"],
            policy_version="v1",
        )
        assert result.allowed is True
        assert result.payload["Authorization"] == "Bearer ghp_real_secret_value_xyz"
        assert result.payload["Accept"] == "application/json"
        assert result.deny_receipt is None
        assert len(result.audit_events) == 1
        assert result.audit_events[0].decision is CredentialDecision.ALLOW

    def test_inject_tool_args_nested(self, injector: CredentialInjector) -> None:
        args = {
            "repo": "octo/hello",
            "secrets": ["{{cred:github_pat}}", "literal"],
            "nested": {"token": "{{cred:github_pat}}"},
        }
        result = injector.inject_tool_args(
            "did:web:agent-ci",
            args,
            action_class="github:push_code",
            target_service="api.github.com",
            allowed_handles=["github_pat"],
        )
        assert result.allowed is True
        assert result.payload["secrets"][0] == "ghp_real_secret_value_xyz"
        assert result.payload["nested"]["token"] == "ghp_real_secret_value_xyz"
        # Original payload not mutated
        assert args["secrets"][0] == "{{cred:github_pat}}"

    def test_inject_env(self, injector: CredentialInjector) -> None:
        env = {"PATH": "/usr/bin", "GITHUB_TOKEN": "{{cred:github_pat}}"}
        result = injector.inject_env(
            "did:web:agent-ci",
            env,
            action_class="github:read_issues",
            target_service="subprocess",
            allowed_handles=["github_pat"],
        )
        assert result.allowed is True
        assert result.payload["GITHUB_TOKEN"] == "ghp_real_secret_value_xyz"

    def test_unauthorized_handle_in_payload_denies_whole_call(
        self, injector: CredentialInjector
    ) -> None:
        # Workflow only authorized db_password; payload references github_pat
        # via what looks like a smuggled MCP description / tool arg.
        result = injector.inject_tool_args(
            "did:web:agent-analytics",
            {"sql": "SELECT 1", "auth": "{{cred:github_pat}}"},
            action_class="db:query",
            target_service="pg-staging",
            allowed_handles=["db_password"],
        )
        assert result.allowed is False
        assert isinstance(result.payload, DenyReceipt)
        assert result.payload.reason == DENY_REASON

    def test_out_of_scope_handle_returns_same_deny_as_missing(
        self, injector: CredentialInjector
    ) -> None:
        """kayalopez point 6: deny must not reveal whether handle exists."""
        missing = injector.inject_headers(
            "did:web:agent-ci",
            {"X": "{{cred:does_not_exist}}"},
            action_class="github:read_issues",
            target_service="svc",
            allowed_handles=["does_not_exist"],  # authorized by workflow but no record
        )
        out_of_scope = injector.inject_headers(
            "did:web:agent-ci",
            {"X": "{{cred:db_password}}"},
            action_class="github:read_issues",
            target_service="svc",
            allowed_handles=["db_password"],  # exists but not bound to this agent/action
        )
        assert missing.allowed is False
        assert out_of_scope.allowed is False
        assert missing.deny_receipt == out_of_scope.deny_receipt
        # Same payload shape too
        assert missing.payload.to_dict() == out_of_scope.payload.to_dict()

    def test_policy_runs_before_resolution(
        self, injector: CredentialInjector
    ) -> None:
        """kayalopez point 2: substitution happens after policy evaluation."""
        seen: list[InjectionContext] = []

        def policy(ctx: InjectionContext) -> PolicyOutcome:
            seen.append(ctx)
            return PolicyOutcome(allow=False, reason="workflow denied")

        result = injector.inject_headers(
            "did:web:agent-ci",
            {"Authorization": "Bearer {{cred:github_pat}}"},
            action_class="github:push_code",
            target_service="api.github.com",
            allowed_handles=["github_pat"],
            policy_check=policy,
            policy_version="v7",
        )
        assert result.allowed is False
        assert isinstance(result.payload, DenyReceipt)
        # Policy saw the requested handles before any value was read
        assert seen and seen[0].requested_handles == ("github_pat",)
        assert seen[0].policy_version == "v7"

    def test_same_deny_across_injection_surfaces(
        self, injector: CredentialInjector
    ) -> None:
        """kayalopez fixture: same fixture via headers/args/env yields same deny."""
        fixture = "{{cred:github_pat}}"
        h = injector.inject_headers("did:web:agent-analytics",
            {"Authorization": fixture},
            action_class="db:query",
            target_service="svc",
            allowed_handles=["github_pat"],
        )
        a = injector.inject_tool_args(
            "did:web:agent-analytics",
            {"x": fixture},
            action_class="db:query",
            target_service="svc",
            allowed_handles=["github_pat"],
        )
        e = injector.inject_env(
            "did:web:agent-analytics",
            {"TOKEN": fixture},
            action_class="db:query",
            target_service="svc",
            allowed_handles=["github_pat"],
        )
        for r in (h, a, e):
            assert r.allowed is False
            assert r.deny_receipt is not None
            assert r.deny_receipt.reason == DENY_REASON

    def test_placeholder_without_reference_is_passthrough(
        self, injector: CredentialInjector
    ) -> None:
        result = injector.inject_headers(
            "did:web:agent-ci",
            {"Accept": "application/json"},
            action_class="github:read_issues",
            target_service="svc",
            allowed_handles=[],
        )
        assert result.allowed is True
        assert result.payload == {"Accept": "application/json"}


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


class TestAudit:
    def test_audit_records_allow_without_value(
        self, vault: CredentialVault, injector: CredentialInjector
    ) -> None:
        injector.inject_headers(
            "did:web:agent-ci",
            {"Authorization": "Bearer {{cred:github_pat}}"},
            action_class="github:read_issues",
            target_service="api.github.com",
            allowed_handles=["github_pat"],
            policy_version="v1",
        )
        events = vault.audit_log()
        assert len(events) == 1
        ev = events[0]
        assert ev.decision is CredentialDecision.ALLOW
        assert ev.handle_name == "github_pat"
        assert ev.agent_did == "did:web:agent-ci"
        assert ev.policy_version == "v1"
        # Serialization contains no value
        as_dict = ev.to_dict()
        assert "value" not in as_dict
        assert "ghp_real_secret_value_xyz" not in json.dumps(as_dict)

    def test_audit_records_deny(
        self, vault: CredentialVault, injector: CredentialInjector
    ) -> None:
        injector.inject_headers(
            "did:web:rogue",
            {"Authorization": "Bearer {{cred:github_pat}}"},
            action_class="github:read_issues",
            target_service="api.github.com",
            allowed_handles=["github_pat"],
        )
        events = vault.audit_log()
        assert any(e.decision is CredentialDecision.DENY for e in events)

    def test_audit_digest_stable_and_value_free(
        self, vault: CredentialVault, injector: CredentialInjector
    ) -> None:
        injector.inject_headers(
            "did:web:agent-ci",
            {"Authorization": "Bearer {{cred:github_pat}}"},
            action_class="github:read_issues",
            target_service="api.github.com",
            allowed_handles=["github_pat"],
        )
        events = vault.audit_log()
        d1 = audit_digest(events, key=b"k")
        d2 = audit_digest(events, key=b"k")
        assert d1 == d2
        assert d1 != audit_digest(events, key=b"other")


# ---------------------------------------------------------------------------
# Rotation semantics
# ---------------------------------------------------------------------------


class TestRotation:
    def test_rotation_does_not_require_prompt_changes(
        self, vault: CredentialVault, injector: CredentialInjector
    ) -> None:
        # Saved prompt holds the placeholder forever
        saved_prompt_header = {"Authorization": "Bearer {{cred:github_pat}}"}

        before = injector.inject_headers(
            "did:web:agent-ci",
            saved_prompt_header,
            action_class="github:read_issues",
            target_service="svc",
            allowed_handles=["github_pat"],
        )
        assert before.payload["Authorization"] == "Bearer ghp_real_secret_value_xyz"

        vault.rotate("github_pat", "ghp_rotated_value")

        after = injector.inject_headers(
            "did:web:agent-ci",
            saved_prompt_header,
            action_class="github:read_issues",
            target_service="svc",
            allowed_handles=["github_pat"],
        )
        assert after.payload["Authorization"] == "Bearer ghp_rotated_value"
        # Saved prompt was never modified
        assert saved_prompt_header["Authorization"] == "Bearer {{cred:github_pat}}"


# ---------------------------------------------------------------------------
# Encrypted persistence
# ---------------------------------------------------------------------------


cryptography = pytest.importorskip("cryptography")  # type: ignore[assignment]


class TestPersistence:
    def test_round_trip_encrypted(self, tmp_path: Path) -> None:
        key = CredentialVault.generate_key()
        path = tmp_path / "vault.bin"
        secret = "rotated test fixture value not a real secret"  # gitleaks:allow
        v1 = CredentialVault(persist_path=path, encryption_key=key)
        v1.put("k", "original")
        v1.rotate("k", secret)
        # File exists and is not plaintext: distinctive secret must not appear
        blob = path.read_bytes()
        assert secret.encode() not in blob
        assert b'"value"' not in blob

        v2 = CredentialVault(persist_path=path, encryption_key=key)
        assert v2.list_handles() == ["k"]
        meta = v2.get_metadata("k")
        assert meta is not None and meta["version"] == 2

    def test_missing_key_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError):
            CredentialVault(persist_path=tmp_path / "v.bin", encryption_key=None)


# ---------------------------------------------------------------------------
# Placeholder regex
# ---------------------------------------------------------------------------


class TestPlaceholderRegex:
    def test_matches_expected_forms(self) -> None:
        assert PLACEHOLDER_RE.findall("{{cred:abc}}") == ["abc"]
        assert PLACEHOLDER_RE.findall("{{ cred:a.b-c_1 }}") == ["a.b-c_1"]
        assert PLACEHOLDER_RE.findall("Bearer {{cred:x}} and {{cred:y}}") == ["x", "y"]

    def test_rejects_invalid_chars(self) -> None:
        assert PLACEHOLDER_RE.findall("{{cred:has space}}") == []
        assert PLACEHOLDER_RE.findall("{{cred:bad/slash}}") == []
