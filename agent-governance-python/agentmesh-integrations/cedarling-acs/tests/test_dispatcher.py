# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the Cedarling ACS v5 policy dispatcher.

These run against the real ``cedarling-python`` engine, evaluating hand-built
ACS policy inputs against real Cedar policy stores written to a temp directory.
The suite skips when ``cedarling-python`` is not installed.

Each test drives one leg of the contract through an actual authorization: the
verdict mapping, request projection (proved by policies that key on the
projected principal/action/resource/context), multi-issuer tokens, and the
fail-closed paths.
"""
from __future__ import annotations

import base64
import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("cedarling_python")

import cedarling_python

from cedarling_acs import CedarlingConfig, CedarlingPolicyDispatcher

_METADATA = {
    "cedar_version": "4.4.0",
    "policy_store": {
        "id": "a61ced1196e0ed4e8a3601ceda121ec0",
        "name": "DispatcherTestStore",
        "description": "temp policy store for cedarling-acs tests",
        "version": "1.0.0",
        "created_date": "2026-08-26T00:00:00Z",
    },
}


def _write_store(
    root: Path,
    schema: str,
    policies: dict[str, str],
    trusted: dict[str, dict] | None = None,
) -> str:
    (root / "policies").mkdir(parents=True)
    (root / "metadata.json").write_text(json.dumps(_METADATA), encoding="utf-8")
    (root / "schema.cedarschema").write_text(schema, encoding="utf-8")
    for name, text in policies.items():
        (root / "policies" / f"{name}.cedar").write_text(text, encoding="utf-8")
    if trusted:
        (root / "trusted-issuers").mkdir()
        for name, obj in trusted.items():
            (root / "trusted-issuers" / f"{name}.json").write_text(
                json.dumps(obj), encoding="utf-8"
            )
    return str(root)


def _inv(pi: dict) -> dict:
    return {"input": pi}


# =====================================================================
# Unsigned (role-based) store
# =====================================================================

_UNSIGNED_SCHEMA = """namespace AGT {
  entity Agent = { role: String };
  entity Tool = {};
  entity PolicyTarget = {};
  action "pre_tool_call" appliesTo {
    principal: [Agent], resource: [Tool], context: {}
  };
  action "input" appliesTo {
    principal: [Agent], resource: [PolicyTarget], context: { source?: String }
  };
}"""

_UNSIGNED_POLICIES = {
    "allow-admin-tool": (
        '@id("allow-admin-tool")\n'
        "permit(principal is AGT::Agent, action == AGT::Action::\"pre_tool_call\", "
        "resource is AGT::Tool)\n"
        'when { principal.role == "admin" };'
    ),
    "forbid-auditor-delete": (
        '@id("forbid-auditor-delete")\n'
        "forbid(principal is AGT::Agent, action == AGT::Action::\"pre_tool_call\", "
        'resource == AGT::Tool::"delete_file")\n'
        'when { principal.role == "auditor" };'
    ),
    # Permits an `input` point only when a non-envelope snapshot key
    # (context.source) is present, proving the context projection.
    "allow-trusted-input": (
        '@id("allow-trusted-input")\n'
        "permit(principal is AGT::Agent, action == AGT::Action::\"input\", "
        "resource is AGT::PolicyTarget)\n"
        'when { principal.role == "admin" && context has source && '
        'context.source == "trusted" };'
    ),
}


@pytest.fixture(scope="module")
def unsigned_store(tmp_path_factory) -> str:
    return _write_store(
        tmp_path_factory.mktemp("unsigned"), _UNSIGNED_SCHEMA, _UNSIGNED_POLICIES
    )


@pytest.fixture(scope="module")
def unsigned(unsigned_store: str) -> CedarlingPolicyDispatcher:
    return CedarlingPolicyDispatcher.from_bootstrap(
        {"CEDARLING_POLICY_STORE_LOCAL_FN": unsigned_store, "CEDARLING_LOG_TYPE": "off"},
        config=CedarlingConfig(namespace="AGT", auth_type="unsigned"),
    )


_FORGERY_SCHEMA = """namespace AGT {
  entity Agent = { role: String };
  entity Admin = { role: String };
  entity Tool = {};
  entity PolicyTarget = {};
  action "pre_tool_call" appliesTo {
    principal: [Agent, Admin], resource: [Tool], context: {}
  };
}"""

_FORGERY_POLICIES = {
    "allow-admin-entity": (
        '@id("allow-admin-entity")\n'
        "permit(principal is AGT::Admin, action == AGT::Action::\"pre_tool_call\", "
        "resource is AGT::Tool);"
    ),
    "allow-root-id": (
        '@id("allow-root-id")\n'
        'permit(principal == AGT::Agent::"root", action == AGT::Action::"pre_tool_call", '
        "resource is AGT::Tool);"
    ),
}


@pytest.fixture(scope="module")
def forgery(tmp_path_factory) -> CedarlingPolicyDispatcher:
    store = _write_store(
        tmp_path_factory.mktemp("forgery"), _FORGERY_SCHEMA, _FORGERY_POLICIES
    )
    return CedarlingPolicyDispatcher.from_bootstrap(
        {"CEDARLING_POLICY_STORE_LOCAL_FN": store, "CEDARLING_LOG_TYPE": "off"},
        config=CedarlingConfig(namespace="AGT", auth_type="unsigned"),
    )


def _tool_pi(*, role: str, tool: str, agent_id: str = "agent-1") -> dict:
    return {
        "intervention_point": "pre_tool_call",
        "policy_target": {"kind": "tool_args", "path": "$.tool_call.args", "value": {}},
        "snapshot": {"envelope": {"agent": {"id": agent_id, "attributes": {"role": role}}}},
        "annotations": {},
        "tool": {"name": tool, "clearance": "public"},
    }


def _input_pi(*, role: str, source: str | None) -> dict:
    snapshot: dict[str, Any] = {"envelope": {"agent": {"id": "a1", "attributes": {"role": role}}}}
    if source is not None:
        snapshot["source"] = source
    return {
        "intervention_point": "input",
        "policy_target": {"kind": "user_input", "path": "$.input.body", "value": "hi"},
        "snapshot": snapshot,
        "annotations": {},
        "tool": None,
    }


def test_admin_tool_call_allowed(unsigned):
    verdict = unsigned.evaluate(_inv(_tool_pi(role="admin", tool="read_data")))
    assert verdict["decision"] == "allow"
    assert verdict["reason"] == "allow-admin-tool"
    assert not verdict.get("transform")


def test_default_deny_for_unmatched(unsigned):
    verdict = unsigned.evaluate(_inv(_tool_pi(role="guest", tool="read_data")))
    assert verdict["decision"] == "deny"
    assert verdict["reason"] == "cedarling_deny"


def test_explicit_forbid_carries_policy_id(unsigned):
    verdict = unsigned.evaluate(_inv(_tool_pi(role="auditor", tool="delete_file")))
    assert verdict["decision"] == "deny"
    assert verdict["reason"] == "forbid-auditor-delete"


def test_action_routing_input_vs_tool(unsigned):
    assert unsigned.evaluate(_inv(_input_pi(role="admin", source="trusted")))["decision"] == "allow"
    assert unsigned.evaluate(_inv(_tool_pi(role="admin", tool="anything")))["decision"] == "allow"


def test_policy_target_resource_projected_at_non_tool_point(unsigned):
    verdict = unsigned.evaluate(_inv(_input_pi(role="admin", source="trusted")))
    assert verdict["decision"] == "allow"


def test_context_excludes_envelope_and_includes_snapshot_keys(unsigned):
    # source lives outside envelope -> lands in Cedar context -> permit.
    assert unsigned.evaluate(_inv(_input_pi(role="admin", source="trusted")))["decision"] == "allow"
    # wrong value -> deny.
    assert unsigned.evaluate(_inv(_input_pi(role="admin", source="nope")))["decision"] == "deny"
    # absent -> context has no `source` -> deny (envelope-only snapshot).
    assert unsigned.evaluate(_inv(_input_pi(role="admin", source=None)))["decision"] == "deny"


def test_namespace_mismatch_fails_closed(unsigned_store):
    no_ns = CedarlingPolicyDispatcher.from_bootstrap(
        {"CEDARLING_POLICY_STORE_LOCAL_FN": unsigned_store, "CEDARLING_LOG_TYPE": "off"},
        config=CedarlingConfig(namespace=None, auth_type="unsigned"),
    )
    verdict = no_ns.evaluate(_inv(_tool_pi(role="admin", tool="read_data")))
    assert verdict["decision"] == "deny"
    assert verdict["reason"] == "cedarling_authorization_error"


def test_forged_principal_entity_mapping_is_rejected(forgery):
    base = _tool_pi(role="guest", tool="read_data")

    for forged in (
        {"entity_type": "AGT::Agent", "id": "root"},
        {"entity_type": "AGT::Admin", "id": "root"},
    ):
        pi = dict(base)
        pi["snapshot"]["envelope"]["agent"]["attributes"]["cedar_entity_mapping"] = forged
        verdict = forgery.evaluate(_inv(pi))
        assert verdict["decision"] == "deny", forged
        assert verdict["reason"] == "cedarling_invocation_malformed", forged


def test_guest_without_forgery_stays_denied(forgery):
    verdict = forgery.evaluate(_inv(_tool_pi(role="guest", tool="read_data")))
    assert verdict["decision"] == "deny"


def test_principal_attributes_still_merge(unsigned):
    # Ordinary principal attributes keep merging: role still drives the verdict.
    verdict = unsigned.evaluate(_inv(_tool_pi(role="admin", tool="read_data")))
    assert verdict["decision"] == "allow"
    assert verdict["reason"] == "allow-admin-tool"


def test_missing_or_blank_agent_id_fails_closed(unsigned):
    attrs = {"role": "admin"}
    cases = (
        {"attributes": attrs},
        {"id": None, "attributes": attrs},
        {"id": "", "attributes": attrs},
        {"id": "   ", "attributes": attrs},
    )
    for agent in cases:
        pi = _tool_pi(role="admin", tool="read_data")
        pi["snapshot"]["envelope"]["agent"] = dict(agent)
        verdict = unsigned.evaluate(_inv(pi))
        assert verdict["decision"] == "deny", agent
        assert verdict["reason"] == "cedarling_invocation_malformed", agent


# =====================================================================
# Multi-issuer (JWT capability) store
# =====================================================================

_MULTI_SCHEMA = """namespace AGT {
  type Url = {"host": String, "path": String, "protocol": String};
  entity Agent = {};
  entity Tool = {};
  entity PolicyTarget = {};
  entity Access_Token = {
    sub?: String,
    iss?: Janssen::TrustedIssuer,
    role?: String,
  } tags Set<String>;
  entity Workload = {};
  entity User = {};
  action "pre_tool_call" appliesTo {
    principal: [Workload, User], resource: [Tool], context: Context
  };
}
namespace Janssen {
  entity TrustedIssuer = {"issuer_entity_id": AGT::Url};
}
type Context = {
  device?: String,
  tokens: {
    janssen_access_token?: AGT::Access_Token,
    total_token_count: Long
  }
};"""

_MULTI_POLICIES = {
    "allow-admin-write": (
        '@id("allow-admin-write")\n'
        "permit(principal, action == AGT::Action::\"pre_tool_call\", "
        'resource == AGT::Tool::"write_config") when {\n'
        "  context has tokens.janssen_access_token &&\n"
        '  context.tokens.janssen_access_token.hasTag("role") &&\n'
        '  context.tokens.janssen_access_token.getTag("role").contains("admin") &&\n'
        '  context has device && context.device != "mobile"\n'
        "};"
    ),
    "forbid-prod-delete": (
        '@id("forbid-prod-delete")\n'
        "forbid(principal, action == AGT::Action::\"pre_tool_call\", "
        'resource == AGT::Tool::"delete_prod");'
    ),
}

_TRUSTED = {
    "janssen": {
        "name": "Janssen",
        "description": "IdP for operations agents",
        "configuration_endpoint": "https://test.jans.org/.well-known/openid-configuration",
        "token_metadata": {
            "access_token": {
                "trusted": True,
                "entity_type_name": "AGT::Access_Token",
                "token_id": "jti",
            }
        },
    }
}

_ACCESS_TOKEN_TYPE = "AGT::Access_Token"


def _mint(subject: str, role: str) -> str:
    def b64(obj: dict) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": subject,
        "iss": "https://test.jans.org",
        "aud": "operations-console",
        "client_id": "operations-console",
        "token_type": "Bearer",
        "scope": ["openid"],
        "role": role,
        "iat": now,
        "exp": now + 3600,
        "jti": f"jti-{subject}",
    }
    return f"{b64(header)}.{b64(payload)}.demo-signature"


@pytest.fixture(scope="module")
def multi(tmp_path_factory) -> CedarlingPolicyDispatcher:
    store = _write_store(
        tmp_path_factory.mktemp("multi"), _MULTI_SCHEMA, _MULTI_POLICIES, trusted=_TRUSTED
    )
    return CedarlingPolicyDispatcher.from_bootstrap(
        {
            "CEDARLING_POLICY_STORE_LOCAL_FN": store,
            "CEDARLING_JWT_SIG_VALIDATION": "disabled",
            "CEDARLING_JWT_STATUS_VALIDATION": "disabled",
            "CEDARLING_JWT_SIGNATURE_ALGORITHMS_SUPPORTED": ["HS256"],
            "CEDARLING_LOG_TYPE": "off",
        },
        config=CedarlingConfig(namespace="AGT", auth_type="multi-issuer"),
    )


def _multi_pi(*, tool: str, device: str, token: str | None, token_key: str = _ACCESS_TOKEN_TYPE) -> dict:
    agent: dict[str, Any] = {"id": "agent-ops"}
    if token is not None:
        agent["tokens"] = {token_key: token}
    return {
        "intervention_point": "pre_tool_call",
        "policy_target": {"kind": "tool_args", "path": "$.tool_call.args", "value": {}},
        "snapshot": {"envelope": {"agent": agent}, "device": device},
        "annotations": {},
        "tool": {"name": tool},
    }


def test_multi_issuer_admin_on_laptop_allowed(multi):
    verdict = multi.evaluate(
        _inv(_multi_pi(tool="write_config", device="laptop", token=_mint("ops", "admin")))
    )
    assert verdict["decision"] == "allow"
    assert verdict["reason"] == "allow-admin-write"


def test_multi_issuer_forbid_surfaces_policy_id(multi):
    verdict = multi.evaluate(
        _inv(_multi_pi(tool="delete_prod", device="laptop", token=_mint("ops", "admin")))
    )
    assert verdict["decision"] == "deny"
    assert verdict["reason"] == "forbid-prod-delete"


def test_multi_issuer_admin_on_mobile_denied(multi):
    verdict = multi.evaluate(
        _inv(_multi_pi(tool="write_config", device="mobile", token=_mint("ops", "admin")))
    )
    assert verdict["decision"] == "deny"


def test_multi_issuer_operator_denied(multi):
    verdict = multi.evaluate(
        _inv(_multi_pi(tool="write_config", device="laptop", token=_mint("help", "operator")))
    )
    assert verdict["decision"] == "deny"


def test_multi_issuer_missing_tokens_fails_closed(multi):
    verdict = multi.evaluate(_inv(_multi_pi(tool="write_config", device="laptop", token=None)))
    assert verdict["decision"] == "deny"
    assert verdict["reason"] == "cedarling_engine_error"


def test_multi_issuer_non_string_token_fails_closed(multi):
    pi = _multi_pi(tool="write_config", device="laptop", token=_mint("ops", "admin"))
    pi["snapshot"]["envelope"]["agent"]["tokens"] = {_ACCESS_TOKEN_TYPE: 123}
    verdict = multi.evaluate(_inv(pi))
    assert verdict["decision"] == "deny"
    assert verdict["reason"] == "cedarling_engine_error"


def test_multi_issuer_top_level_token_path_allows(tmp_path_factory):
    store = _write_store(
        tmp_path_factory.mktemp("top-tokens"), _MULTI_SCHEMA, _MULTI_POLICIES, trusted=_TRUSTED
    )
    dispatcher = CedarlingPolicyDispatcher.from_bootstrap(
        {
            "CEDARLING_POLICY_STORE_LOCAL_FN": store,
            "CEDARLING_JWT_SIG_VALIDATION": "disabled",
            "CEDARLING_JWT_STATUS_VALIDATION": "disabled",
            "CEDARLING_JWT_SIGNATURE_ALGORITHMS_SUPPORTED": ["HS256"],
            "CEDARLING_LOG_TYPE": "off",
        },
        config=CedarlingConfig(
            namespace="AGT", auth_type="multi-issuer", token_paths=(("tokens",),)
        ),
    )
    pi = _multi_pi(tool="write_config", device="laptop", token=None)
    pi["snapshot"]["tokens"] = {_ACCESS_TOKEN_TYPE: _mint("ops", "admin")}
    verdict = dispatcher.evaluate(_inv(pi))
    assert verdict["decision"] == "allow"
    assert verdict["reason"] == "allow-admin-write"


# =====================================================================
# Engine-independent behavior
# =====================================================================


def test_malformed_invocation_denies(unsigned):
    verdict = unsigned.evaluate({"not_input": {}})
    assert verdict["decision"] == "deny"
    assert verdict["reason"] == "cedarling_invocation_malformed"


def test_policy_input_passed_directly_is_tolerated(unsigned):
    verdict = unsigned.evaluate(_tool_pi(role="admin", tool="read_data"))
    assert verdict["decision"] == "allow"


def test_policy_store_pointer_emitted_as_evidence(unsigned_store):
    d = CedarlingPolicyDispatcher.from_bootstrap(
        {"CEDARLING_POLICY_STORE_LOCAL_FN": unsigned_store, "CEDARLING_LOG_TYPE": "off"},
        config=CedarlingConfig(
            namespace="AGT", policy_store_pointer="https://ex/store/v1"
        ),
    )
    verdict = d.evaluate(_inv(_tool_pi(role="admin", tool="read_data")))
    assert verdict["evidence"]["verification_pointers"]["policy_store"] == "https://ex/store/v1"


def test_no_evidence_by_default(unsigned):
    verdict = unsigned.evaluate(_inv(_tool_pi(role="admin", tool="read_data")))
    assert "evidence" not in verdict


def test_engine_required():
    with pytest.raises(ValueError):
        CedarlingPolicyDispatcher(None)


def test_from_bootstrap_reports_missing_cedarling(monkeypatch):
    monkeypatch.setitem(sys.modules, "cedarling_python", None)
    with pytest.raises(ImportError) as exc:
        CedarlingPolicyDispatcher.from_bootstrap({})
    assert "cedarling" in str(exc.value).lower()

def test_auth_type_rejects_invalid():
    with pytest.raises(ValueError, match="auth_type must be one"):
        CedarlingConfig(auth_type="singed")


def test_auth_type_rejects_unsigned_typo():
    with pytest.raises(ValueError, match="auth_type must be one"):
        CedarlingConfig(auth_type="unsigend")


def test_auth_type_accepts_valid():
    assert CedarlingConfig(auth_type="unsigned").auth_type == "unsigned"
    assert CedarlingConfig(auth_type="multi-issuer").auth_type == "multi-issuer"


def _stub_result(allowed: Any) -> SimpleNamespace:
    return SimpleNamespace(
        is_allowed=lambda: allowed,
        response=SimpleNamespace(diagnostics=SimpleNamespace(reason=set())),
    )


def test_is_allowed_must_return_real_bool():
    for truthy in ("true", 1):
        engine = SimpleNamespace(authorize_unsigned=lambda _request: _stub_result(truthy))
        dispatcher = CedarlingPolicyDispatcher(
            engine, config=CedarlingConfig(namespace="AGT", auth_type="unsigned")
        )
        verdict = dispatcher.evaluate(_inv(_tool_pi(role="admin", tool="read_data")))
        assert verdict["decision"] == "deny", truthy
        assert verdict["reason"] == "cedarling_deny", truthy

    engine = SimpleNamespace(authorize_unsigned=lambda _request: _stub_result(True))
    dispatcher = CedarlingPolicyDispatcher(
        engine, config=CedarlingConfig(namespace="AGT", auth_type="unsigned")
    )
    verdict = dispatcher.evaluate(_inv(_tool_pi(role="admin", tool="read_data")))
    assert verdict["decision"] == "allow"


def test_token_paths_default_is_envelope_only():
    cfg = CedarlingConfig()
    assert cfg.token_paths == (("envelope", "agent", "tokens"),)
