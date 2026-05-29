# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Unit tests for ``ACASandboxProvider``.

All ``azure-containerapps-sandbox`` calls are mocked, so this file runs
without Azure credentials or network access. Integration tests that hit
real Azure live in ``test_azure_sandbox_integration.py``.

Covers:
* Module-level helpers (``_validate_resource_name``,
  ``_network_allowlist``, ``_network_default``,
  ``_unpack_exec_result``, ``aca_config_from_policy``).
* Construction: missing SDK, name validation, missing region,
  ``ensure_group_location`` wiring, mgmt-client failure tolerance.
* ``create_session``: with/without policy, fail-closed egress,
  ``network_default=allow`` opt-out, empty allowlist, invalid IDs,
  data-plane failures, missing sandbox id, kwargs forwarding,
  resource-cap projection.
* ``execute_code``: policy gate fires before any Azure call,
  base64 transport, context merging, timeout kill, no-session error,
  data-plane failure surfacing, dict-vs-typed-result handling.
* ``destroy_session``: idempotent, error swallowing.
* ``get_session_status``, ``close``, ``__exit__``, ``is_available``.
* ``*_async`` wrappers delegate to sync counterparts.
* Multi-session isolation: per-session evaluator + config + sandbox
  client do not bleed between agents.
"""

from __future__ import annotations

import asyncio
import base64
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from agent_sandbox.aca_sandbox_provider import (
    ACASandboxProvider,
    aca_config_from_policy,
)
# Underscore-prefixed helpers are internal: import them directly from the
# implementation module rather than the package's public ``__all__``.
from agent_sandbox.aca_sandbox_provider.aca_sandbox_provider import (
    _network_allowlist,
    _network_default,
    _unpack_exec_result,
    _validate_resource_name,
)
from agent_sandbox.sandbox_provider import (
    ExecutionStatus,
    SandboxConfig,
    SessionStatus,
)


# =========================================================================
# Helpers / fixtures
# =========================================================================


def _make_policy(
    *,
    network_allowlist=None,
    tool_allowlist=None,
    max_cpu=None,
    max_memory_mb=None,
    timeout_seconds=None,
    network_default=None,
    rules=None,
    name="test-policy",
    version="1",
):
    """Build a duck-typed policy object matching what the provider reads."""
    defaults = SimpleNamespace()
    if max_cpu is not None:
        defaults.max_cpu = max_cpu
    if max_memory_mb is not None:
        defaults.max_memory_mb = max_memory_mb
    if timeout_seconds is not None:
        defaults.timeout_seconds = timeout_seconds
    if network_default is not None:
        defaults.network_default = network_default

    return SimpleNamespace(
        name=name,
        version=version,
        rules=rules or [],
        defaults=defaults,
        network_allowlist=list(network_allowlist) if network_allowlist else [],
        tool_allowlist=list(tool_allowlist) if tool_allowlist else [],
    )


def _make_sandbox_client(sandbox_id="sb-abc123", exec_response=None):
    """Build a per-sandbox SandboxClient mock that mirrors the SDK surface."""
    sb = MagicMock(name=f"SandboxClient({sandbox_id})")
    sb.sandbox_id = sandbox_id
    sb.exec.return_value = (
        exec_response
        if exec_response is not None
        else SimpleNamespace(exit_code=0, stdout="ok", stderr="")
    )
    return sb


def _make_poller(sandbox_client):
    """Wrap a sandbox client in a poller mock matching ``LROPoller``."""
    poller = MagicMock(name="LROPoller")
    poller.result.return_value = sandbox_client
    return poller


@pytest.fixture()
def fake_sdk():
    """Patch ``azure.containerapps.sandbox`` + ``azure.identity``.

    Yields ``(group_client, mgmt_client, sandbox_factory)`` where
    ``sandbox_factory`` is a callable that creates the next sandbox
    client to be returned from ``begin_create_sandbox().result()``.
    """
    group_client = MagicMock(name="SandboxGroupClient")
    mgmt_client = MagicMock(name="SandboxGroupManagementClient")

    # Default: one sandbox per create call.
    default_sb = _make_sandbox_client()
    group_client.begin_create_sandbox.return_value = _make_poller(default_sb)

    sdk_module = MagicMock(name="azure.containerapps.sandbox")
    sdk_module.SandboxGroupClient = MagicMock(return_value=group_client)
    sdk_module.SandboxGroupManagementClient = MagicMock(
        return_value=mgmt_client
    )
    sdk_module.endpoint_for_region = MagicMock(
        side_effect=lambda r: f"https://management.{r}.azuredevcompute.io"
    )

    # Typed egress models — use SimpleNamespace-style stand-ins so test
    # assertions can read the attributes the SDK exposes (default_action,
    # host_rules, pattern, action) instead of MagicMock junk.
    def _make_host_rule(pattern="", action="Allow"):
        return SimpleNamespace(pattern=pattern, action=action)

    def _make_egress_policy(
        default_action="Allow", host_rules=None, rules=None,
        traffic_inspection=None,
    ):
        return SimpleNamespace(
            default_action=default_action,
            host_rules=list(host_rules or []),
            rules=list(rules or []),
            traffic_inspection=traffic_inspection,
        )

    sdk_module.EgressHostRule = MagicMock(side_effect=_make_host_rule)
    sdk_module.EgressPolicy = MagicMock(side_effect=_make_egress_policy)

    containerapps_pkg = MagicMock(name="azure.containerapps")
    containerapps_pkg.sandbox = sdk_module

    identity_module = MagicMock(name="azure.identity")
    identity_module.DefaultAzureCredential = MagicMock(return_value="cred-X")

    with patch.dict(
        "sys.modules",
        {
            "azure.containerapps": containerapps_pkg,
            "azure.containerapps.sandbox": sdk_module,
            "azure.identity": identity_module,
        },
    ):
        # Expose a tiny helper so individual tests can queue follow-up
        # sandbox clients without rewriting the poller plumbing.
        def queue(*sandbox_clients):
            pollers = [_make_poller(sb) for sb in sandbox_clients]
            group_client.begin_create_sandbox.side_effect = pollers

        yield SimpleNamespace(
            group=group_client,
            mgmt=mgmt_client,
            sdk=sdk_module,
            identity=identity_module,
            default_sandbox=default_sb,
            queue=queue,
        )


@pytest.fixture()
def provider(fake_sdk):
    """A ready-to-use provider with the default sandbox queued."""
    return ACASandboxProvider(
        resource_group="rg",
        sandbox_group="grp",
        region="eastus2",
    )


# =========================================================================
# Section 1: Module-level helpers
# =========================================================================


class TestValidateResourceName:
    @pytest.mark.parametrize(
        "value",
        ["a", "A", "0", "abc", "Agent-1", "name_with_underscores", "a" * 63],
    )
    def test_accepts_valid_names(self, value):
        _validate_resource_name(value, "label")  # no exception

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "-leading-dash",
            "_leading_us",
            "has space",
            "has/slash",
            "has.dot",
            "a" * 64,
            123,
            None,
        ],
    )
    def test_rejects_invalid_names(self, value):
        with pytest.raises(ValueError, match="Invalid label"):
            _validate_resource_name(value, "label")


class TestNetworkAllowlist:
    def test_empty_when_missing(self):
        assert _network_allowlist(SimpleNamespace()) == []

    def test_returns_str_list_verbatim(self):
        policy = SimpleNamespace(network_allowlist=["a.com", "*.b.com"])
        assert _network_allowlist(policy) == ["a.com", "*.b.com"]

    def test_accepts_host_object_form(self):
        entries = [
            SimpleNamespace(host="x.com"),
            SimpleNamespace(pattern="*.y.com"),
        ]
        assert _network_allowlist(
            SimpleNamespace(network_allowlist=entries)
        ) == ["x.com", "*.y.com"]

    def test_skips_entries_with_no_host_or_pattern(self):
        entries = [
            "a.com",
            SimpleNamespace(),
            SimpleNamespace(host="b.com"),
        ]
        assert _network_allowlist(
            SimpleNamespace(network_allowlist=entries)
        ) == ["a.com", "b.com"]

    def test_none_allowlist(self):
        assert _network_allowlist(
            SimpleNamespace(network_allowlist=None)
        ) == []


class TestNetworkDefault:
    @pytest.mark.parametrize("value", ["deny", "DENY", "Deny"])
    def test_explicit_deny(self, value):
        policy = SimpleNamespace(defaults=SimpleNamespace(network_default=value))
        assert _network_default(policy) == "deny"

    @pytest.mark.parametrize("value", ["allow", "ALLOW", "Allow"])
    def test_explicit_allow(self, value):
        policy = SimpleNamespace(defaults=SimpleNamespace(network_default=value))
        assert _network_default(policy) == "allow"

    def test_fail_closed_when_field_missing(self):
        assert _network_default(SimpleNamespace(defaults=SimpleNamespace())) == "deny"

    def test_fail_closed_when_defaults_missing(self):
        assert _network_default(SimpleNamespace()) == "deny"

    @pytest.mark.parametrize("value", ["", "permit", "block", 1, None, [], {}])
    def test_fail_closed_on_invalid_value(self, value):
        policy = SimpleNamespace(defaults=SimpleNamespace(network_default=value))
        assert _network_default(policy) == "deny"


class TestUnpackExecResult:
    def test_typed_result_object(self):
        resp = SimpleNamespace(exit_code=0, stdout="hi", stderr="")
        assert _unpack_exec_result(resp) == (0, "hi", "")

    def test_typed_result_with_camelcase_exit_code(self):
        # Some preview builds expose ``exitCode`` on a typed object.
        resp = SimpleNamespace(stdout="x", stderr="", exitCode=2)
        assert _unpack_exec_result(resp) == (2, "x", "")

    def test_dict_snake_case(self):
        assert _unpack_exec_result(
            {"exit_code": 7, "stdout": "a", "stderr": "b"}
        ) == (7, "a", "b")

    def test_dict_camel_case(self):
        assert _unpack_exec_result(
            {"exitCode": 1, "stdout": "", "stderr": "boom"}
        ) == (1, "", "boom")

    def test_none(self):
        assert _unpack_exec_result(None) == (-1, "", "")

    def test_unknown_shape_falls_back(self):
        assert _unpack_exec_result("opaque") == (-1, "", "opaque")


class TestAzureConfigFromPolicy:
    def test_preserves_base_when_policy_empty(self):
        base = SandboxConfig(memory_mb=999, cpu_limit=3.0, timeout_seconds=42)
        cfg = aca_config_from_policy(
            SimpleNamespace(defaults=SimpleNamespace()), base
        )
        assert cfg.memory_mb == 999
        assert cfg.cpu_limit == 3.0
        assert cfg.timeout_seconds == 42
        assert cfg.network_enabled is False

    def test_applies_resource_caps(self):
        policy = _make_policy(max_cpu=0.25, max_memory_mb=256, timeout_seconds=15)
        cfg = aca_config_from_policy(policy, SandboxConfig())
        assert cfg.cpu_limit == 0.25
        assert cfg.memory_mb == 256
        assert cfg.timeout_seconds == 15

    def test_zero_or_falsy_caps_do_not_override(self):
        policy = _make_policy(max_cpu=0, max_memory_mb=0, timeout_seconds=0)
        base = SandboxConfig(memory_mb=777, cpu_limit=4.0, timeout_seconds=30)
        cfg = aca_config_from_policy(policy, base)
        assert cfg.memory_mb == 777
        assert cfg.cpu_limit == 4.0
        assert cfg.timeout_seconds == 30

    def test_network_allowlist_enables_network(self):
        policy = _make_policy(network_allowlist=["a.com"])
        cfg = aca_config_from_policy(policy, SandboxConfig())
        assert cfg.network_enabled is True

    def test_env_vars_are_copied_not_aliased(self):
        base = SandboxConfig(env_vars={"K": "V"})
        cfg = aca_config_from_policy(
            SimpleNamespace(defaults=SimpleNamespace()), base
        )
        cfg.env_vars["NEW"] = "X"
        assert "NEW" not in base.env_vars


# =========================================================================
# Section 2: Construction
# =========================================================================


class TestConstruction:
    def test_unavailable_when_sdk_missing(self, monkeypatch):
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "azure.containerapps" or name.startswith(
                "azure.containerapps"
            ):
                raise ImportError("simulated")
            return real_import(name, *a, **kw)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        p = ACASandboxProvider(
            resource_group="rg", sandbox_group="grp", region="eastus2"
        )
        assert p.is_available() is False
        # The unavailable reason names the missing package.
        reason = p.unavailable_reason
        assert reason is not None
        assert "azure-containerapps-sandbox is not installed" in reason
        # And the RuntimeError from create_session must carry that reason
        # too — callers should not have to dig through logs.
        with pytest.raises(RuntimeError) as exc_info:
            p.create_session("agent")
        msg = str(exc_info.value)
        assert "not available" in msg
        assert "azure-containerapps-sandbox is not installed" in msg

    def test_unavailable_when_sdk_import_raises_nonimport_error(
        self, monkeypatch, caplog
    ):
        # Anything other than ImportError must also leave the provider
        # unavailable but log a different message.
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "azure.containerapps":
                raise RuntimeError("module loader exploded")
            return real_import(name, *a, **kw)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        with caplog.at_level("WARNING"):
            p = ACASandboxProvider(
                resource_group="rg", sandbox_group="grp", region="eastus2"
            )
        assert p.is_available() is False
        assert "Failed to import azure-containerapps-sandbox" in caplog.text

    def test_endpoint_for_region_failure_marks_unavailable(
        self, fake_sdk, caplog
    ):
        fake_sdk.sdk.endpoint_for_region.side_effect = ValueError(
            "unknown region 'mars'"
        )
        with caplog.at_level("WARNING"):
            p = ACASandboxProvider(
                resource_group="rg", sandbox_group="grp", region="mars"
            )
        assert p.is_available() is False
        assert "endpoint_for_region" in caplog.text

    def test_default_credential_import_failure_marks_unavailable(
        self, fake_sdk, monkeypatch, caplog
    ):
        # azure-identity is part of the SDK's transitive deps, but make
        # sure missing-azure-identity gets a clean diagnostic instead of
        # a crash.
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "azure.identity":
                raise ImportError("simulated")
            return real_import(name, *a, **kw)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        with caplog.at_level("WARNING"):
            p = ACASandboxProvider(
                resource_group="rg", sandbox_group="grp", region="eastus2"
            )
        assert p.is_available() is False
        # Diagnostic includes both the missing-module statement and the
        # install hint pointing at the `azure` extra.
        assert "azure-identity is not installed" in p.unavailable_reason
        assert "agt-sandbox[azure]" in p.unavailable_reason
        assert "azure-identity is not installed" in caplog.text

    def test_unavailable_reason_is_none_when_healthy(self, fake_sdk):
        p = ACASandboxProvider(
            resource_group="rg", sandbox_group="grp", region="eastus2"
        )
        assert p.is_available() is True
        assert p.unavailable_reason is None

    def test_default_credential_construction_failure_marks_unavailable(
        self, fake_sdk, caplog
    ):
        fake_sdk.identity.DefaultAzureCredential.side_effect = RuntimeError(
            "no token source"
        )
        with caplog.at_level("WARNING"):
            p = ACASandboxProvider(
                resource_group="rg", sandbox_group="grp", region="eastus2"
            )
        assert p.is_available() is False
        assert "DefaultAzureCredential" in caplog.text

    def test_validates_sandbox_group_name(self, fake_sdk):
        with pytest.raises(ValueError, match="sandbox_group"):
            ACASandboxProvider(
                resource_group="rg", sandbox_group="bad name", region="eastus2"
            )

    def test_missing_region_marks_unavailable(self, fake_sdk, monkeypatch):
        # No region kwarg, no AZURE_SANDBOX_REGION → endpoint cannot be
        # built, provider stays unavailable.
        monkeypatch.delenv("AZURE_SANDBOX_REGION", raising=False)
        p = ACASandboxProvider(resource_group="rg", sandbox_group="grp")
        assert p.is_available() is False

    def test_region_from_env(self, fake_sdk, monkeypatch):
        monkeypatch.setenv("AZURE_SANDBOX_REGION", "westus2")
        p = ACASandboxProvider(resource_group="rg", sandbox_group="grp")
        assert p.is_available() is True
        fake_sdk.sdk.endpoint_for_region.assert_called_with("westus2")

    def test_explicit_endpoint_bypasses_region(self, fake_sdk):
        p = ACASandboxProvider(
            resource_group="rg",
            sandbox_group="grp",
            endpoint="https://custom.example.com",
        )
        assert p.is_available() is True
        fake_sdk.sdk.endpoint_for_region.assert_not_called()
        # SandboxGroupClient was constructed with the custom endpoint.
        args, _ = fake_sdk.sdk.SandboxGroupClient.call_args
        assert args[0] == "https://custom.example.com"

    def test_group_client_construction_failure_marks_unavailable(self, fake_sdk):
        fake_sdk.sdk.SandboxGroupClient.side_effect = RuntimeError("boom")
        p = ACASandboxProvider(
            resource_group="rg", sandbox_group="grp", region="eastus2"
        )
        assert p.is_available() is False

    def test_ensure_group_location_constructs_mgmt_client(self, fake_sdk):
        p = ACASandboxProvider(
            resource_group="rg",
            sandbox_group="grp",
            ensure_group_location="westus2",
        )
        assert p.is_available() is True
        assert p._mgmt_client is fake_sdk.mgmt

    def test_ensure_group_location_defaults_region(self, fake_sdk):
        # When `region` is omitted, `ensure_group_location` doubles as the
        # data-plane region.
        ACASandboxProvider(
            resource_group="rg",
            sandbox_group="grp",
            ensure_group_location="westus2",
        )
        fake_sdk.sdk.endpoint_for_region.assert_called_with("westus2")

    def test_no_mgmt_client_when_ensure_location_unset(self, fake_sdk):
        p = ACASandboxProvider(
            resource_group="rg", sandbox_group="grp", region="eastus2"
        )
        assert p._mgmt_client is None

    def test_mgmt_client_failure_does_not_kill_provider(self, fake_sdk):
        fake_sdk.sdk.SandboxGroupManagementClient.side_effect = RuntimeError(
            "mgmt-down"
        )
        p = ACASandboxProvider(
            resource_group="rg",
            sandbox_group="grp",
            ensure_group_location="westus2",
        )
        assert p.is_available() is True
        assert p._mgmt_client is None

    def test_mgmt_client_attributeerror_is_tolerated(self, fake_sdk, caplog):
        # If a future SDK drops SandboxGroupManagementClient the provider
        # must still come up — just without group bootstrap.
        fake_sdk.sdk.SandboxGroupManagementClient.side_effect = AttributeError(
            "no such attr"
        )
        with caplog.at_level("WARNING"):
            p = ACASandboxProvider(
                resource_group="rg",
                sandbox_group="grp",
                ensure_group_location="westus2",
            )
        assert p.is_available() is True
        assert p._mgmt_client is None
        assert "SandboxGroupManagementClient missing" in caplog.text

    def test_custom_credential_skips_default_credential(self, fake_sdk):
        custom = object()
        ACASandboxProvider(
            resource_group="rg",
            sandbox_group="grp",
            region="eastus2",
            credential=custom,
        )
        fake_sdk.identity.DefaultAzureCredential.assert_not_called()
        # The custom credential was forwarded to SandboxGroupClient.
        args, _ = fake_sdk.sdk.SandboxGroupClient.call_args
        assert args[1] is custom


# =========================================================================
# Section 3: create_session
# =========================================================================


class TestCreateSession:
    def test_ungoverned_session_writes_no_egress_policy(self, provider, fake_sdk):
        handle = provider.create_session("agent-1")
        assert handle.status == SessionStatus.READY
        assert handle.session_id == "sb-abc123"
        fake_sdk.group.begin_create_sandbox.assert_called_once()
        # No policy → no egress configuration at all on the sandbox client.
        fake_sdk.default_sandbox.set_egress_policy.assert_not_called()

    def test_validates_agent_id(self, provider):
        with pytest.raises(ValueError, match="agent_id"):
            provider.create_session("bad agent id!")

    def test_create_sandbox_kwargs_include_disk_and_labels(self, provider, fake_sdk):
        provider.create_session("agent-1")
        kwargs = fake_sdk.group.begin_create_sandbox.call_args.kwargs
        assert kwargs["disk"] == "ubuntu"
        assert kwargs["labels"] == {"agent_id": "agent-1"}

    def test_governed_session_is_fail_closed_by_default(self, provider, fake_sdk):
        policy = _make_policy(network_allowlist=["pypi.org", "*.github.com"])
        provider.create_session("agent-1", policy=policy)

        sb = fake_sdk.default_sandbox
        sb.set_egress_policy.assert_called_once()
        body = sb.set_egress_policy.call_args.args[0]
        assert body.default_action == "Deny"
        assert {r.pattern for r in body.host_rules} == {
            "pypi.org",
            "*.github.com",
        }
        assert all(r.action == "Allow" for r in body.host_rules)

    def test_empty_allowlist_plus_deny_is_total_lockdown(self, provider, fake_sdk):
        policy = _make_policy(network_allowlist=[])
        provider.create_session("agent-1", policy=policy)

        sb = fake_sdk.default_sandbox
        sb.set_egress_policy.assert_called_once()
        body = sb.set_egress_policy.call_args.args[0]
        assert body.default_action == "Deny"
        assert body.host_rules == []

    def test_network_default_allow_skips_egress_api_call(self, provider, fake_sdk):
        policy = _make_policy(
            network_allowlist=["pypi.org"],
            network_default="allow",
        )
        provider.create_session("agent-1", policy=policy)
        fake_sdk.default_sandbox.set_egress_policy.assert_not_called()

    def test_egress_policy_failure_is_logged_not_raised(self, provider, fake_sdk):
        fake_sdk.default_sandbox.set_egress_policy.side_effect = RuntimeError(
            "egress 5xx"
        )
        policy = _make_policy(network_allowlist=["pypi.org"])
        handle = provider.create_session("agent-1", policy=policy)
        assert handle.status == SessionStatus.READY

    def test_egress_falls_back_to_dict_when_typed_models_missing(
        self, provider, fake_sdk, monkeypatch
    ):
        # Some forked SDKs ship without the typed EgressPolicy /
        # EgressHostRule models. Removing them should trigger the dict
        # fallback path rather than crash.
        import builtins

        real_import = builtins.__import__

        def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "azure.containerapps.sandbox" and fromlist and (
                "EgressPolicy" in fromlist or "EgressHostRule" in fromlist
            ):
                raise ImportError("simulated missing typed models")
            return real_import(name, globals, locals, fromlist, level)

        monkeypatch.setattr(builtins, "__import__", fake_import)

        policy = _make_policy(network_allowlist=["pypi.org"])
        provider.create_session("agent-1", policy=policy)

        sb = fake_sdk.default_sandbox
        sb.set_egress_policy.assert_called_once()
        body = sb.set_egress_policy.call_args.args[0]
        assert body == {
            "defaultAction": "Deny",
            "hostRules": [{"pattern": "pypi.org", "action": "Allow"}],
        }

    def test_create_sandbox_failure_raises_runtime_error(self, provider, fake_sdk):
        fake_sdk.group.begin_create_sandbox.side_effect = RuntimeError(
            "quota exceeded"
        )
        with pytest.raises(RuntimeError, match="quota exceeded"):
            provider.create_session("agent-1")

    def test_missing_sandbox_id_raises(self, provider, fake_sdk):
        broken = MagicMock(spec=[])  # no sandbox_id, no id
        fake_sdk.group.begin_create_sandbox.return_value = _make_poller(broken)
        with pytest.raises(RuntimeError, match="sandbox_id"):
            provider.create_session("agent-1")

    def test_falls_back_to_id_attribute_when_sandbox_id_absent(
        self, provider, fake_sdk
    ):
        sb = MagicMock()
        sb.sandbox_id = None
        sb.id = "sb-from-id"
        fake_sdk.group.begin_create_sandbox.return_value = _make_poller(sb)
        handle = provider.create_session("agent-1")
        assert handle.session_id == "sb-from-id"

    def test_policy_resource_caps_flow_into_create_kwargs(self, provider, fake_sdk):
        policy = _make_policy(max_cpu=0.5, max_memory_mb=1024)
        provider.create_session("agent-1", policy=policy)
        kwargs = fake_sdk.group.begin_create_sandbox.call_args.kwargs
        assert kwargs["cpu"] == "500m"
        assert kwargs["memory"] == "1024Mi"

    def test_cpu_floor_is_100m(self, provider, fake_sdk):
        policy = _make_policy(max_cpu=0.001)
        provider.create_session("agent-1", policy=policy)
        kwargs = fake_sdk.group.begin_create_sandbox.call_args.kwargs
        assert kwargs["cpu"] == "100m"

    def test_memory_floor_is_128mi(self, provider, fake_sdk):
        policy = _make_policy(max_memory_mb=16)
        provider.create_session("agent-1", policy=policy)
        kwargs = fake_sdk.group.begin_create_sandbox.call_args.kwargs
        assert kwargs["memory"] == "128Mi"

    def test_resource_caps_omitted_when_no_policy(self, provider, fake_sdk):
        # Without a policy the provider must not invent caps the user
        # didn't ask for — let the sandbox image defaults apply.
        provider.create_session("agent-1")
        kwargs = fake_sdk.group.begin_create_sandbox.call_args.kwargs
        assert "cpu" not in kwargs
        assert "memory" not in kwargs

    def test_typeerror_falls_back_to_minimal_kwargs(self, provider, fake_sdk):
        # If the SDK rejects unknown kwargs (cpu/memory/environment),
        # the provider retries with only disk + labels.
        calls: list[dict] = []

        def fake_create(**kwargs):
            calls.append(dict(kwargs))
            if "cpu" in kwargs:
                raise TypeError("unexpected keyword 'cpu'")
            return _make_poller(_make_sandbox_client("sb-fallback"))

        fake_sdk.group.begin_create_sandbox.side_effect = fake_create
        policy = _make_policy(max_cpu=0.5, max_memory_mb=256)
        handle = provider.create_session("agent-1", policy=policy)
        assert handle.session_id == "sb-fallback"
        assert len(calls) == 2
        assert "cpu" not in calls[1] and "memory" not in calls[1]

    def test_typeerror_fallback_also_failing_raises(self, provider, fake_sdk):
        # If even the minimal-kwargs retry blows up, the original-style
        # RuntimeError must surface so callers see a real failure.
        def fake_create(**kwargs):
            if "cpu" in kwargs:
                raise TypeError("unexpected keyword 'cpu'")
            raise RuntimeError("backend down")

        fake_sdk.group.begin_create_sandbox.side_effect = fake_create
        policy = _make_policy(max_cpu=0.5, max_memory_mb=256)
        with pytest.raises(RuntimeError, match="backend down"):
            provider.create_session("agent-1", policy=policy)

    def test_env_vars_forwarded_to_create(self, provider, fake_sdk):
        cfg = SandboxConfig(env_vars={"OPENAI_API_KEY": "sk-test", "DEBUG": "1"})
        provider.create_session("agent-1", config=cfg)
        kwargs = fake_sdk.group.begin_create_sandbox.call_args.kwargs
        assert kwargs["environment"] == {"OPENAI_API_KEY": "sk-test", "DEBUG": "1"}
        # Caller's dict must not be aliased — provider stores a copy.
        kwargs["environment"]["MUTATED"] = "yes"
        assert "MUTATED" not in cfg.env_vars

    def test_runs_ungated_when_evaluator_missing(self, provider, monkeypatch, caplog):
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "agent_os.policies.evaluator":
                raise ImportError("simulated")
            return real_import(name, *a, **kw)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        policy = _make_policy()
        with caplog.at_level("WARNING"):
            handle = provider.create_session("agent-1", policy=policy)
        assert handle.status == SessionStatus.READY
        assert "agent-os-kernel not installed" in caplog.text

    def test_evaluator_construction_error_is_fatal(self, provider, monkeypatch):
        class BadEvaluator:
            def __init__(self, *a, **kw):
                raise RuntimeError("evaluator broken")

        evaluator_module = MagicMock()
        evaluator_module.PolicyEvaluator = BadEvaluator
        monkeypatch.setitem(
            __import__("sys").modules,
            "agent_os.policies.evaluator",
            evaluator_module,
        )
        with pytest.raises(RuntimeError, match="PolicyEvaluator"):
            provider.create_session("agent-1", policy=_make_policy())

    def test_ensure_group_idempotent_on_existing_group(self, fake_sdk):
        p = ACASandboxProvider(
            resource_group="rg",
            sandbox_group="grp",
            ensure_group_location="westus2",
        )
        # get_sandbox_group succeeds → no create call.
        fake_sdk.mgmt.get_sandbox_group.return_value = {"name": "grp"}
        p.create_session("agent-1")
        fake_sdk.mgmt.begin_create_sandbox_group.assert_not_called()
        fake_sdk.mgmt.create_sandbox_group.assert_not_called()

    def test_ensure_group_creates_lro_when_missing(self, fake_sdk):
        p = ACASandboxProvider(
            resource_group="rg",
            sandbox_group="grp",
            ensure_group_location="westus2",
        )
        fake_sdk.mgmt.get_sandbox_group.side_effect = RuntimeError("404")
        p.create_session("agent-1")
        fake_sdk.mgmt.begin_create_sandbox_group.assert_called_once()

    def test_ensure_group_uses_legacy_method_names(self, fake_sdk):
        # Older preview SDKs expose `get_group` / `begin_create_group`
        # instead of the `_sandbox_group` variants.
        mgmt = MagicMock(spec=["get_group", "begin_create_group", "close"])
        mgmt.get_group.side_effect = RuntimeError("404")
        poller = MagicMock()
        poller.result.return_value = None
        mgmt.begin_create_group.return_value = poller
        fake_sdk.sdk.SandboxGroupManagementClient.return_value = mgmt

        p = ACASandboxProvider(
            resource_group="rg",
            sandbox_group="grp",
            ensure_group_location="westus2",
        )
        p.create_session("agent-1")
        mgmt.begin_create_group.assert_called_once_with(
            "grp", location="westus2"
        )
        poller.result.assert_called_once()

    def test_ensure_group_falls_back_to_sync_create(self, fake_sdk):
        # Some SDKs ship a synchronous `create_sandbox_group` without an
        # LRO `begin_create_sandbox_group`. Cover that branch.
        mgmt = MagicMock(spec=["get_sandbox_group", "create_sandbox_group", "close"])
        mgmt.get_sandbox_group.side_effect = RuntimeError("404")
        fake_sdk.sdk.SandboxGroupManagementClient.return_value = mgmt

        p = ACASandboxProvider(
            resource_group="rg",
            sandbox_group="grp",
            ensure_group_location="westus2",
        )
        p.create_session("agent-1")
        mgmt.create_sandbox_group.assert_called_once_with(
            "grp", location="westus2"
        )

    def test_ensure_group_noop_when_no_create_method_available(self, fake_sdk):
        # Tolerate a mgmt client surface we don't recognize: log nothing,
        # raise nothing, just leave the group untouched.
        mgmt = MagicMock(spec=["get_sandbox_group", "close"])
        mgmt.get_sandbox_group.side_effect = RuntimeError("404")
        fake_sdk.sdk.SandboxGroupManagementClient.return_value = mgmt

        p = ACASandboxProvider(
            resource_group="rg",
            sandbox_group="grp",
            ensure_group_location="westus2",
        )
        # Must not raise even though no create method exists.
        handle = p.create_session("agent-1")
        assert handle.status == SessionStatus.READY


# =========================================================================
# Section 4: execute_code
# =========================================================================


class _Decision:
    def __init__(self, allowed, reason=""):
        self.allowed = allowed
        self.reason = reason


class _StubEvaluator:
    """Captures the eval context and returns a canned decision."""

    def __init__(self, allow=True, reason=""):
        self.allow = allow
        self.reason = reason
        self.calls: list[dict] = []

    def evaluate(self, ctx):
        self.calls.append(dict(ctx))
        return _Decision(self.allow, self.reason)


@pytest.fixture()
def provider_with_evaluator(provider):
    """Provision a session and inject a stub evaluator under the lock."""

    def _build(allow=True, reason=""):
        handle = provider.create_session("agent-1")
        ev = _StubEvaluator(allow=allow, reason=reason)
        with provider._state_lock:
            provider._evaluators[(handle.agent_id, handle.session_id)] = ev
        return handle, ev

    return provider, _build


class TestExecuteCode:
    def test_no_session_raises(self, provider):
        with pytest.raises(RuntimeError, match="No active session"):
            provider.execute_code("agent-1", "nonexistent", "print(1)")

    def test_policy_deny_raises_before_any_azure_call(
        self, provider_with_evaluator, fake_sdk
    ):
        provider, build = provider_with_evaluator
        handle, _ev = build(allow=False, reason="rule X")
        fake_sdk.default_sandbox.exec.reset_mock()

        with pytest.raises(PermissionError, match="rule X"):
            provider.execute_code(handle.agent_id, handle.session_id, "import os")
        fake_sdk.default_sandbox.exec.assert_not_called()

    def test_context_is_merged_into_eval_ctx(self, provider_with_evaluator):
        provider, build = provider_with_evaluator
        handle, ev = build(allow=True)
        provider.execute_code(
            handle.agent_id, handle.session_id, "print(1)",
            context={"step_index": 3, "intent": "test"},
        )
        ctx = ev.calls[-1]
        assert ctx["agent_id"] == handle.agent_id
        assert ctx["action"] == "execute"
        assert ctx["code"] == "print(1)"
        assert ctx["step_index"] == 3
        assert ctx["intent"] == "test"

    def test_code_is_base64_piped_into_python3(
        self, provider_with_evaluator, fake_sdk
    ):
        provider, build = provider_with_evaluator
        handle, _ = build(allow=True)
        src = "print('héllo \\n quote\"')"
        provider.execute_code(handle.agent_id, handle.session_id, src)

        cmd = fake_sdk.default_sandbox.exec.call_args.args[0]
        assert "base64 -d | python3" in cmd
        encoded = cmd.split()[1]
        assert base64.b64decode(encoded).decode("utf-8") == src

    def test_success_result_wraps_typed_response(
        self, provider_with_evaluator, fake_sdk
    ):
        provider, build = provider_with_evaluator
        fake_sdk.default_sandbox.exec.return_value = SimpleNamespace(
            exit_code=0, stdout="hello\n", stderr=""
        )
        handle, _ = build(allow=True)
        result = provider.execute_code(handle.agent_id, handle.session_id, "print(1)")
        assert result.status == ExecutionStatus.COMPLETED
        assert result.result.success is True
        assert result.result.exit_code == 0
        assert result.result.stdout == "hello\n"

    def test_failure_result_when_exit_code_nonzero(
        self, provider_with_evaluator, fake_sdk
    ):
        provider, build = provider_with_evaluator
        fake_sdk.default_sandbox.exec.return_value = SimpleNamespace(
            exit_code=1, stdout="", stderr="boom"
        )
        handle, _ = build(allow=True)
        result = provider.execute_code(handle.agent_id, handle.session_id, "x")
        assert result.status == ExecutionStatus.FAILED
        assert result.result.success is False
        assert result.result.exit_code == 1
        assert result.result.stderr == "boom"

    def test_legacy_dict_response_supported(
        self, provider_with_evaluator, fake_sdk
    ):
        # Earlier preview builds returned a dict instead of a typed
        # object; the provider must keep accepting that shape.
        provider, build = provider_with_evaluator
        fake_sdk.default_sandbox.exec.return_value = {
            "exitCode": 0,
            "stdout": "legacy",
            "stderr": "",
        }
        handle, _ = build(allow=True)
        result = provider.execute_code(handle.agent_id, handle.session_id, "p")
        assert result.result.success is True
        assert result.result.stdout == "legacy"

    def test_stdout_stderr_truncated_to_10k(
        self, provider_with_evaluator, fake_sdk
    ):
        provider, build = provider_with_evaluator
        big = "x" * 50000
        fake_sdk.default_sandbox.exec.return_value = SimpleNamespace(
            exit_code=0, stdout=big, stderr=big
        )
        handle, _ = build(allow=True)
        result = provider.execute_code(handle.agent_id, handle.session_id, "p")
        assert len(result.result.stdout) == 10000
        assert len(result.result.stderr) == 10000

    def test_exec_exception_returns_failed_handle(
        self, provider_with_evaluator, fake_sdk
    ):
        provider, build = provider_with_evaluator
        fake_sdk.default_sandbox.exec.side_effect = RuntimeError("transport down")
        handle, _ = build(allow=True)
        result = provider.execute_code(handle.agent_id, handle.session_id, "p")
        assert result.status == ExecutionStatus.FAILED
        assert result.result.success is False
        assert "transport down" in result.result.stderr

    def test_timeout_kill_when_duration_exceeds_session_cfg(
        self, provider_with_evaluator, fake_sdk, monkeypatch
    ):
        provider, build = provider_with_evaluator
        handle, _ = build(allow=True)
        with provider._state_lock:
            cfg = provider._session_configs[(handle.agent_id, handle.session_id)]
            cfg.timeout_seconds = 0.001

        from agent_sandbox.aca_sandbox_provider import (
            aca_sandbox_provider as mod,
        )

        ticks = iter([0.0, 1.0])
        monkeypatch.setattr(mod.time, "monotonic", lambda: next(ticks))

        result = provider.execute_code(handle.agent_id, handle.session_id, "p")
        assert result.result.killed is True
        assert "timeout" in (result.result.kill_reason or "").lower()


# =========================================================================
# Section 5: destroy_session / status / close
# =========================================================================


class TestDestroyAndStatus:
    def test_destroy_unknown_session_is_noop(self, provider, fake_sdk):
        provider.destroy_session("ghost", "ghost")
        fake_sdk.default_sandbox.delete.assert_not_called()

    def test_destroy_calls_sandbox_delete_and_cleans_state(
        self, provider, fake_sdk
    ):
        handle = provider.create_session("agent-1")
        provider.destroy_session(handle.agent_id, handle.session_id)
        fake_sdk.default_sandbox.delete.assert_called_once_with()

        fake_sdk.default_sandbox.delete.reset_mock()
        # Second destroy is idempotent — state is gone, no re-delete.
        provider.destroy_session(handle.agent_id, handle.session_id)
        fake_sdk.default_sandbox.delete.assert_not_called()

    def test_destroy_swallows_delete_failure(self, provider, fake_sdk, caplog):
        fake_sdk.default_sandbox.delete.side_effect = RuntimeError("404 not found")
        handle = provider.create_session("agent-1")
        with caplog.at_level("WARNING"):
            provider.destroy_session(handle.agent_id, handle.session_id)
        assert "Failed to delete Azure sandbox" in caplog.text

    def test_get_session_status(self, provider):
        handle = provider.create_session("agent-1")
        assert (
            provider.get_session_status(handle.agent_id, handle.session_id)
            == SessionStatus.READY
        )
        provider.destroy_session(handle.agent_id, handle.session_id)
        assert (
            provider.get_session_status(handle.agent_id, handle.session_id)
            == SessionStatus.DESTROYED
        )

    def test_close_releases_group_client(self, provider, fake_sdk):
        provider.close()
        fake_sdk.group.close.assert_called_once()

    def test_close_tolerates_client_errors(self, provider, fake_sdk):
        fake_sdk.group.close.side_effect = RuntimeError("dangling")
        provider.close()  # must not raise

    def test_context_manager_calls_close(self, fake_sdk):
        with ACASandboxProvider(
            resource_group="rg", sandbox_group="grp", region="eastus2"
        ) as p:
            assert p.is_available() is True
        fake_sdk.group.close.assert_called_once()


# =========================================================================
# Section 6: Async wrappers
# =========================================================================


class TestAsyncWrappers:
    def test_create_and_execute_and_destroy_async(self, provider, fake_sdk):
        async def run():
            handle = await provider.create_session_async("agent-1")
            with provider._state_lock:
                provider._evaluators[(handle.agent_id, handle.session_id)] = (
                    _StubEvaluator(allow=True)
                )
            exec_handle = await provider.execute_code_async(
                handle.agent_id, handle.session_id, "print(1)"
            )
            await provider.destroy_session_async(handle.agent_id, handle.session_id)
            return exec_handle

        exec_handle = asyncio.run(run())
        assert exec_handle.status == ExecutionStatus.COMPLETED
        fake_sdk.group.begin_create_sandbox.assert_called_once()
        fake_sdk.default_sandbox.exec.assert_called_once()
        fake_sdk.default_sandbox.delete.assert_called_once()


# =========================================================================
# Section 7: Multi-session isolation
# =========================================================================


class TestMultiSessionIsolation:
    def test_two_agents_independent_state(self, provider, fake_sdk):
        sb_a = _make_sandbox_client("sb-a")
        sb_b = _make_sandbox_client("sb-b")
        fake_sdk.queue(sb_a, sb_b)

        h1 = provider.create_session("agent-1", policy=_make_policy(max_cpu=0.5))
        h2 = provider.create_session("agent-2", policy=_make_policy(max_cpu=2.0))

        assert h1.session_id == "sb-a"
        assert h2.session_id == "sb-b"

        with provider._state_lock:
            cfg1 = provider._session_configs[(h1.agent_id, h1.session_id)]
            cfg2 = provider._session_configs[(h2.agent_id, h2.session_id)]

        assert cfg1.cpu_limit == 0.5
        assert cfg2.cpu_limit == 2.0

        # Destroying one must not touch the other.
        provider.destroy_session(h1.agent_id, h1.session_id)
        sb_a.delete.assert_called_once()
        sb_b.delete.assert_not_called()
        assert (
            provider.get_session_status(h2.agent_id, h2.session_id)
            == SessionStatus.READY
        )
