# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Unit tests for ``ACASandboxProvider``.

All ``azure-sandbox`` / ``azure-mgmt-sandbox`` calls are mocked, so this
file runs without Azure credentials or network access.  Integration
tests that hit real Azure live in ``test_azure_sandbox_integration.py``.

Covers:
* Module-level helpers (``_validate_resource_name``,
  ``_network_allowlist``, ``_network_default``,
  ``aca_config_from_policy``).
* Construction: missing SDK, name validation,
  ``ensure_group_location`` wiring.
* ``create_session``: with/without policy, fail-closed egress,
  ``network_default=allow`` opt-out, empty allowlist, invalid IDs,
  data-plane failures, missing sandbox id.
* ``execute_code``: policy gate fires before any Azure call,
  base64 transport, context merging, timeout kill, no-session error,
  data-plane failure surfacing.
* ``destroy_session``: idempotent, error swallowing.
* ``get_session_status``, ``close``, ``__exit__``, ``is_available``.
* ``*_async`` wrappers delegate to sync counterparts.
* Multi-session isolation: per-session evaluator + config + sandbox id
  do not bleed between agents.
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
    """Build a duck-typed policy object matching what the provider reads.

    Using ``SimpleNamespace`` keeps the unit tests independent of
    ``agent-os-kernel``'s real ``PolicyDocument`` schema.  Schema-level
    contracts are validated separately in ``test_azure_sandbox_schema.py``.
    """
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


@pytest.fixture()
def fake_clients():
    """Patch the lazy SDK imports so construction never touches Azure."""
    data_client = MagicMock(name="SandboxClient")
    mgmt_client = MagicMock(name="SandboxGroupManagementClient")

    sandbox_module = MagicMock()
    sandbox_module.SandboxClient = MagicMock(return_value=data_client)
    mgmt_module = MagicMock()
    mgmt_module.SandboxGroupManagementClient = MagicMock(return_value=mgmt_client)

    with patch.dict(
        "sys.modules",
        {
            "azure.sandbox": sandbox_module,
            "azure.mgmt.sandbox": mgmt_module,
        },
    ):
        yield data_client, mgmt_client


@pytest.fixture()
def provider(fake_clients):
    data_client, _ = fake_clients
    # Configure default create_sandbox response so happy paths "just work".
    data_client.create_sandbox.return_value = {"id": "sb-abc123"}
    data_client.exec.return_value = {"exitCode": 0, "stdout": "ok", "stderr": ""}
    p = ACASandboxProvider(
        resource_group="rg",
        sandbox_group="grp",
    )
    return p


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
            "",                # empty
            "-leading-dash",   # must start with alnum
            "_leading_us",     # must start with alnum
            "has space",
            "has/slash",
            "has.dot",
            "a" * 64,          # length 64 — limit is 63 after first char
            123,               # wrong type
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
        entries = [SimpleNamespace(host="x.com"), SimpleNamespace(pattern="*.y.com")]
        assert _network_allowlist(SimpleNamespace(network_allowlist=entries)) == [
            "x.com",
            "*.y.com",
        ]

    def test_skips_entries_with_no_host_or_pattern(self):
        entries = [
            "a.com",
            SimpleNamespace(),  # neither host nor pattern → skipped
            SimpleNamespace(host="b.com"),
        ]
        assert _network_allowlist(SimpleNamespace(network_allowlist=entries)) == [
            "a.com",
            "b.com",
        ]

    def test_none_allowlist(self):
        assert _network_allowlist(SimpleNamespace(network_allowlist=None)) == []


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


class TestAzureConfigFromPolicy:
    def test_preserves_base_when_policy_empty(self):
        base = SandboxConfig(memory_mb=999, cpu_limit=3.0, timeout_seconds=42)
        cfg = aca_config_from_policy(SimpleNamespace(defaults=SimpleNamespace()), base)
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
        # Falsy values should leave the base config alone (provider default wins).
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
        cfg = aca_config_from_policy(SimpleNamespace(defaults=SimpleNamespace()), base)
        cfg.env_vars["NEW"] = "X"
        assert "NEW" not in base.env_vars


# =========================================================================
# Section 2: Construction
# =========================================================================


class TestConstruction:
    def test_unavailable_when_sdk_missing(self, monkeypatch):
        # Force the lazy import to raise ImportError.
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "azure.sandbox":
                raise ImportError("simulated")
            return real_import(name, *a, **kw)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        p = ACASandboxProvider(resource_group="rg", sandbox_group="grp")
        assert p.is_available() is False
        with pytest.raises(RuntimeError, match="not available"):
            p.create_session("agent")

    def test_validates_sandbox_group_name(self, fake_clients):
        with pytest.raises(ValueError, match="sandbox_group"):
            ACASandboxProvider(resource_group="rg", sandbox_group="bad name")

    def test_data_client_construction_failure_marks_unavailable(self, monkeypatch):
        import builtins

        sandbox_module = MagicMock()
        sandbox_module.SandboxClient = MagicMock(side_effect=RuntimeError("boom"))

        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "azure.sandbox":
                return sandbox_module
            return real_import(name, *a, **kw)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        p = ACASandboxProvider(resource_group="rg", sandbox_group="grp")
        assert p.is_available() is False

    def test_ensure_group_location_constructs_mgmt_client(self, fake_clients):
        _, mgmt_client = fake_clients
        p = ACASandboxProvider(
            resource_group="rg",
            sandbox_group="grp",
            ensure_group_location="westus2",
        )
        assert p.is_available() is True
        assert p._mgmt_client is mgmt_client

    def test_no_mgmt_client_when_ensure_location_unset(self, fake_clients):
        p = ACASandboxProvider(resource_group="rg", sandbox_group="grp")
        assert p._mgmt_client is None

    def test_mgmt_client_failure_does_not_kill_provider(self, monkeypatch):
        import builtins

        data_client = MagicMock()
        sandbox_module = MagicMock()
        sandbox_module.SandboxClient = MagicMock(return_value=data_client)

        mgmt_module = MagicMock()
        mgmt_module.SandboxGroupManagementClient = MagicMock(
            side_effect=RuntimeError("mgmt-down")
        )

        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "azure.sandbox":
                return sandbox_module
            if name == "azure.mgmt.sandbox":
                return mgmt_module
            return real_import(name, *a, **kw)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        p = ACASandboxProvider(
            resource_group="rg",
            sandbox_group="grp",
            ensure_group_location="westus2",
        )
        # Data plane still works; mgmt client is None.
        assert p.is_available() is True
        assert p._mgmt_client is None


# =========================================================================
# Section 3: create_session
# =========================================================================


class TestCreateSession:
    def test_ungoverned_session_writes_no_egress_policy(self, provider, fake_clients):
        data_client, _ = fake_clients
        handle = provider.create_session("agent-1")
        assert handle.status == SessionStatus.READY
        assert handle.session_id == "sb-abc123"
        data_client.create_sandbox.assert_called_once()
        # No policy → no egress configuration at all.
        data_client.set_egress_policy.assert_not_called()

    def test_validates_agent_id(self, provider):
        with pytest.raises(ValueError, match="agent_id"):
            provider.create_session("bad agent id!")

    def test_governed_session_is_fail_closed_by_default(self, provider, fake_clients):
        data_client, _ = fake_clients
        policy = _make_policy(network_allowlist=["pypi.org", "*.github.com"])
        provider.create_session("agent-1", policy=policy)

        data_client.set_egress_policy.assert_called_once()
        sandbox_id, group, body = data_client.set_egress_policy.call_args.args
        assert sandbox_id == "sb-abc123"
        assert group == "grp"
        assert body["defaultAction"] == "Deny"
        assert {r["pattern"] for r in body["hostRules"]} == {"pypi.org", "*.github.com"}
        assert all(r["action"] == "Allow" for r in body["hostRules"])

    def test_empty_allowlist_plus_deny_is_total_lockdown(self, provider, fake_clients):
        data_client, _ = fake_clients
        # Schema default for network_default is "deny"; an empty allowlist
        # must still write a deny-all policy.
        policy = _make_policy(network_allowlist=[])
        provider.create_session("agent-1", policy=policy)

        data_client.set_egress_policy.assert_called_once()
        body = data_client.set_egress_policy.call_args.args[2]
        assert body == {"defaultAction": "Deny", "hostRules": []}

    def test_network_default_allow_skips_egress_api_call(self, provider, fake_clients):
        data_client, _ = fake_clients
        policy = _make_policy(
            network_allowlist=["pypi.org"],
            network_default="allow",
        )
        provider.create_session("agent-1", policy=policy)
        data_client.set_egress_policy.assert_not_called()

    def test_egress_policy_failure_is_logged_not_raised(self, provider, fake_clients):
        data_client, _ = fake_clients
        data_client.set_egress_policy.side_effect = RuntimeError("egress 5xx")
        policy = _make_policy(network_allowlist=["pypi.org"])
        # Must not propagate — session creation still succeeds.
        handle = provider.create_session("agent-1", policy=policy)
        assert handle.status == SessionStatus.READY

    def test_create_sandbox_failure_raises_runtime_error(self, provider, fake_clients):
        data_client, _ = fake_clients
        data_client.create_sandbox.side_effect = RuntimeError("quota exceeded")
        with pytest.raises(RuntimeError, match="quota exceeded"):
            provider.create_session("agent-1")

    def test_missing_sandbox_id_in_response_raises(self, provider, fake_clients):
        data_client, _ = fake_clients
        data_client.create_sandbox.return_value = {}
        with pytest.raises(RuntimeError, match="missing 'id'"):
            provider.create_session("agent-1")

    def test_uses_name_when_id_missing(self, provider, fake_clients):
        data_client, _ = fake_clients
        data_client.create_sandbox.return_value = {"name": "sb-by-name"}
        handle = provider.create_session("agent-1")
        assert handle.session_id == "sb-by-name"

    def test_policy_resource_caps_flow_into_create_sandbox(self, provider, fake_clients):
        data_client, _ = fake_clients
        policy = _make_policy(max_cpu=0.5, max_memory_mb=1024)
        provider.create_session("agent-1", policy=policy)
        kwargs = data_client.create_sandbox.call_args.kwargs
        assert kwargs["cpu"] == "500m"
        assert kwargs["memory"] == "1024Mi"

    def test_cpu_floor_is_100m(self, provider, fake_clients):
        data_client, _ = fake_clients
        policy = _make_policy(max_cpu=0.001)  # would round to 1m
        provider.create_session("agent-1", policy=policy)
        assert data_client.create_sandbox.call_args.kwargs["cpu"] == "100m"

    def test_memory_floor_is_128mi(self, provider, fake_clients):
        data_client, _ = fake_clients
        policy = _make_policy(max_memory_mb=16)
        provider.create_session("agent-1", policy=policy)
        assert data_client.create_sandbox.call_args.kwargs["memory"] == "128Mi"

    def test_runs_ungated_when_evaluator_missing(self, provider, monkeypatch, caplog):
        # Simulate agent-os-kernel not being installed.
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
        # An *unexpected* evaluator error must not silently degrade to ungated.
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

    def test_ensure_group_idempotent_on_existing_group(self, fake_clients):
        data_client, mgmt_client = fake_clients
        data_client.create_sandbox.return_value = {"id": "sb-1"}
        p = ACASandboxProvider(
            resource_group="rg",
            sandbox_group="grp",
            ensure_group_location="westus2",
        )
        # get_group succeeds → no create_group call.
        mgmt_client.get_group.return_value = {"name": "grp"}
        p.create_session("agent-1")
        mgmt_client.create_group.assert_not_called()

    def test_ensure_group_creates_when_missing(self, fake_clients):
        data_client, mgmt_client = fake_clients
        data_client.create_sandbox.return_value = {"id": "sb-1"}
        p = ACASandboxProvider(
            resource_group="rg",
            sandbox_group="grp",
            ensure_group_location="westus2",
        )
        mgmt_client.get_group.side_effect = RuntimeError("404")
        p.create_session("agent-1")
        mgmt_client.create_group.assert_called_once()


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
        self, provider_with_evaluator, fake_clients
    ):
        provider, build = provider_with_evaluator
        data_client, _ = fake_clients
        handle, _ev = build(allow=False, reason="rule X")
        data_client.exec.reset_mock()

        with pytest.raises(PermissionError, match="rule X"):
            provider.execute_code(handle.agent_id, handle.session_id, "import os")
        data_client.exec.assert_not_called()

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

    def test_code_is_base64_piped_into_python3(self, provider_with_evaluator, fake_clients):
        provider, build = provider_with_evaluator
        data_client, _ = fake_clients
        handle, _ = build(allow=True)
        src = "print('héllo \\n quote\"')"
        provider.execute_code(handle.agent_id, handle.session_id, src)

        cmd = data_client.exec.call_args.args[2]
        assert "base64 -d | python3" in cmd
        encoded = cmd.split()[1]
        assert base64.b64decode(encoded).decode("utf-8") == src

    def test_success_result_wraps_exit_code_and_streams(
        self, provider_with_evaluator, fake_clients
    ):
        provider, build = provider_with_evaluator
        data_client, _ = fake_clients
        data_client.exec.return_value = {
            "exitCode": 0,
            "stdout": "hello\n",
            "stderr": "",
        }
        handle, _ = build(allow=True)
        result = provider.execute_code(handle.agent_id, handle.session_id, "print(1)")
        assert result.status == ExecutionStatus.COMPLETED
        assert result.result.success is True
        assert result.result.exit_code == 0
        assert result.result.stdout == "hello\n"

    def test_failure_result_when_exit_code_nonzero(
        self, provider_with_evaluator, fake_clients
    ):
        provider, build = provider_with_evaluator
        data_client, _ = fake_clients
        data_client.exec.return_value = {
            "exitCode": 1,
            "stdout": "",
            "stderr": "boom",
        }
        handle, _ = build(allow=True)
        result = provider.execute_code(handle.agent_id, handle.session_id, "x")
        assert result.status == ExecutionStatus.FAILED
        assert result.result.success is False
        assert result.result.exit_code == 1
        assert result.result.stderr == "boom"

    def test_stdout_stderr_truncated_to_10k(
        self, provider_with_evaluator, fake_clients
    ):
        provider, build = provider_with_evaluator
        data_client, _ = fake_clients
        big = "x" * 50000
        data_client.exec.return_value = {
            "exitCode": 0,
            "stdout": big,
            "stderr": big,
        }
        handle, _ = build(allow=True)
        result = provider.execute_code(handle.agent_id, handle.session_id, "p")
        assert len(result.result.stdout) == 10000
        assert len(result.result.stderr) == 10000

    def test_exec_exception_returns_failed_handle(
        self, provider_with_evaluator, fake_clients
    ):
        provider, build = provider_with_evaluator
        data_client, _ = fake_clients
        data_client.exec.side_effect = RuntimeError("transport down")
        handle, _ = build(allow=True)
        result = provider.execute_code(handle.agent_id, handle.session_id, "p")
        assert result.status == ExecutionStatus.FAILED
        assert result.result.success is False
        assert "transport down" in result.result.stderr

    def test_timeout_kill_when_duration_exceeds_session_cfg(
        self, provider_with_evaluator, fake_clients, monkeypatch
    ):
        provider, build = provider_with_evaluator
        data_client, _ = fake_clients

        # Force timeout_seconds to a tiny value so any real duration trips it.
        handle, _ = build(allow=True)
        with provider._state_lock:
            cfg = provider._session_configs[(handle.agent_id, handle.session_id)]
            cfg.timeout_seconds = 0.001

        # Fake time.monotonic so duration > timeout_seconds.
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
    def test_destroy_unknown_session_is_noop(self, provider, fake_clients):
        data_client, _ = fake_clients
        provider.destroy_session("ghost", "ghost")
        data_client.delete_sandbox.assert_not_called()

    def test_destroy_calls_delete_sandbox_and_cleans_state(
        self, provider, fake_clients
    ):
        data_client, _ = fake_clients
        handle = provider.create_session("agent-1")
        provider.destroy_session(handle.agent_id, handle.session_id)
        data_client.delete_sandbox.assert_called_once_with(
            "sb-abc123", "grp", resource_group="rg"
        )
        # Calling again must not crash and must not re-invoke delete.
        data_client.delete_sandbox.reset_mock()
        provider.destroy_session(handle.agent_id, handle.session_id)
        data_client.delete_sandbox.assert_not_called()

    def test_destroy_swallows_delete_failure(self, provider, fake_clients, caplog):
        data_client, _ = fake_clients
        data_client.delete_sandbox.side_effect = RuntimeError("404 not found")
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

    def test_close_releases_clients(self, provider, fake_clients):
        data_client, _ = fake_clients
        provider.close()
        data_client.close.assert_called_once()

    def test_close_tolerates_client_errors(self, provider, fake_clients):
        data_client, _ = fake_clients
        data_client.close.side_effect = RuntimeError("dangling")
        provider.close()  # must not raise

    def test_context_manager_calls_close(self, fake_clients):
        data_client, _ = fake_clients
        with ACASandboxProvider(resource_group="rg", sandbox_group="grp") as p:
            assert p.is_available() is True
        data_client.close.assert_called_once()


# =========================================================================
# Section 6: Async wrappers
# =========================================================================


class TestAsyncWrappers:
    def test_create_and_execute_and_destroy_async(self, provider, fake_clients):
        data_client, _ = fake_clients

        async def run():
            handle = await provider.create_session_async("agent-1")
            # Inject a permissive evaluator to exercise the gate.
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
        data_client.create_sandbox.assert_called_once()
        data_client.exec.assert_called_once()
        data_client.delete_sandbox.assert_called_once()


# =========================================================================
# Section 7: Multi-session isolation
# =========================================================================


class TestMultiSessionIsolation:
    def test_two_agents_independent_state(self, provider, fake_clients):
        data_client, _ = fake_clients
        ids = iter([{"id": "sb-a"}, {"id": "sb-b"}])
        data_client.create_sandbox.side_effect = lambda *a, **kw: next(ids)

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
        assert (
            provider.get_session_status(h2.agent_id, h2.session_id)
            == SessionStatus.READY
        )
