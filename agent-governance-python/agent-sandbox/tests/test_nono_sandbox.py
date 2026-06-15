# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Unit tests for :mod:`agent_sandbox.nono_sandbox_provider`.

The native ``nono-py`` extension is never required: the provider's module
global ``_nono_module`` is monkeypatched with a fake that records the
``CapabilitySet`` / proxy / ``sandboxed_exec`` calls and returns canned
results. This keeps the suite hermetic — no nono install, no kernel
sandbox, no network — and lets the same tests run on any host (including
Windows, where nono is unsupported).

Coverage targets:

* Config: :class:`NonoConfig` validation, ``from_sandbox_config``,
  the fail-closed egress contract, env sanitisation.
* Policy translation: ``nono_config_from_policy``,
  ``policy_yaml_to_nono_config`` (including the ``sandbox_mounts`` block).
* Construction / availability: unsupported host, missing extension.
* Lifecycle: create/execute/destroy, session reuse, status, raw ``run``,
  ``run_once``.
* Spawn behaviour: capability wiring (system / ro / rw paths, network
  block vs proxy), env isolation, timeout → killed result, output
  truncation, sandboxed_exec failure.
* Guards: invalid agent_id, code-scanner enforcement, policy deny gate,
  tool_allowlist fail-closed, protected mount rejection, non-Python
  interpreter fail-closed.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from agent_sandbox.code_scanner import SandboxCodeViolation
from agent_sandbox.nono_sandbox_provider import (
    NonoConfig,
    nono_config_from_policy,
    policy_yaml_to_nono_config,
)
from agent_sandbox.nono_sandbox_provider import provider as provider_mod
from agent_sandbox.sandbox_provider import (
    ExecutionStatus,
    SandboxConfig,
    SessionStatus,
)

# =========================================================================
# Fake nono_py module
# =========================================================================


class _AccessMode:
    READ = "READ"
    WRITE = "WRITE"
    READ_WRITE = "READ_WRITE"


class _FakeCaps:
    def __init__(self) -> None:
        self.paths: list[tuple[str, str]] = []
        self.network_blocked = False
        self.proxy: Any | None = None

    def allow_path(self, path: str, mode: str) -> None:
        self.paths.append((path, mode))

    def block_network(self) -> None:
        self.network_blocked = True

    def proxy_only(self, proxy: Any) -> None:
        self.proxy = proxy


class _FakeProxy:
    def __init__(self, config: Any) -> None:
        self.config = config
        self.shutdown_called = False

    def sandbox_env(
        self, extra: list[tuple[str, str]] | None = None
    ) -> list[tuple[str, str]]:
        merged = [("HTTP_PROXY", "http://127.0.0.1:9999")]
        merged.extend(extra or [])
        return merged

    def shutdown(self) -> None:
        self.shutdown_called = True


class _FakeProxyConfig:
    def __init__(
        self,
        allowed_hosts: list[str] | None = None,
        allow_all_hosts: bool = False,
    ) -> None:
        self.allowed_hosts = allowed_hosts or []
        self.allow_all_hosts = allow_all_hosts


class _FakeExecResult:
    def __init__(self, stdout: bytes, stderr: bytes, exit_code: int) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code


class _FakeNono:
    """Stand-in for the ``nono_py`` module."""

    def __init__(self) -> None:
        self.AccessMode = _AccessMode
        self.CapabilitySet = _FakeCaps
        self.ProxyConfig = _FakeProxyConfig
        self._supported = True
        # Last invocation bookkeeping.
        self.last_caps: _FakeCaps | None = None
        self.last_command: list[str] | None = None
        self.last_cwd: str | None = None
        self.last_env: list[tuple[str, str]] | None = None
        self.last_timeout: float | None = None
        self.last_inherit_env: bool | None = None
        self.proxies: list[_FakeProxy] = []
        # Canned result / behaviour.
        self.stdout = b"ok"
        self.stderr = b""
        self.exit_code = 0
        self.raise_exc: BaseException | None = None

    def is_supported(self) -> bool:
        return self._supported

    def support_info(self) -> Any:
        return SimpleNamespace(details="fake", is_supported=self._supported)

    def start_proxy(self, config: Any) -> _FakeProxy:
        proxy = _FakeProxy(config)
        self.proxies.append(proxy)
        return proxy

    def sandboxed_exec(
        self,
        caps: _FakeCaps,
        command: list[str],
        cwd: str | None = None,
        timeout_secs: float | None = None,
        env: list[tuple[str, str]] | None = None,
        inherit_env: bool = False,
    ) -> _FakeExecResult:
        self.last_caps = caps
        self.last_command = list(command)
        self.last_cwd = cwd
        self.last_env = list(env) if env is not None else None
        self.last_timeout = timeout_secs
        self.last_inherit_env = inherit_env
        if self.raise_exc is not None:
            raise self.raise_exc
        return _FakeExecResult(self.stdout, self.stderr, self.exit_code)


@pytest.fixture
def fake_nono(monkeypatch):
    """Install a fake ``nono_py`` as the provider's module global."""
    fake = _FakeNono()
    monkeypatch.setattr(provider_mod, "_nono_module", fake)
    return fake


@pytest.fixture
def provider(fake_nono):
    return provider_mod.NonoSandboxProvider()


# =========================================================================
# NonoConfig
# =========================================================================


class TestNonoConfig:
    def test_defaults(self):
        cfg = NonoConfig()
        assert cfg.allow_outbound is False
        assert cfg.readonly_paths == []
        assert cfg.timeout_seconds == 60.0

    def test_nonpositive_timeout_rejected(self):
        with pytest.raises(ValueError, match="timeout_seconds must be positive"):
            NonoConfig(timeout_seconds=0)

    def test_outbound_without_hosts_rejected(self):
        with pytest.raises(ValueError, match="without a host allowlist"):
            NonoConfig(allow_outbound=True)

    def test_outbound_unrestricted_requires_explicit_opt_in(self):
        cfg = NonoConfig(allow_outbound=True, allow_unrestricted_egress=True)
        assert cfg.allow_outbound is True
        assert cfg.allowed_hosts == []

    def test_outbound_with_hosts_ok(self):
        cfg = NonoConfig(allow_outbound=True, allowed_hosts=["pypi.org"])
        assert cfg.allowed_hosts == ["pypi.org"]

    def test_from_sandbox_config(self):
        sc = SandboxConfig(
            timeout_seconds=10,
            network_enabled=True,
            input_dir="/in",
            output_dir="/out",
            env_vars={"K": "V"},
        )
        cfg = NonoConfig.from_sandbox_config(sc)
        assert cfg.timeout_seconds == 10
        assert cfg.allow_outbound is True
        assert cfg.allow_unrestricted_egress is True
        assert cfg.readonly_paths == ["/in"]
        assert cfg.readwrite_paths == ["/out"]
        assert cfg.env_vars == {"K": "V"}

    def test_sanitized_env_strips_loader_hooks(self):
        cfg = NonoConfig(
            env_vars={"SAFE": "ok", "LD_PRELOAD": "/tmp/evil.so"}
        )
        assert cfg.sanitized_env() == {"SAFE": "ok"}


# =========================================================================
# Policy translation
# =========================================================================


def _force_unix_paths(monkeypatch):
    import agent_sandbox._hardening as hardening

    monkeypatch.setattr(
        hardening, "platform", SimpleNamespace(system=lambda: "Linux")
    )
    monkeypatch.setattr(hardening.os.path, "realpath", lambda p: p)


def _policy(**kw):
    """Build a policy for config translation and session tests."""
    defaults: dict[str, Any] = {"action": "allow"}
    for field in ("timeout_seconds", "max_memory_mb", "max_cpu", "network_default"):
        if field in kw and kw[field] is not None:
            defaults[field] = kw[field]

    doc: dict[str, Any] = {
        "name": kw.get("name", "test-policy"),
        "version": kw.get("version", "1"),
        "rules": kw.get("rules", []),
        "defaults": defaults,
    }
    if "network_allowlist" in kw:
        doc["network_allowlist"] = list(kw["network_allowlist"] or [])
    if "tool_allowlist" in kw:
        doc["tool_allowlist"] = list(kw["tool_allowlist"] or [])
    if "input_dir" in kw or "output_dir" in kw:
        doc["sandbox_mounts"] = {
            "input_dir": kw.get("input_dir"),
            "output_dir": kw.get("output_dir"),
        }

    try:
        from agent_os.policies import PolicyDocument

        return PolicyDocument.model_validate(doc)
    except ImportError:
        mounts = None
        if "sandbox_mounts" in doc:
            mounts = SimpleNamespace(**doc["sandbox_mounts"])
        return SimpleNamespace(
            name=doc["name"],
            version=doc["version"],
            rules=doc["rules"],
            defaults=SimpleNamespace(**defaults),
            sandbox_mounts=mounts,
            network_allowlist=doc.get("network_allowlist"),
            tool_allowlist=doc.get("tool_allowlist"),
        )


class TestPolicyTranslation:
    def test_mounts_and_egress(self):
        cfg = nono_config_from_policy(
            _policy(
                timeout_seconds=45,
                input_dir="/data/in",
                output_dir="/data/out",
                network_allowlist=["pypi.org", "*.github.com"],
            )
        )
        assert cfg.timeout_seconds == 45
        assert "/data/in" in cfg.readonly_paths
        assert "/data/out" in cfg.readwrite_paths
        assert cfg.allow_outbound is True
        assert cfg.allowed_hosts == ["pypi.org", "*.github.com"]

    def test_no_network_allowlist_keeps_egress_off(self):
        cfg = nono_config_from_policy(_policy(timeout_seconds=5))
        assert cfg.allow_outbound is False

    def test_network_default_allow_enables_unrestricted(self):
        cfg = nono_config_from_policy(_policy(network_default="allow"))
        assert cfg.allow_outbound is True
        assert cfg.allow_unrestricted_egress is True
        assert cfg.allowed_hosts == []

    def test_network_default_deny_keeps_egress_off(self):
        cfg = nono_config_from_policy(_policy(network_default="deny"))
        assert cfg.allow_outbound is False

    def test_network_allowlist_takes_precedence_over_default(self):
        cfg = nono_config_from_policy(
            _policy(network_default="allow", network_allowlist=["pypi.org"])
        )
        assert cfg.allow_outbound is True
        assert cfg.allowed_hosts == ["pypi.org"]
        assert cfg.allow_unrestricted_egress is False

    def test_protected_mount_rejected(self, monkeypatch):
        _force_unix_paths(monkeypatch)
        with pytest.raises(ValueError, match="protected system directory"):
            nono_config_from_policy(_policy(input_dir="/usr"))

    def test_policy_yaml_to_nono_config(self, tmp_path):
        yaml_text = (
            'version: "1.0"\n'
            "name: demo\n"
            "defaults:\n"
            "  timeout_seconds: 30\n"
            "  max_memory_mb: 512\n"
            "network_allowlist:\n"
            "  - pypi.org\n"
            "sandbox_mounts:\n"
            "  input_dir: /data/user-pdf\n"
            "  output_dir: /data/agent-out\n"
        )
        path = tmp_path / "policy.yaml"
        path.write_text(yaml_text, encoding="utf-8")

        cfg = policy_yaml_to_nono_config(str(path))
        assert cfg.timeout_seconds == 30
        assert cfg.readonly_paths == ["/data/user-pdf"]
        assert cfg.readwrite_paths == ["/data/agent-out"]
        assert cfg.allow_outbound is True
        assert cfg.allowed_hosts == ["pypi.org"]

    def test_policy_yaml_non_mapping_rejected(self, tmp_path):
        path = tmp_path / "bad.yaml"
        path.write_text("- just\n- a list\n", encoding="utf-8")
        with pytest.raises(ValueError, match="must be a mapping"):
            policy_yaml_to_nono_config(str(path))


class TestPolicyFieldValidation:
    def test_invalid_network_allowlist_type(self):
        policy = SimpleNamespace(network_allowlist="pypi.org")
        with pytest.raises(TypeError, match="network_allowlist must be a list"):
            nono_config_from_policy(policy)

    def test_empty_network_allowlist_entry_rejected(self):
        policy = SimpleNamespace(network_allowlist=["pypi.org", "  "])
        with pytest.raises(ValueError, match="non-empty strings"):
            nono_config_from_policy(policy)

    def test_invalid_timeout_type(self):
        policy = SimpleNamespace(
            defaults=SimpleNamespace(timeout_seconds="thirty")
        )
        with pytest.raises(TypeError, match="timeout_seconds must be a number"):
            nono_config_from_policy(policy)

    def test_nonpositive_timeout_rejected(self):
        policy = SimpleNamespace(defaults=SimpleNamespace(timeout_seconds=0))
        with pytest.raises(ValueError, match="must be positive"):
            nono_config_from_policy(policy)

    def test_invalid_mount_path_type(self):
        policy = SimpleNamespace(
            sandbox_mounts=SimpleNamespace(input_dir=123, output_dir=None)
        )
        with pytest.raises(TypeError, match="input_dir must be a string"):
            nono_config_from_policy(policy)


class TestAvailability:
    def test_top_level_export_is_always_a_class(self):
        import agent_sandbox
        from agent_sandbox import NonoSandboxProvider

        assert NonoSandboxProvider is not None
        assert isinstance(NonoSandboxProvider, type)
        assert "NonoSandboxProvider" in agent_sandbox.__all__

    def test_missing_nono_py_does_not_break_import(self, monkeypatch):
        monkeypatch.setattr(provider_mod, "_nono_module", None)
        provider = provider_mod.NonoSandboxProvider()
        assert provider.is_available() is False
        result = provider.run("agent-1", ["echo", "hi"])
        assert result.success is False
        assert "nono-py" in result.stderr or "unavailable" in result.stderr

    def test_available_when_supported(self, provider):
        assert provider.is_available() is True

    def test_unavailable_when_extension_missing(self, monkeypatch):
        monkeypatch.setattr(provider_mod, "_nono_module", None)
        p = provider_mod.NonoSandboxProvider()
        assert p.is_available() is False
        with pytest.raises(RuntimeError, match="nono unavailable"):
            p.create_session("agent-1")

    def test_unavailable_when_unsupported_host(self, monkeypatch):
        fake = _FakeNono()
        fake._supported = False
        monkeypatch.setattr(provider_mod, "_nono_module", fake)
        p = provider_mod.NonoSandboxProvider()
        assert p.is_available() is False
        with pytest.raises(RuntimeError, match="not supported"):
            p.create_session("agent-1")


# =========================================================================
# Lifecycle
# =========================================================================


class TestLifecycle:
    def test_create_execute_destroy(self, provider, fake_nono):
        fake_nono.stdout = b"hello from sandbox"
        handle = provider.create_session("agent-1")
        assert handle.status == SessionStatus.READY
        assert provider.get_session_status(
            handle.agent_id, handle.session_id
        ) == SessionStatus.READY

        execution = provider.execute_code(
            handle.agent_id, handle.session_id, "print('hi')"
        )
        assert execution.status == ExecutionStatus.COMPLETED
        assert execution.result.success is True
        assert "hello from sandbox" in execution.result.stdout
        # Command is <resolved python interpreter> <script under scripts/>.
        from pathlib import Path

        assert "python" in Path(fake_nono.last_command[0]).name.lower()
        assert fake_nono.last_command[1].endswith(".py")
        assert "scripts" in fake_nono.last_command[1]
        assert fake_nono.last_inherit_env is False

        provider.destroy_session(handle.agent_id, handle.session_id)
        assert provider.get_session_status(
            handle.agent_id, handle.session_id
        ) == SessionStatus.DESTROYED

    def test_execute_without_session_raises(self, provider):
        with pytest.raises(RuntimeError, match="No active session"):
            provider.execute_code("agent-1", "nope", "print(1)")

    def test_destroy_unknown_session_is_noop(self, provider):
        provider.destroy_session("agent-1", "missing")

    def test_invalid_agent_id_rejected(self, provider):
        with pytest.raises(ValueError, match="Invalid agent_id"):
            provider.create_session("bad id with spaces!")

    def test_nonzero_exit_is_failure(self, provider, fake_nono):
        fake_nono.exit_code = 1
        fake_nono.stderr = b"boom"
        handle = provider.create_session("agent-1")
        execution = provider.execute_code(
            handle.agent_id, handle.session_id, "print(1)"
        )
        assert execution.status == ExecutionStatus.FAILED
        assert execution.result.success is False
        assert "boom" in execution.result.stderr

    def test_run_once_executes_and_cleans_up(self, provider, fake_nono):
        fake_nono.stdout = b"one-shot output"
        execution = provider.run_once("agent-1", "print('hi')")
        assert execution.status == ExecutionStatus.COMPLETED
        assert "one-shot output" in execution.result.stdout
        assert provider._sessions == {}

    def test_run_once_cleans_up_on_failure(self, provider, fake_nono):
        fake_nono.exit_code = 2
        execution = provider.run_once("agent-1", "print('hi')")
        assert execution.result.success is False
        assert provider._sessions == {}

    def test_run_once_destroys_session_on_guard_violation(
        self, provider, fake_nono
    ):
        with pytest.raises(SandboxCodeViolation):
            provider.run_once(
                "agent-1", "import subprocess; subprocess.run(['ls'])"
            )
        assert provider._sessions == {}


# =========================================================================
# Capability + env wiring
# =========================================================================


class TestCapabilityWiring:
    def test_session_paths_granted(self, provider, fake_nono):
        handle = provider.create_session("agent-1")
        provider.execute_code(handle.agent_id, handle.session_id, "print(1)")
        caps = fake_nono.last_caps
        # scripts dir read-only, output dir read-write.
        ro = [p for p, m in caps.paths if m == "READ"]
        rw = [p for p, m in caps.paths if m == "READ_WRITE"]
        assert any(p.endswith("scripts") for p in ro)
        assert any(p.endswith("output") for p in rw)

    def test_network_blocked_by_default(self, provider, fake_nono):
        handle = provider.create_session("agent-1")
        provider.execute_code(handle.agent_id, handle.session_id, "print(1)")
        assert fake_nono.last_caps.network_blocked is True
        assert fake_nono.last_caps.proxy is None
        assert fake_nono.proxies == []

    def test_proxy_started_for_egress(self, provider, fake_nono):
        policy = _policy(network_allowlist=["pypi.org"])
        handle = provider.create_session("agent-1", policy=policy)
        provider.execute_code(handle.agent_id, handle.session_id, "print(1)")
        # A proxy was started with the allowlist and bound to the caps.
        assert len(fake_nono.proxies) == 1
        assert fake_nono.proxies[0].config.allowed_hosts == ["pypi.org"]
        assert fake_nono.last_caps.proxy is fake_nono.proxies[0]
        assert fake_nono.last_caps.network_blocked is False
        # Proxy env vars are injected into the child environment.
        assert ("HTTP_PROXY", "http://127.0.0.1:9999") in fake_nono.last_env

    def test_unrestricted_egress_uses_allow_all_hosts(self, provider, fake_nono):
        policy = _policy(network_default="allow")
        handle = provider.create_session("agent-1", policy=policy)
        provider.execute_code(handle.agent_id, handle.session_id, "print(1)")
        assert fake_nono.proxies[0].config.allow_all_hosts is True

    def test_proxy_shut_down_on_destroy(self, provider, fake_nono):
        policy = _policy(network_allowlist=["pypi.org"])
        handle = provider.create_session("agent-1", policy=policy)
        proxy = fake_nono.proxies[0]
        provider.destroy_session(handle.agent_id, handle.session_id)
        assert proxy.shutdown_called is True

    def test_env_not_inherited_and_context_injected(self, provider, fake_nono):
        handle = provider.create_session("agent-1")
        provider.execute_code(
            handle.agent_id,
            handle.session_id,
            "print(1)",
            context={"task": "demo"},
        )
        assert fake_nono.last_inherit_env is False
        env = dict(fake_nono.last_env)
        assert "NONO_CONTEXT" in env
        assert "demo" in env["NONO_CONTEXT"]

    def test_cwd_is_output_dir(self, provider, fake_nono):
        handle = provider.create_session("agent-1")
        provider.execute_code(handle.agent_id, handle.session_id, "print(1)")
        assert fake_nono.last_cwd.endswith("output")


# =========================================================================
# Spawn behaviour
# =========================================================================


class TestSpawn:
    def test_timeout_marks_killed(self, provider, fake_nono):
        fake_nono.exit_code = 124  # nono timeout convention
        handle = provider.create_session("agent-1")
        execution = provider.execute_code(
            handle.agent_id, handle.session_id, "print(1)"
        )
        assert execution.result.killed is True
        assert execution.result.success is False
        assert "timeout" in execution.result.kill_reason.lower()

    def test_sandboxed_exec_failure_surfaces(self, provider, fake_nono):
        fake_nono.raise_exc = RuntimeError("fork failed")
        handle = provider.create_session("agent-1")
        execution = provider.execute_code(
            handle.agent_id, handle.session_id, "print(1)"
        )
        assert execution.result.success is False
        assert "fork failed" in execution.result.stderr

    def test_output_truncated(self, provider, fake_nono):
        fake_nono.stdout = b"x" * 2_000_000
        handle = provider.create_session("agent-1")
        execution = provider.execute_code(
            handle.agent_id, handle.session_id, "print(1)"
        )
        assert "truncated" in execution.result.stdout

    def test_timeout_passed_through(self, provider, fake_nono):
        handle = provider.create_session(
            "agent-1", config=SandboxConfig(timeout_seconds=12)
        )
        provider.execute_code(handle.agent_id, handle.session_id, "print(1)")
        assert fake_nono.last_timeout == 12


# =========================================================================
# Raw run
# =========================================================================


class TestRawRun:
    def test_run_with_session(self, provider, fake_nono):
        fake_nono.stdout = b"ran"
        handle = provider.create_session("agent-1")
        result = provider.run(
            handle.agent_id, ["echo", "hi"], session_id=handle.session_id
        )
        assert result.success is True
        assert "ran" in result.stdout
        # The program is resolved to an absolute path; args are preserved.
        from pathlib import Path

        assert Path(fake_nono.last_command[0]).name == "echo"
        assert fake_nono.last_command[1:] == ["hi"]

    def test_run_ephemeral_without_session(self, provider, fake_nono):
        fake_nono.stdout = b"oneshot"
        result = provider.run("agent-1", ["echo", "hi"])
        assert result.success is True

    def test_run_empty_command(self, provider):
        result = provider.run("agent-1", [])
        assert result.success is False

    def test_run_unavailable_provider(self, monkeypatch):
        monkeypatch.setattr(provider_mod, "_nono_module", None)
        p = provider_mod.NonoSandboxProvider()
        result = p.run("agent-1", ["echo", "hi"])
        assert result.success is False
        assert "nono-py" in result.stderr


# =========================================================================
# Guards
# =========================================================================


class TestGuards:
    def test_code_scanner_blocks_subprocess(self, provider, fake_nono):
        handle = provider.create_session("agent-1")
        with pytest.raises(SandboxCodeViolation):
            provider.execute_code(
                handle.agent_id,
                handle.session_id,
                "import subprocess; subprocess.run(['ls'])",
            )

    def test_policy_deny_blocks_execution(self, provider, fake_nono):
        class _DenyEvaluator:
            def evaluate(self, ctx):
                return SimpleNamespace(allowed=False, reason="nope")

        handle = provider.create_session("agent-1")
        key = (handle.agent_id, handle.session_id)
        provider._sessions[key].evaluator = _DenyEvaluator()
        with pytest.raises(PermissionError, match="Policy denied"):
            provider.execute_code(handle.agent_id, handle.session_id, "print(1)")

    def test_tool_allowlist_fails_closed(self, provider, fake_nono):
        policy = _policy(tool_allowlist=["read_doc"])
        with pytest.raises(ValueError, match="tool allowlisting"):
            provider.create_session("agent-1", policy=policy)

    def test_empty_tool_allowlist_is_allowed(self, provider, fake_nono):
        policy = _policy(tool_allowlist=[])
        handle = provider.create_session("agent-1", policy=policy)
        assert handle.status == SessionStatus.READY

    def test_non_python_interpreter_fails_closed(self, monkeypatch, fake_nono):
        p = provider_mod.NonoSandboxProvider(interpreter="node")
        handle = p.create_session("agent-1")
        with pytest.raises(ValueError, match="only supports a Python"):
            p.execute_code(handle.agent_id, handle.session_id, "print(1)")

    def test_absolute_python_interpreter_path_allowed(self, monkeypatch, fake_nono):
        p = provider_mod.NonoSandboxProvider(interpreter="/usr/bin/python3")
        handle = p.create_session("agent-1")
        execution = p.execute_code(handle.agent_id, handle.session_id, "print(1)")
        assert execution.result.success is True
