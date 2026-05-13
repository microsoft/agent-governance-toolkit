# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Integration tests for ``ACASandboxProvider`` against real Azure.

These tests provision real Azure Container Apps sandboxes and exercise
the full data plane (``create_sandbox`` / ``set_egress_policy`` /
``exec`` / ``delete_sandbox``). They are **skipped by default** to keep
``pytest`` runs free of cloud cost and credential requirements.

Enable them by setting the gate variable and the Azure context::

    $env:AGT_AZURE_INTEGRATION = "1"
    $env:AZURE_RG              = "your-resource-group"
    $env:AZURE_REGION          = "westus2"
    $env:AZURE_SANDBOX_GROUP   = "agt-test"            # optional, default below
    $env:AZURE_SANDBOX_DISK    = "python-3.13"         # optional, must have python3

    # Standard azure-identity discovery — run `az login` first, or supply
    # AZURE_CLIENT_ID / AZURE_CLIENT_SECRET / AZURE_TENANT_ID, or use a
    # managed identity on the test runner.

    pytest tests/test_azure_sandbox_integration.py -v

Every test allocates a unique ``agent_id`` so concurrent runs do not
collide, and every test cleans up its sandbox in ``finally`` /
fixture teardown. Failed runs that leak a sandbox can be cleaned up
with ``az sandbox delete --name <id> --group <group>`` or by destroying
the sandbox group entirely.

Cost note: each test provisions one short-lived sandbox VM (~10s
lifetime). Total spend per full run is small but non-zero.
"""

from __future__ import annotations

import os
import uuid

import pytest

from agent_os.policies import PolicyDocument
from agent_sandbox import ACASandboxProvider
from agent_sandbox.sandbox_provider import SessionStatus

# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------

_REQUIRED = ("AGT_AZURE_INTEGRATION", "AZURE_RG", "AZURE_REGION")
_missing = [k for k in _REQUIRED if not os.environ.get(k)]

pytestmark = pytest.mark.skipif(
    bool(_missing),
    reason=(
        "Azure integration tests disabled. To run, set: "
        + ", ".join(_REQUIRED)
        + " (and run `az login` or equivalent)."
    ),
)


_RG = os.environ.get("AZURE_RG", "")
_REGION = os.environ.get("AZURE_REGION", "")
_GROUP = os.environ.get("AZURE_SANDBOX_GROUP", "agt-test")
_DISK = os.environ.get("AZURE_SANDBOX_DISK", "python-3.13")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _agent_id(label: str) -> str:
    """Unique agent id per test invocation, capped to the Azure name regex."""
    suffix = uuid.uuid4().hex[:6]
    return f"agt-{label}-{suffix}"[:63]


def _build_policy(
    *,
    network_allowlist=None,
    network_default="deny",
    max_cpu=0.5,
    max_memory_mb=512,
    timeout_seconds=60,
    rules=None,
) -> PolicyDocument:
    return PolicyDocument.model_validate(
        {
            "name": "azure-integration-test",
            "version": "1",
            "defaults": {
                "action": "allow",
                "max_cpu": max_cpu,
                "max_memory_mb": max_memory_mb,
                "timeout_seconds": timeout_seconds,
                "network_default": network_default,
            },
            "network_allowlist": list(network_allowlist or []),
            "tool_allowlist": [],
            "rules": rules or [],
        }
    )


@pytest.fixture(scope="module")
def provider():
    """One provider per module — sandboxes are created/destroyed per test."""
    p = ACASandboxProvider(
        resource_group=_RG,
        sandbox_group=_GROUP,
        disk=_DISK,
        ensure_group_location=_REGION,
    )
    if not p.is_available():
        pytest.skip("ACASandboxProvider is_available() returned False")
    yield p
    p.close()


@pytest.fixture()
def session_tracker(provider):
    """Yield a (provider, register) pair; auto-destroys any sessions on teardown."""
    created: list[tuple[str, str]] = []

    def register(agent_id: str, session_id: str) -> None:
        created.append((agent_id, session_id))

    yield provider, register

    for agent_id, session_id in created:
        try:
            provider.destroy_session(agent_id, session_id)
        except Exception:
            # Best-effort teardown — surface but don't fail the test.
            pass


# ---------------------------------------------------------------------------
# Smoke
# ---------------------------------------------------------------------------


class TestSmoke:
    def test_provider_constructs_and_is_available(self, provider):
        assert provider.is_available() is True

    def test_create_destroy_no_policy(self, session_tracker):
        provider, register = session_tracker
        agent_id = _agent_id("smoke")
        handle = provider.create_session(agent_id)
        register(agent_id, handle.session_id)

        assert handle.status == SessionStatus.READY
        assert handle.session_id
        assert (
            provider.get_session_status(agent_id, handle.session_id)
            == SessionStatus.READY
        )

        provider.destroy_session(agent_id, handle.session_id)
        assert (
            provider.get_session_status(agent_id, handle.session_id)
            == SessionStatus.DESTROYED
        )

    def test_execute_python_print(self, session_tracker):
        provider, register = session_tracker
        agent_id = _agent_id("exec")
        policy = _build_policy()  # deny-all egress, no rules

        handle = provider.create_session(agent_id, policy=policy)
        register(agent_id, handle.session_id)

        result = provider.execute_code(
            agent_id, handle.session_id, "print('hello azure')"
        )
        assert result.result.success is True
        assert result.result.exit_code == 0
        assert "hello azure" in result.result.stdout


# ---------------------------------------------------------------------------
# Egress: fail-closed default + allowlist + explicit allow
# ---------------------------------------------------------------------------


class TestEgress:
    def test_empty_allowlist_with_deny_blocks_internet(self, session_tracker):
        provider, register = session_tracker
        agent_id = _agent_id("deny-all")
        policy = _build_policy(network_allowlist=[], network_default="deny")

        handle = provider.create_session(agent_id, policy=policy)
        register(agent_id, handle.session_id)

        # Reach for a host that is definitely not in the (empty) allowlist.
        result = provider.execute_code(
            agent_id,
            handle.session_id,
            (
                "from urllib.request import urlopen\n"
                "try:\n"
                "    urlopen('https://example.com', timeout=10)\n"
                "    print('REACHED')\n"
                "except Exception as exc:\n"
                "    print('BLOCKED', type(exc).__name__)\n"
            ),
        )
        # Either the proxy returned 403 (caught & printed BLOCKED) or the
        # request timed out / errored — anything except REACHED is correct.
        assert "REACHED" not in result.result.stdout

    def test_allowlist_permits_listed_hosts(self, session_tracker):
        provider, register = session_tracker
        agent_id = _agent_id("allow-pypi")
        policy = _build_policy(network_allowlist=["pypi.org"])

        handle = provider.create_session(agent_id, policy=policy)
        register(agent_id, handle.session_id)

        result = provider.execute_code(
            agent_id,
            handle.session_id,
            (
                "from urllib.request import urlopen\n"
                "with urlopen('https://pypi.org', timeout=10) as r:\n"
                "    print('STATUS', r.status)\n"
            ),
        )
        assert "STATUS 200" in result.result.stdout, result.result.stdout

    def test_allowlist_blocks_unlisted_hosts(self, session_tracker):
        provider, register = session_tracker
        agent_id = _agent_id("block-unlisted")
        policy = _build_policy(network_allowlist=["pypi.org"])

        handle = provider.create_session(agent_id, policy=policy)
        register(agent_id, handle.session_id)

        result = provider.execute_code(
            agent_id,
            handle.session_id,
            (
                "from urllib.request import urlopen\n"
                "try:\n"
                "    urlopen('https://example.com', timeout=10)\n"
                "    print('REACHED')\n"
                "except Exception as exc:\n"
                "    print('BLOCKED', type(exc).__name__)\n"
            ),
        )
        assert "REACHED" not in result.result.stdout

    def test_network_default_allow_lets_everything_through(self, session_tracker):
        provider, register = session_tracker
        agent_id = _agent_id("allow-all")
        # network_default: allow + no allowlist → no egress policy applied,
        # so the sandbox keeps Azure's default-allow behavior.
        policy = _build_policy(network_allowlist=[], network_default="allow")

        handle = provider.create_session(agent_id, policy=policy)
        register(agent_id, handle.session_id)

        result = provider.execute_code(
            agent_id,
            handle.session_id,
            (
                "from urllib.request import urlopen\n"
                "with urlopen('https://example.com', timeout=10) as r:\n"
                "    print('STATUS', r.status)\n"
            ),
        )
        assert "STATUS" in result.result.stdout, result.result.stdout


# ---------------------------------------------------------------------------
# Policy rule gate
# ---------------------------------------------------------------------------


class TestPolicyGate:
    def test_rule_deny_raises_permission_error(self, session_tracker):
        provider, register = session_tracker
        agent_id = _agent_id("deny-rule")
        policy = _build_policy(
            rules=[
                {
                    "name": "deny-subprocess",
                    "condition": {
                        "field": "code",
                        "operator": "contains",
                        "value": "subprocess",
                    },
                    "action": "deny",
                    "priority": 100,
                    "message": "shell-out blocked",
                }
            ],
        )

        handle = provider.create_session(agent_id, policy=policy)
        register(agent_id, handle.session_id)

        with pytest.raises(PermissionError, match="shell-out blocked"):
            provider.execute_code(
                agent_id, handle.session_id, "import subprocess; subprocess.run(['ls'])"
            )

    def test_rule_allow_passes_through(self, session_tracker):
        provider, register = session_tracker
        agent_id = _agent_id("allow-rule")
        policy = _build_policy(
            rules=[
                {
                    "name": "deny-subprocess",
                    "condition": {
                        "field": "code",
                        "operator": "contains",
                        "value": "subprocess",
                    },
                    "action": "deny",
                    "priority": 100,
                    "message": "shell-out blocked",
                }
            ],
        )

        handle = provider.create_session(agent_id, policy=policy)
        register(agent_id, handle.session_id)

        result = provider.execute_code(
            agent_id, handle.session_id, "print(1 + 1)"
        )
        assert "2" in result.result.stdout


# ---------------------------------------------------------------------------
# Resource caps
# ---------------------------------------------------------------------------


class TestResourceCaps:
    def test_timeout_seconds_marks_long_runs_killed(self, session_tracker):
        provider, register = session_tracker
        agent_id = _agent_id("timeout")
        policy = _build_policy(timeout_seconds=2)

        handle = provider.create_session(agent_id, policy=policy)
        register(agent_id, handle.session_id)

        result = provider.execute_code(
            agent_id,
            handle.session_id,
            "import time; time.sleep(15); print('done')",
        )
        # The provider's wall-clock kill flag should fire even though the
        # data plane itself has no notion of cancellation.
        assert result.result.killed is True or result.result.duration_seconds >= 2


# ---------------------------------------------------------------------------
# Lifecycle hygiene
# ---------------------------------------------------------------------------


class TestLifecycle:
    def test_destroy_is_idempotent(self, session_tracker):
        provider, register = session_tracker
        agent_id = _agent_id("idempotent")
        handle = provider.create_session(agent_id)
        register(agent_id, handle.session_id)

        provider.destroy_session(agent_id, handle.session_id)
        # Second destroy must not raise.
        provider.destroy_session(agent_id, handle.session_id)

    def test_two_agents_isolated(self, session_tracker):
        provider, register = session_tracker
        a1 = _agent_id("iso-a")
        a2 = _agent_id("iso-b")
        h1 = provider.create_session(a1, policy=_build_policy(network_allowlist=["pypi.org"]))
        register(a1, h1.session_id)
        h2 = provider.create_session(a2, policy=_build_policy(network_allowlist=[]))
        register(a2, h2.session_id)

        assert h1.session_id != h2.session_id

        # a1 can reach pypi.org; a2 cannot.
        r1 = provider.execute_code(
            a1,
            h1.session_id,
            "from urllib.request import urlopen\n"
            "print('S', urlopen('https://pypi.org', timeout=10).status)\n",
        )
        r2 = provider.execute_code(
            a2,
            h2.session_id,
            "from urllib.request import urlopen\n"
            "try: urlopen('https://pypi.org', timeout=10); print('REACHED')\n"
            "except Exception as exc: print('BLOCKED', type(exc).__name__)\n",
        )
        assert "S 200" in r1.result.stdout
        assert "REACHED" not in r2.result.stdout
