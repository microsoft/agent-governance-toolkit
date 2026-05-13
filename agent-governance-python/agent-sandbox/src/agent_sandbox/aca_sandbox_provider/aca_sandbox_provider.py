# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Azure-backed sandbox provider implementing the ``SandboxProvider`` ABC.

Each agent session maps to an Azure Container Apps **sandbox** inside a
**sandbox group**.  The control plane (sandbox-group lifecycle) is handled
by ``azure-mgmt-sandbox``; the data plane (sandbox CRUD, exec, files,
egress policy) by ``azure-sandbox``.

Policy is loaded at session creation time:

* ``defaults.max_memory_mb`` / ``defaults.max_cpu`` → sandbox CPU and memory.
* ``network_allowlist`` → sandbox egress policy (defaultAction=Deny + per-host
  Allow rules).
* ``tool_allowlist`` is host-side only and is enforced through the
  ``PolicyEvaluator`` gate on every ``execute_code`` call.

Example::

    from agent_sandbox import ACASandboxProvider

    provider = ACASandboxProvider(
        resource_group="my-rg",
        sandbox_group="agents",
    )
    handle = provider.create_session("agent-1")
    exec_handle = provider.execute_code(
        "agent-1", handle.session_id, "print('hello azure')"
    )
    print(exec_handle.result.stdout)
    provider.destroy_session("agent-1", handle.session_id)
"""

from __future__ import annotations

import base64
import logging
import re
import threading
import time
import uuid
from typing import TYPE_CHECKING, Any

from agent_sandbox.sandbox_provider import (
    ExecutionHandle,
    ExecutionStatus,
    SandboxConfig,
    SandboxProvider,
    SandboxResult,
    SessionHandle,
    SessionStatus,
)

if TYPE_CHECKING:
    from azure.core.credentials import TokenCredential

logger = logging.getLogger(__name__)


# Sandbox-group / sandbox names are interpolated into ARM and data-plane
# URLs.  Constrain to characters that are safe in those paths and reject
# anything else up front so callers never produce a malformed request.
_AZURE_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$")


def _validate_resource_name(value: str, label: str) -> None:
    if not isinstance(value, str) or not _AZURE_NAME_RE.match(value):
        raise ValueError(
            f"Invalid {label} '{value}': must match "
            r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}"
        )


def aca_config_from_policy(
    policy: Any, base: SandboxConfig
) -> SandboxConfig:
    """Project policy fields onto a :class:`SandboxConfig`.

    Mirrors :func:`agent_sandbox.docker_sandbox_provider.docker_config_from_policy`
    but only consumes the fields that map onto Azure sandbox primitives:
    CPU/memory defaults, the network allowlist, and ``env_vars``.
    """
    cfg = SandboxConfig(
        timeout_seconds=base.timeout_seconds,
        memory_mb=base.memory_mb,
        cpu_limit=base.cpu_limit,
        network_enabled=base.network_enabled,
        read_only_fs=base.read_only_fs,
        env_vars=dict(base.env_vars),
        input_dir=base.input_dir,
        output_dir=base.output_dir,
        runtime=base.runtime,
    )

    defaults = getattr(policy, "defaults", None)
    if defaults is not None:
        if hasattr(defaults, "max_memory_mb") and defaults.max_memory_mb:
            cfg.memory_mb = defaults.max_memory_mb
        if hasattr(defaults, "max_cpu") and defaults.max_cpu:
            cfg.cpu_limit = defaults.max_cpu
        if hasattr(defaults, "timeout_seconds") and defaults.timeout_seconds:
            cfg.timeout_seconds = defaults.timeout_seconds

    if getattr(policy, "network_allowlist", None):
        cfg.network_enabled = True

    return cfg


def _network_allowlist(policy: Any) -> list[str]:
    """Return the policy's network allowlist as a list of host patterns."""
    allow = getattr(policy, "network_allowlist", None) or []
    # Accept list[str] or list[obj-with-host]
    out: list[str] = []
    for entry in allow:
        if isinstance(entry, str):
            out.append(entry)
        else:
            host = getattr(entry, "host", None) or getattr(entry, "pattern", None)
            if host:
                out.append(host)
    return out


def _network_default(policy: Any) -> str:
    """Return the policy's sandbox egress default ('allow' or 'deny').

    Reads ``policy.defaults.network_default``. **Falls back to 'deny'**
    (fail-closed) whenever a policy is supplied but the field is missing
    or unrecognized. The only way to get a default-allow sandbox is to
    explicitly set ``defaults.network_default: allow`` in the policy.
    """
    defaults = getattr(policy, "defaults", None)
    value = getattr(defaults, "network_default", None) if defaults else None
    if isinstance(value, str) and value.lower() in ("allow", "deny"):
        return value.lower()
    return "deny"


class ACASandboxProvider(SandboxProvider):
    """``SandboxProvider`` backed by Azure Container Apps sandboxes.

    .. note::
       The ``resource_group`` **must already exist** in the target
       subscription. This provider does not create or manage resource
       groups — create one out-of-band first (e.g.
       ``az group create -n my-rg -l westus2``) and pass its name here.
       Calling :meth:`create_session` against a non-existent resource
       group surfaces the Azure 404 as a ``RuntimeError`` wrapping the
       upstream ``ResourceGroupNotFound`` error.

       Sandbox groups (the sub-resource inside the RG) *can* be
       auto-created — see ``ensure_group_location`` below.

    Parameters
    ----------
    resource_group:
        Default resource group containing the sandbox group.  Must
        already exist; see the note above.
    sandbox_group:
        Sandbox group that holds per-agent sandboxes.  Must already exist
        unless ``ensure_group_location`` is set, in which case the
        provider creates it on first use via ``azure-mgmt-sandbox``.
    subscription_id:
        Azure subscription ID.  Auto-detected from
        ``AZURE_SUBSCRIPTION_ID`` (or ``az account show``) when omitted.
    credential:
        ``azure-identity`` credential.  Defaults to ``DefaultAzureCredential``.
    disk:
        Public disk image name to provision sandboxes from
        (default ``"ubuntu"``).
    ensure_group_location:
        If set, the sandbox group will be created in this Azure region
        when it does not already exist.  The enclosing
        ``resource_group`` is **not** created — it must pre-exist.
    """

    def __init__(
        self,
        resource_group: str,
        sandbox_group: str,
        *,
        subscription_id: str | None = None,
        credential: "TokenCredential | None" = None,
        disk: str = "ubuntu",
        ensure_group_location: str | None = None,
    ) -> None:
        _validate_resource_name(sandbox_group, "sandbox_group")

        self._resource_group = resource_group
        self._sandbox_group = sandbox_group
        self._disk = disk
        self._ensure_group_location = ensure_group_location

        self._state_lock = threading.RLock()
        self._sandboxes: dict[tuple[str, str], str] = {}
        self._evaluators: dict[tuple[str, str], Any] = {}
        self._session_configs: dict[tuple[str, str], SandboxConfig] = {}

        self._available = False
        self._data_client: Any = None
        self._mgmt_client: Any = None

        try:
            from azure.sandbox import SandboxClient

            self._data_client = SandboxClient(
                resource_group=resource_group,
                subscription_id=subscription_id,
                credential=credential,
            )
        except ImportError:
            logger.warning(
                "azure-sandbox is not installed — "
                "ACASandboxProvider is unavailable"
            )
            return
        except Exception as exc:
            logger.warning("Failed to construct SandboxClient: %s", exc)
            return

        if ensure_group_location:
            try:
                from azure.mgmt.sandbox import SandboxGroupManagementClient

                self._mgmt_client = SandboxGroupManagementClient(
                    resource_group=resource_group,
                    subscription_id=subscription_id,
                    credential=credential,
                )
            except ImportError:
                logger.warning(
                    "azure-mgmt-sandbox is not installed — "
                    "ensure_group_location ignored"
                )
            except Exception as exc:
                logger.warning(
                    "Failed to construct SandboxGroupManagementClient: %s", exc
                )

        self._available = True

    # ------------------------------------------------------------------
    # Group bootstrap
    # ------------------------------------------------------------------

    def _ensure_sandbox_group(self) -> None:
        if self._mgmt_client is None or self._ensure_group_location is None:
            return
        try:
            self._mgmt_client.get_group(
                self._sandbox_group, resource_group=self._resource_group
            )
            return
        except Exception:
            pass
        logger.info(
            "Creating sandbox group '%s' in '%s'",
            self._sandbox_group,
            self._ensure_group_location,
        )
        self._mgmt_client.create_group(
            self._sandbox_group,
            location=self._ensure_group_location,
            resource_group=self._resource_group,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _cpu_millicores(cpu_limit: float) -> str:
        millicores = max(100, int(round(cpu_limit * 1000)))
        return f"{millicores}m"

    @staticmethod
    def _memory_mib(memory_mb: int) -> str:
        return f"{max(128, int(memory_mb))}Mi"

    def _apply_egress_policy(
        self,
        sandbox_id: str,
        hosts: list[str],
        network_default: str = "deny",
    ) -> None:
        """Translate a network allowlist into an Azure egress policy.

        ``network_default`` controls the proxy's ``defaultAction``:

        * ``"deny"`` (fail-closed, recommended): the proxy denies any host
          not in ``hosts``. This is applied **even when ``hosts`` is empty**,
          which yields a sandbox with no outbound network access at all.
        * ``"allow"``: the proxy allows everything; ``hosts`` is ignored
          (no API call is made). Only suitable for trusted dev/research
          workloads where the policy's rule engine is the only gate.
        """
        if network_default == "allow":
            # Explicit opt-out — leave Azure's default-allow behavior.
            return
        # network_default == "deny" → fail-closed, always set the policy
        # (even with an empty hosts list, which produces a deny-all sandbox).
        policy = {
            "defaultAction": "Deny",
            "hostRules": [
                {"pattern": h, "action": "Allow"} for h in hosts
            ],
        }
        try:
            self._data_client.set_egress_policy(
                sandbox_id, self._sandbox_group, policy,
                resource_group=self._resource_group,
            )
        except Exception as exc:
            logger.warning(
                "Failed to apply egress policy on sandbox '%s': %s",
                sandbox_id, exc,
            )

    # ------------------------------------------------------------------
    # SandboxProvider interface
    # ------------------------------------------------------------------

    def create_session(
        self,
        agent_id: str,
        policy: Any | None = None,
        config: SandboxConfig | None = None,
    ) -> SessionHandle:
        if not self._available:
            raise RuntimeError("ACASandboxProvider is not available")

        _validate_resource_name(agent_id, "agent_id")

        cfg = config or SandboxConfig()
        evaluator = None
        allow_hosts: list[str] = []
        net_default = "deny"  # fail-closed when no policy is supplied
        policy_provided = policy is not None

        if policy is not None:
            cfg = aca_config_from_policy(policy, cfg)
            allow_hosts = _network_allowlist(policy)
            net_default = _network_default(policy)
            try:
                from agent_os.policies.evaluator import PolicyEvaluator

                evaluator = PolicyEvaluator(policies=[policy])
            except ImportError:
                logger.warning(
                    "agent-os-kernel not installed — "
                    "policy evaluation unavailable, session runs ungated"
                )
            except Exception as exc:
                raise RuntimeError(
                    f"Failed to initialize PolicyEvaluator: {exc}"
                ) from exc

        # Make sure the sandbox group exists (no-op unless requested).
        self._ensure_sandbox_group()

        # Provision the sandbox.
        try:
            sbx = self._data_client.create_sandbox(
                self._sandbox_group,
                disk=self._disk,
                cpu=self._cpu_millicores(cfg.cpu_limit),
                memory=self._memory_mib(cfg.memory_mb),
                environment=cfg.env_vars or None,
                resource_group=self._resource_group,
            )
        except Exception as exc:
            raise RuntimeError(
                f"Failed to create Azure sandbox for agent '{agent_id}': {exc}"
            ) from exc

        sandbox_id = sbx.get("id") or sbx.get("name")
        if not sandbox_id:
            raise RuntimeError(
                f"Azure sandbox response missing 'id': {sbx!r}"
            )

        # Apply egress policy. We do this whenever a policy is supplied —
        # the default `network_default="deny"` makes the sandbox
        # fail-closed even if `network_allowlist` is empty. Callers that
        # genuinely want a default-allow sandbox must set
        # `defaults.network_default: allow` in the policy.
        if policy_provided:
            self._apply_egress_policy(sandbox_id, allow_hosts, net_default)

        session_id = sandbox_id
        key = (agent_id, session_id)
        with self._state_lock:
            self._sandboxes[key] = sandbox_id
            self._session_configs[key] = cfg
            if evaluator is not None:
                self._evaluators[key] = evaluator

        return SessionHandle(
            agent_id=agent_id,
            session_id=session_id,
            status=SessionStatus.READY,
        )

    def execute_code(
        self,
        agent_id: str,
        session_id: str,
        code: str,
        *,
        context: dict[str, Any] | None = None,
    ) -> ExecutionHandle:
        key = (agent_id, session_id)
        with self._state_lock:
            sandbox_id = self._sandboxes.get(key)
            evaluator = self._evaluators.get(key)
            session_cfg = self._session_configs.get(key) or SandboxConfig()

        if sandbox_id is None:
            raise RuntimeError(
                f"No active session for agent '{agent_id}' with "
                f"session_id '{session_id}'. Call create_session() first."
            )

        if evaluator is not None:
            eval_ctx: dict[str, Any] = {
                "agent_id": agent_id,
                "action": "execute",
                "code": code,
            }
            if context:
                eval_ctx.update(context)
            decision = evaluator.evaluate(eval_ctx)
            if not decision.allowed:
                raise PermissionError(f"Policy denied: {decision.reason}")

        # Run the code over the data-plane exec endpoint.  We base64-encode
        # the source so the body is opaque to the host shell and any code,
        # including multi-line scripts and quotes, runs unmodified.
        encoded = base64.b64encode(code.encode("utf-8")).decode("ascii")
        command = (
            f"echo {encoded} | base64 -d | python3"
        )

        start = time.monotonic()
        try:
            resp = self._data_client.exec(
                sandbox_id,
                self._sandbox_group,
                command,
                resource_group=self._resource_group,
            )
        except Exception as exc:
            duration = time.monotonic() - start
            return ExecutionHandle(
                execution_id=uuid.uuid4().hex[:8],
                agent_id=agent_id,
                session_id=session_id,
                status=ExecutionStatus.FAILED,
                result=SandboxResult(
                    success=False,
                    exit_code=-1,
                    stderr=str(exc),
                    duration_seconds=round(duration, 3),
                ),
            )

        duration = time.monotonic() - start
        exit_code = int(resp.get("exitCode", -1))
        stdout = (resp.get("stdout") or "")[:10000]
        stderr = (resp.get("stderr") or "")[:10000]
        result = SandboxResult(
            success=exit_code == 0,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=round(duration, 3),
        )
        status = (
            ExecutionStatus.COMPLETED if result.success else ExecutionStatus.FAILED
        )
        # Honor the session's configured timeout: surface a kill if exceeded.
        if (
            session_cfg.timeout_seconds
            and result.duration_seconds > session_cfg.timeout_seconds
        ):
            result.killed = True
            result.kill_reason = (
                f"Execution exceeded timeout of {session_cfg.timeout_seconds}s"
            )

        return ExecutionHandle(
            execution_id=uuid.uuid4().hex[:8],
            agent_id=agent_id,
            session_id=session_id,
            status=status,
            result=result,
        )

    def destroy_session(self, agent_id: str, session_id: str) -> None:
        key = (agent_id, session_id)
        with self._state_lock:
            sandbox_id = self._sandboxes.pop(key, None)
            self._evaluators.pop(key, None)
            self._session_configs.pop(key, None)

        if sandbox_id is None:
            return

        try:
            self._data_client.delete_sandbox(
                sandbox_id,
                self._sandbox_group,
                resource_group=self._resource_group,
            )
        except Exception as exc:
            logger.warning(
                "Failed to delete Azure sandbox '%s' for agent '%s': %s",
                sandbox_id, agent_id, exc,
            )

    def is_available(self) -> bool:
        return self._available

    def get_session_status(
        self, agent_id: str, session_id: str
    ) -> SessionStatus:
        with self._state_lock:
            if (agent_id, session_id) in self._sandboxes:
                return SessionStatus.READY
        return SessionStatus.DESTROYED

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Release HTTP client resources."""
        for client in (self._data_client, self._mgmt_client):
            close = getattr(client, "close", None)
            if callable(close):
                try:
                    close()
                except Exception as exc:
                    # Teardown is best-effort: a failure here must not mask
                    # the original error (or a normal exit). Log at debug
                    # so operators can still diagnose if needed.
                    logger.debug(
                        "Ignoring error while closing client %s: %s",
                        type(client).__name__,
                        exc,
                    )

    def __enter__(self) -> "ACASandboxProvider":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
