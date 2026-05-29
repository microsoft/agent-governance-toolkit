# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Azure-backed sandbox provider implementing the ``SandboxProvider`` ABC.

Each agent session maps to an Azure Container Apps **sandbox** inside a
**sandbox group**. The provider drives the early-access
``azure-containerapps-sandbox`` Python SDK (verified against
``0.1.0b1``):

* :class:`azure.containerapps.sandbox.SandboxGroupClient` — data plane,
  scoped to one ``(resource_group, sandbox_group)`` pair. Used to create,
  list, and delete sandboxes inside the group.
* :class:`azure.containerapps.sandbox.SandboxClient` — per-sandbox client
  returned by ``SandboxGroupClient.begin_create_sandbox(...).result()``.
  Carries ``exec``, ``set_egress_policy``, ``delete``, ``get`` and the
  other per-sandbox operations.
* :class:`azure.containerapps.sandbox.SandboxGroupManagementClient` —
  control plane (ARM), used only when ``ensure_group_location`` is set
  so the provider can create the sandbox group on first use.

Region selection follows the SDK's ``endpoint_for_region(region)``
helper — supply ``region=`` (or set the ``AZURE_SANDBOX_REGION`` env
var) so the data-plane client knows which regional endpoint to hit.

Policy is loaded at session creation time:

* ``defaults.max_memory_mb`` / ``defaults.max_cpu`` →
  :class:`SandboxConfig` caps used for host-side timeout enforcement and
  forwarded to ``begin_create_sandbox`` as ``cpu`` / ``memory`` kwargs
  when the SDK accepts them.
* ``network_allowlist`` → sandbox egress policy
  (``defaultAction=Deny`` + per-host ``Allow`` rules) applied via
  :meth:`SandboxClient.set_egress_policy`.
* ``tool_allowlist`` is host-side only and is enforced through the
  ``PolicyEvaluator`` gate on every :meth:`execute_code` call.

Example::

    from agent_sandbox import ACASandboxProvider

    provider = ACASandboxProvider(
        resource_group="my-rg",
        sandbox_group="agents",
        region="eastus2",
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
import os
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


_IDENTITY_INSTALL_HINT = (
    "Install azure-identity (or supply `credential=` explicitly):\n"
    "  pip install 'agt-sandbox[azure]'"
)


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


def _unpack_exec_result(resp: Any) -> tuple[int, str, str]:
    """Normalize an :meth:`SandboxClient.exec` response.

    The 0.1.0b1 SDK returns a typed result object whose example usage is
    ``out.stdout`` / ``out.stderr`` / ``out.exit_code``. Earlier preview
    builds returned a dict (``{"exitCode": ..., "stdout": ..., ...}``).
    Accept both shapes so the provider works across SDK revisions.
    """
    if resp is None:
        return -1, "", ""
    # Attribute style (typed result object).
    if hasattr(resp, "exit_code") or hasattr(resp, "stdout"):
        exit_code = getattr(resp, "exit_code", None)
        if exit_code is None:
            exit_code = getattr(resp, "exitCode", -1)
        return (
            int(exit_code if exit_code is not None else -1),
            str(getattr(resp, "stdout", "") or ""),
            str(getattr(resp, "stderr", "") or ""),
        )
    # Dict style (legacy preview).
    if isinstance(resp, dict):
        exit_code = resp.get("exit_code", resp.get("exitCode", -1))
        return (
            int(exit_code if exit_code is not None else -1),
            str(resp.get("stdout") or ""),
            str(resp.get("stderr") or ""),
        )
    return -1, "", str(resp)


class ACASandboxProvider(SandboxProvider):
    """``SandboxProvider`` backed by Azure Container Apps sandboxes.

    Uses the early-access ``azure-containerapps-sandbox`` SDK
    (``0.1.0b1``+). The provider holds one
    :class:`SandboxGroupClient <azure.containerapps.sandbox.SandboxGroupClient>`
    for the whole ``(resource_group, sandbox_group)`` pair and caches the
    per-sandbox :class:`SandboxClient
    <azure.containerapps.sandbox.SandboxClient>` returned from
    :meth:`begin_create_sandbox` so every operation goes through the
    typed surface — no raw ARM URLs.

    .. note::
       The ``resource_group`` **must already exist** in the target
       subscription. This provider does not create or manage resource
       groups — create one out-of-band first (e.g.
       ``az group create -n my-rg -l eastus2``) and pass its name here.
       Calling :meth:`create_session` against a non-existent resource
       group surfaces the Azure 404 as a ``RuntimeError`` wrapping the
       upstream ``ResourceGroupNotFound`` error.

       Sandbox groups (the sub-resource inside the RG) *can* be
       auto-created — see ``ensure_group_location`` below.

    Parameters
    ----------
    resource_group:
        Default resource group containing the sandbox group. Must
        already exist; see the note above.
    sandbox_group:
        Sandbox group that holds per-agent sandboxes. Must already exist
        unless ``ensure_group_location`` is set, in which case the
        provider creates it on first use via
        ``azure-containerapps-sandbox``'s management client.
    region:
        Azure region for the data-plane endpoint, resolved with
        :func:`azure.containerapps.sandbox.endpoint_for_region`. Falls
        back to ``ensure_group_location`` (if set) or the
        ``AZURE_SANDBOX_REGION`` environment variable. Required when
        ``endpoint`` is not supplied.
    endpoint:
        Explicit data-plane endpoint URL. Use this in tests or against
        non-public clouds where ``endpoint_for_region`` does not apply.
        Takes precedence over ``region``.
    subscription_id:
        Azure subscription ID. Auto-detected by ``azure-identity`` /
        ``DefaultAzureCredential`` when omitted, or read from
        ``AZURE_SUBSCRIPTION_ID``.
    credential:
        ``azure-identity`` credential. Defaults to
        :class:`DefaultAzureCredential`.
    disk:
        Public disk image name to provision sandboxes from
        (default ``"ubuntu"``).
    ensure_group_location:
        If set, the sandbox group will be created in this Azure region
        when it does not already exist. The enclosing
        ``resource_group`` is **not** created — it must pre-exist. Also
        used as the default for ``region`` when ``region`` is omitted.
    """

    def __init__(
        self,
        resource_group: str,
        sandbox_group: str,
        *,
        region: str | None = None,
        endpoint: str | None = None,
        subscription_id: str | None = None,
        credential: "TokenCredential | None" = None,
        disk: str = "ubuntu",
        ensure_group_location: str | None = None,
    ) -> None:
        _validate_resource_name(sandbox_group, "sandbox_group")

        self._resource_group = resource_group
        self._sandbox_group = sandbox_group
        self._subscription_id = subscription_id
        self._disk = disk
        self._ensure_group_location = ensure_group_location

        # Resolve region/endpoint. The SDK's SandboxGroupClient needs a
        # regional endpoint — derive it from `region` (preferred), then
        # `ensure_group_location`, then $AZURE_SANDBOX_REGION.
        resolved_region = (
            region
            or ensure_group_location
            or os.environ.get("AZURE_SANDBOX_REGION")
        )

        self._state_lock = threading.RLock()
        # Map (agent_id, session_id) → per-sandbox SandboxClient.
        self._sandboxes: dict[tuple[str, str], Any] = {}
        self._evaluators: dict[tuple[str, str], Any] = {}
        self._session_configs: dict[tuple[str, str], SandboxConfig] = {}

        self._available = False
        self._unavailable_reason: str | None = None
        self._group_client: Any = None
        self._mgmt_client: Any = None
        self._endpoint: str | None = endpoint

        # Lazy import so the package stays importable without
        # azure-containerapps-sandbox installed.
        try:
            from azure.containerapps import sandbox as _sdk
        except ImportError:
            self._unavailable_reason = (
                "azure-containerapps-sandbox is not installed."
            )
            logger.warning(self._unavailable_reason)
            return
        except Exception as exc:
            self._unavailable_reason = (
                f"Failed to import azure-containerapps-sandbox: {exc}."
            )
            logger.warning(self._unavailable_reason)
            return

        if self._endpoint is None:
            if not resolved_region:
                self._unavailable_reason = (
                    "ACASandboxProvider needs `region=` (or "
                    "ensure_group_location=, or $AZURE_SANDBOX_REGION) to "
                    "construct the data-plane endpoint."
                )
                logger.warning(self._unavailable_reason)
                return
            try:
                self._endpoint = _sdk.endpoint_for_region(resolved_region)
            except Exception as exc:
                self._unavailable_reason = (
                    f"endpoint_for_region({resolved_region!r}) failed: {exc}"
                )
                logger.warning(self._unavailable_reason)
                return

        try:
            # DefaultAzureCredential is the canonical fallback from the
            # SDK's quick-start guide.
            if credential is None:
                from azure.identity import DefaultAzureCredential

                credential = DefaultAzureCredential()
        except ImportError:
            self._unavailable_reason = (
                "azure-identity is not installed.\n" + _IDENTITY_INSTALL_HINT
            )
            logger.warning(self._unavailable_reason)
            return
        except Exception as exc:
            self._unavailable_reason = (
                f"Failed to build DefaultAzureCredential: {exc}. "
                "Run `az login` or supply `credential=` explicitly."
            )
            logger.warning(self._unavailable_reason)
            return

        self._credential = credential

        try:
            self._group_client = _sdk.SandboxGroupClient(
                self._endpoint,
                credential,
                subscription_id=subscription_id,
                resource_group=resource_group,
                sandbox_group=sandbox_group,
            )
        except Exception as exc:
            self._unavailable_reason = (
                f"Failed to construct SandboxGroupClient: {exc}"
            )
            logger.warning(self._unavailable_reason)
            return

        if ensure_group_location:
            try:
                self._mgmt_client = _sdk.SandboxGroupManagementClient(
                    credential,
                    subscription_id=subscription_id,
                    resource_group=resource_group,
                )
            except AttributeError:
                logger.warning(
                    "SandboxGroupManagementClient missing on this SDK "
                    "version — ensure_group_location ignored"
                )
            except Exception as exc:
                logger.warning(
                    "Failed to construct SandboxGroupManagementClient: %s",
                    exc,
                )

        self._available = True

    # ------------------------------------------------------------------
    # Group bootstrap
    # ------------------------------------------------------------------

    def _ensure_sandbox_group(self) -> None:
        """Create the sandbox group on first use when configured.

        Probes the mgmt client for the appropriate get/create methods —
        the exact surface varies slightly across SDK previews. Falls
        through silently when nothing matches so the group is assumed to
        pre-exist.
        """
        if self._mgmt_client is None or self._ensure_group_location is None:
            return

        get_method = (
            getattr(self._mgmt_client, "get_sandbox_group", None)
            or getattr(self._mgmt_client, "get_group", None)
        )
        if get_method is not None:
            try:
                get_method(self._sandbox_group)
                return
            except Exception:
                # Treat any failure (404 or otherwise) as "needs creating".
                pass

        logger.info(
            "Creating sandbox group '%s' in '%s'",
            self._sandbox_group,
            self._ensure_group_location,
        )
        # Prefer the documented `begin_*` LRO form when present;
        # fall back to the synchronous `create_*` form otherwise.
        begin_create = (
            getattr(self._mgmt_client, "begin_create_sandbox_group", None)
            or getattr(self._mgmt_client, "begin_create_group", None)
        )
        if begin_create is not None:
            poller = begin_create(
                self._sandbox_group,
                location=self._ensure_group_location,
            )
            # LROPoller.result() blocks for the terminal state.
            if hasattr(poller, "result"):
                poller.result()
            return

        create_method = (
            getattr(self._mgmt_client, "create_sandbox_group", None)
            or getattr(self._mgmt_client, "create_group", None)
        )
        if create_method is not None:
            create_method(
                self._sandbox_group,
                location=self._ensure_group_location,
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
        sb_client: Any,
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
        # The SDK requires a typed ``EgressPolicy`` model (it calls
        # ``_to_dict()`` on the argument); a plain dict will not work.
        try:
            from azure.containerapps.sandbox import (
                EgressHostRule,
                EgressPolicy,
            )
            policy: Any = EgressPolicy(
                default_action="Deny",
                host_rules=[
                    EgressHostRule(pattern=h, action="Allow") for h in hosts
                ],
            )
        except ImportError:
            # Older/forked SDKs without typed models — fall back to a dict
            # and let the SDK accept or reject it.
            policy = {
                "defaultAction": "Deny",
                "hostRules": [
                    {"pattern": h, "action": "Allow"} for h in hosts
                ],
            }
        try:
            sb_client.set_egress_policy(policy)
        except Exception as exc:
            sandbox_id = getattr(sb_client, "sandbox_id", "<unknown>")
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
            reason = (
                self._unavailable_reason
                or "ACASandboxProvider is not available."
            )
            raise RuntimeError(
                f"ACASandboxProvider is not available: {reason}"
            )

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

        # Provision the sandbox. `begin_create_sandbox` is an LRO that
        # returns a poller; `.result()` blocks until the sandbox reaches
        # Running and returns a per-sandbox SandboxClient.
        #
        # `cpu` / `memory` are passed as kwargs when the SDK accepts
        # them. The 0.1.0b1 reference doc shows only `disk=` and
        # `labels=`; forwarding the resource caps as kwargs is
        # forward-compatible with later previews. If a future SDK
        # rejects unknown kwargs we'll see TypeError here and fall back
        # to a kwargs-free create.
        create_kwargs: dict[str, Any] = {
            "disk": self._disk,
            "labels": {"agent_id": agent_id},
        }
        if policy_provided:
            create_kwargs["cpu"] = self._cpu_millicores(cfg.cpu_limit)
            create_kwargs["memory"] = self._memory_mib(cfg.memory_mb)
        if cfg.env_vars:
            create_kwargs["environment"] = dict(cfg.env_vars)

        try:
            poller = self._group_client.begin_create_sandbox(**create_kwargs)
            sb_client = poller.result() if hasattr(poller, "result") else poller
        except TypeError:
            # Older SDK previews may not accept cpu/memory/environment.
            # Retry with only the documented kwargs.
            fallback_kwargs = {
                "disk": self._disk,
                "labels": create_kwargs["labels"],
            }
            try:
                poller = self._group_client.begin_create_sandbox(
                    **fallback_kwargs
                )
                sb_client = (
                    poller.result() if hasattr(poller, "result") else poller
                )
            except Exception as exc:
                raise RuntimeError(
                    f"Failed to create Azure sandbox for agent "
                    f"'{agent_id}': {exc}"
                ) from exc
        except Exception as exc:
            raise RuntimeError(
                f"Failed to create Azure sandbox for agent '{agent_id}': {exc}"
            ) from exc

        sandbox_id = getattr(sb_client, "sandbox_id", None) or getattr(
            sb_client, "id", None
        )
        if not sandbox_id:
            raise RuntimeError(
                f"Azure sandbox client missing 'sandbox_id': {sb_client!r}"
            )

        # Apply egress policy. We do this whenever a policy is supplied —
        # the default `network_default="deny"` makes the sandbox
        # fail-closed even if `network_allowlist` is empty. Callers that
        # genuinely want a default-allow sandbox must set
        # `defaults.network_default: allow` in the policy.
        if policy_provided:
            self._apply_egress_policy(sb_client, allow_hosts, net_default)

        session_id = sandbox_id
        key = (agent_id, session_id)
        with self._state_lock:
            self._sandboxes[key] = sb_client
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
            sb_client = self._sandboxes.get(key)
            evaluator = self._evaluators.get(key)
            session_cfg = self._session_configs.get(key) or SandboxConfig()

        if sb_client is None:
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

        # Run the code over the per-sandbox `exec` endpoint. We
        # base64-encode the source so the body is opaque to the host
        # shell and any code, including multi-line scripts and quotes,
        # runs unmodified.
        encoded = base64.b64encode(code.encode("utf-8")).decode("ascii")
        command = f"echo {encoded} | base64 -d | python3"

        start = time.monotonic()
        try:
            resp = sb_client.exec(command)
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
        exit_code, stdout, stderr = _unpack_exec_result(resp)
        result = SandboxResult(
            success=exit_code == 0,
            exit_code=exit_code,
            stdout=stdout[:10000],
            stderr=stderr[:10000],
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
            sb_client = self._sandboxes.pop(key, None)
            self._evaluators.pop(key, None)
            self._session_configs.pop(key, None)

        if sb_client is None:
            return

        try:
            sb_client.delete()
        except Exception as exc:
            sandbox_id = getattr(sb_client, "sandbox_id", session_id)
            logger.warning(
                "Failed to delete Azure sandbox '%s' for agent '%s': %s",
                sandbox_id, agent_id, exc,
            )

    def is_available(self) -> bool:
        return self._available

    @property
    def unavailable_reason(self) -> str | None:
        """Human-readable reason the provider is unavailable, or ``None``.

        Includes copy-pasteable install commands when the SDK or
        ``azure-identity`` is missing. Useful for surfacing actionable
        errors in CLIs and test ``skip`` messages.
        """
        return self._unavailable_reason

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
        # Per-sandbox SandboxClient objects share the SandboxGroupClient's
        # underlying HTTP pipeline; closing the group + mgmt clients
        # tears the connections down for everyone.
        for client in (self._group_client, self._mgmt_client):
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
