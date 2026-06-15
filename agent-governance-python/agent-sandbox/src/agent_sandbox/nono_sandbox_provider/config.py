# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Configuration helpers for :class:`NonoSandboxProvider`.

`nono <https://github.com/always-further/nono>`_ is a capability-based
sandbox enforced by OS-native kernel primitives (Landlock on Linux,
Seatbelt on macOS).  Its Python bindings, ``nono-py``, expose a
:class:`nono_py.CapabilitySet` (filesystem grants + a network mode), a
filtering proxy (:func:`nono_py.start_proxy`), and the one-shot
:func:`nono_py.sandboxed_exec` primitive that forks, sandboxes, and execs
a command.

This module models the provider-relevant subset of that surface as a
typed, dependency-free :class:`NonoConfig` and translates an Agent-OS
``PolicyDocument`` (or duck-typed equivalent) into one.  Building the
actual ``CapabilitySet`` / ``ProxyConfig`` objects requires ``nono_py``
and is performed by :class:`NonoSandboxProvider`; this module stays pure
data so policy translation and the fail-closed egress contract can be
unit-tested without the native extension installed.

``nono_config_from_policy`` performs the same kind of policy → config
translation as ``docker_config_from_policy`` and the other provider helpers
so a single policy can drive any backend.
"""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent_sandbox._hardening import sanitize_env_vars, validate_mount_path

logger = logging.getLogger(__name__)

# Default wall-clock execution budget (seconds) when none is supplied.
_DEFAULT_TIMEOUT_SECONDS = 60.0

# System directories a forked child needs read access to so an interpreter
# (and the shell it may invoke) can load. Mirrors nono's own examples /
# test helpers. Missing entries are skipped at cap-build time rather than
# rejected, so the same list is safe on Linux and macOS.
_SYSTEM_PATHS_UNIX = ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt")
_SYSTEM_PATHS_MACOS = ("/private", "/Library/Frameworks", "/dev", "/System")


def default_system_paths() -> list[str]:
    """Return existing system paths a sandboxed interpreter needs to read.

    Includes the platform's standard system roots plus the running
    interpreter's prefix(es) so ``python`` resolves inside the sandbox.
    Only paths that currently exist are returned; the provider grants
    them read-only.

    Returns
    -------
    list[str]
        Absolute paths that exist on the host and should be granted
        read-only to a sandboxed child process.
    """
    candidates: list[str] = list(_SYSTEM_PATHS_UNIX)
    if sys.platform == "darwin":
        candidates.extend(_SYSTEM_PATHS_MACOS)

    # The interpreter's install prefix(es) — needed to import the stdlib.
    try:
        py_prefix = str(Path(sys.executable).resolve().parent.parent)
    except (OSError, ValueError):  # pragma: no cover - defensive
        py_prefix = ""
    for prefix in (py_prefix, sys.prefix, sys.base_prefix):
        if prefix and prefix not in candidates:
            candidates.append(prefix)

    seen: set[str] = set()
    resolved: list[str] = []
    for path in candidates:
        if path in seen:
            continue
        seen.add(path)
        if os.path.exists(path):
            resolved.append(path)
    return resolved


@dataclass
class NonoConfig:
    """Provider-specific configuration for a nono sandbox invocation.

    Attributes
    ----------
    readonly_paths / readwrite_paths:
        Host directories granted to the sandbox read-only and read-write
        respectively. Map to ``caps.allow_path(p, AccessMode.READ)`` /
        ``caps.allow_path(p, AccessMode.READ_WRITE)``.
    allow_outbound:
        Whether the sandbox may open outbound network connections. When
        ``True`` the provider starts a nono filtering proxy and binds the
        sandbox to it; when ``False`` the caps call ``block_network()``.
        Defaults to ``False`` (no egress).
    allowed_hosts:
        Outbound host allowlist enforced by the proxy. Only meaningful
        when ``allow_outbound`` is ``True``. Egress is **fail-closed**:
        when ``allow_outbound`` is ``True`` the host list must be
        non-empty *unless* ``allow_unrestricted_egress`` is explicitly
        set, so a config never silently grants "any host" egress.
    allow_unrestricted_egress:
        Explicit opt-in for unrestricted outbound (``allow_outbound`` set
        with an empty ``allowed_hosts``). Maps to a proxy started with
        ``allow_all_hosts=True``. Defaults to ``False``.
    timeout_seconds:
        Wall-clock execution budget passed to ``sandboxed_exec`` as
        ``timeout_secs``.
    env_vars:
        Environment exposed to the sandboxed process. Sanitised through
        the shared :func:`sanitize_env_vars` before use.
    include_system_paths:
        Whether to grant read access to the standard system directories
        (see :func:`default_system_paths`) so an interpreter can load.
        Defaults to ``True``.
    """

    readonly_paths: list[str] = field(default_factory=list)
    readwrite_paths: list[str] = field(default_factory=list)
    allow_outbound: bool = False
    allowed_hosts: list[str] = field(default_factory=list)
    allow_unrestricted_egress: bool = False
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS
    env_vars: dict[str, str] = field(default_factory=dict)
    include_system_paths: bool = True

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._check_egress()

    def _check_egress(self) -> None:
        """Enforce the fail-closed egress contract.

        Outbound networking with no host allowlist means "reach any
        host", which must never happen implicitly. Require either a
        non-empty ``allowed_hosts`` or an explicit
        ``allow_unrestricted_egress`` opt-in whenever ``allow_outbound``
        is set.
        """
        if (
            self.allow_outbound
            and not self.allowed_hosts
            and not self.allow_unrestricted_egress
        ):
            raise ValueError(
                "Outbound network is enabled (allow_outbound=True) without a "
                "host allowlist. Refusing to grant unrestricted egress by "
                "default. Provide allowed_hosts to restrict egress, or set "
                "allow_unrestricted_egress=True (for example via a policy "
                "'defaults.network_default: allow') to opt in explicitly."
            )

    def sanitized_env(self) -> dict[str, str]:
        """Return ``env_vars`` with dangerous loader hooks stripped.

        Returns
        -------
        dict[str, str]
            Sanitised copy of :attr:`env_vars` with entries like
            ``LD_PRELOAD`` and ``PYTHONSTARTUP`` removed.
        """
        return sanitize_env_vars(self.env_vars) if self.env_vars else {}

    @classmethod
    def from_sandbox_config(
        cls,
        cfg: Any,
        *,
        include_system_paths: bool = True,
    ) -> NonoConfig:
        """Translate the generic ``SandboxConfig`` into a :class:`NonoConfig`.

        ``timeout_seconds`` carries over; ``network_enabled`` becomes
        ``allow_outbound`` (treated as an explicit unrestricted-egress
        opt-in, since the generic config carries no host filter);
        ``input_dir`` is granted read-only and ``output_dir`` read-write.
        ``memory_mb`` / ``cpu_limit`` are not expressible in nono and are
        dropped (the OS governs resources).

        ``input_dir`` / ``output_dir`` are rejected if they target a
        protected system directory.

        Parameters
        ----------
        cfg:
            Generic sandbox configuration (typically
            :class:`~agent_sandbox.sandbox_provider.SandboxConfig`).
        include_system_paths:
            Whether to grant read access to standard system directories
            (see :func:`default_system_paths`) so an interpreter can
            load inside the sandbox. Defaults to ``True``.

        Returns
        -------
        NonoConfig
            Provider-specific configuration ready for
            :class:`~agent_sandbox.nono_sandbox_provider.provider.NonoSandboxProvider`.
        """
        readonly: list[str] = []
        readwrite: list[str] = []
        input_dir = getattr(cfg, "input_dir", None)
        output_dir = getattr(cfg, "output_dir", None)
        if input_dir:
            validate_mount_path(str(input_dir), "input_dir")
            readonly.append(str(input_dir))
        if output_dir:
            validate_mount_path(str(output_dir), "output_dir")
            readwrite.append(str(output_dir))

        network_enabled = bool(getattr(cfg, "network_enabled", False))
        timeout_seconds = float(
            getattr(cfg, "timeout_seconds", _DEFAULT_TIMEOUT_SECONDS)
        )
        env_vars = dict(getattr(cfg, "env_vars", {}) or {})

        return cls(
            readonly_paths=readonly,
            readwrite_paths=readwrite,
            allow_outbound=network_enabled,
            allow_unrestricted_egress=network_enabled,
            timeout_seconds=max(0.001, timeout_seconds),
            env_vars=env_vars,
            include_system_paths=include_system_paths,
        )


def _validate_policy_sandbox_fields(policy: Any) -> None:
    """Validate duck-typed sandbox fields before merging into :class:`NonoConfig`.

    ``nono_config_from_policy`` accepts plain dicts (via :class:`_AttrDict`)
    as well as :class:`~agent_os.policies.schema.PolicyDocument` instances.
    Pydantic validates the latter at construction time; this helper
    rejects malformed attribute types on duck-typed inputs so a hostile or
    mistyped policy cannot slip non-string hosts or mount paths through.
    """
    net_allow = getattr(policy, "network_allowlist", None)
    if net_allow is not None:
        if not isinstance(net_allow, list):
            raise TypeError(
                "policy.network_allowlist must be a list of host patterns, "
                f"got {type(net_allow).__name__}"
            )
        for idx, host in enumerate(net_allow):
            if not isinstance(host, str) or not host.strip():
                raise ValueError(
                    "policy.network_allowlist entries must be non-empty "
                    f"strings; entry {idx} is {host!r}"
                )

    defaults = getattr(policy, "defaults", None)
    if defaults is not None:
        timeout_s = getattr(defaults, "timeout_seconds", None)
        if timeout_s is not None and not isinstance(timeout_s, (int, float)):
            raise TypeError(
                "policy.defaults.timeout_seconds must be a number, "
                f"got {type(timeout_s).__name__}"
            )
        if isinstance(timeout_s, (int, float)) and timeout_s <= 0:
            raise ValueError(
                "policy.defaults.timeout_seconds must be positive, "
                f"got {timeout_s}"
            )
        network_default = getattr(defaults, "network_default", None)
        if network_default is not None and not isinstance(network_default, str):
            raise TypeError(
                "policy.defaults.network_default must be a string, "
                f"got {type(network_default).__name__}"
            )
        max_mem = getattr(defaults, "max_memory_mb", None)
        if max_mem is not None and not isinstance(max_mem, int):
            raise TypeError(
                "policy.defaults.max_memory_mb must be an int, "
                f"got {type(max_mem).__name__}"
            )
        max_cpu = getattr(defaults, "max_cpu", None)
        if max_cpu is not None and not isinstance(max_cpu, (int, float)):
            raise TypeError(
                "policy.defaults.max_cpu must be a number, "
                f"got {type(max_cpu).__name__}"
            )

    mounts = getattr(policy, "sandbox_mounts", None)
    if mounts is not None:
        for label in ("input_dir", "output_dir"):
            path = getattr(mounts, label, None)
            if path is not None and not isinstance(path, str):
                raise TypeError(
                    f"policy.sandbox_mounts.{label} must be a string, "
                    f"got {type(path).__name__}"
                )


def _network_default(policy: Any) -> str:
    """Return the policy's sandbox egress default ('allow' or 'deny').

    Reads ``policy.defaults.network_default`` and **falls back to
    'deny'** (fail-closed) whenever the field is missing or
    unrecognised. Mirrors the other sandbox providers so the only way to get
    default-allow egress is to set ``defaults.network_default: allow``
    explicitly.
    """
    defaults = getattr(policy, "defaults", None)
    value = getattr(defaults, "network_default", None) if defaults else None
    if isinstance(value, str) and value.lower() in ("allow", "deny"):
        return value.lower()
    return "deny"


def nono_config_from_policy(
    policy: Any,
    base: NonoConfig | None = None,
) -> NonoConfig:
    """Extract nono-relevant fields from a policy.

    Reads well-known attributes when present and merges them over
    *base*; missing attributes leave *base* unchanged. Recognised:

    * ``defaults.timeout_seconds`` → ``timeout_seconds``
    * ``sandbox_mounts.input_dir`` → ``readonly_paths`` (appended)
    * ``sandbox_mounts.output_dir`` → ``readwrite_paths`` (appended)
    * ``network_allowlist`` → ``allow_outbound = True`` and
      ``allowed_hosts`` (egress restricted to those hosts)
    * ``defaults.network_default`` → ``allow`` opts into unrestricted
      egress; ``deny`` (the fail-closed default) keeps egress off

    Mount paths that target a protected system directory are rejected,
    and egress stays fail-closed: outbound is only enabled by a
    non-empty ``network_allowlist`` (restricted) or an explicit
    ``network_default: allow`` (unrestricted).

    Parameters
    ----------
    policy:
        A :class:`~agent_os.policies.schema.PolicyDocument` or any
        duck-typed object exposing ``defaults``, ``sandbox_mounts``, and
        ``network_allowlist`` attributes.
    base:
        Optional starting :class:`NonoConfig`. Policy fields are merged
        over this base rather than replacing it.

    Returns
    -------
    NonoConfig
        Assembled nono configuration derived from *policy* and *base*.

    Raises
    ------
    TypeError
        If a recognised policy field has the wrong type.
    ValueError
        If a recognised policy field has an invalid value (for example an
        empty ``network_allowlist`` entry or a non-positive timeout).
    """
    _validate_policy_sandbox_fields(policy)
    src = base or NonoConfig()
    cfg = NonoConfig(
        readonly_paths=list(src.readonly_paths),
        readwrite_paths=list(src.readwrite_paths),
        allow_outbound=src.allow_outbound,
        allowed_hosts=list(src.allowed_hosts),
        allow_unrestricted_egress=src.allow_unrestricted_egress,
        timeout_seconds=src.timeout_seconds,
        env_vars=dict(src.env_vars),
        include_system_paths=src.include_system_paths,
    )

    defaults = getattr(policy, "defaults", None)
    if defaults is not None:
        timeout_s = getattr(defaults, "timeout_seconds", None)
        if isinstance(timeout_s, (int, float)) and timeout_s > 0:
            cfg.timeout_seconds = float(timeout_s)
        # nono has no resource-cap surface; the OS governs CPU / memory.
        # Warn rather than silently drop a cap the operator expressed.
        max_mem = getattr(defaults, "max_memory_mb", None)
        max_cpu = getattr(defaults, "max_cpu", None)
        if max_mem or max_cpu:
            logger.warning(
                "Policy sets resource caps (max_memory_mb=%s, max_cpu=%s) "
                "that nono cannot express; CPU / memory limits are delegated "
                "to the operating system and not enforced by nono itself.",
                max_mem,
                max_cpu,
            )

    mounts = getattr(policy, "sandbox_mounts", None)
    if mounts is not None:
        in_dir = getattr(mounts, "input_dir", None)
        if in_dir and str(in_dir) not in cfg.readonly_paths:
            validate_mount_path(str(in_dir), "input_dir")
            cfg.readonly_paths.append(str(in_dir))
        out_dir = getattr(mounts, "output_dir", None)
        if out_dir and str(out_dir) not in cfg.readwrite_paths:
            validate_mount_path(str(out_dir), "output_dir")
            cfg.readwrite_paths.append(str(out_dir))

    net_allow = getattr(policy, "network_allowlist", None)
    if net_allow:
        cfg.allow_outbound = True
        for host in net_allow:
            if str(host) not in cfg.allowed_hosts:
                cfg.allowed_hosts.append(str(host))
    elif _network_default(policy) == "allow":
        # Explicit opt-in: unrestricted egress with no host filter.
        cfg.allow_outbound = True
        cfg.allow_unrestricted_egress = True

    # Re-validate the assembled config so the egress contract is enforced
    # even though the fields above were mutated after construction.
    cfg._check_egress()
    return cfg


class _AttrDict:
    """Recursive attribute view over a nested mapping.

    ``nono_config_from_policy`` reads a policy via duck-typed attribute
    access (``policy.defaults.timeout_seconds``,
    ``policy.sandbox_mounts.input_dir``, ``policy.network_allowlist``).
    A plain ``dict`` loaded from YAML exposes those as keys, not
    attributes, so this thin wrapper bridges the two without pulling in
    the Agent-OS ``PolicyDocument`` model. Lists and scalars pass
    through unchanged; nested mappings are wrapped lazily.
    """

    __slots__ = ("_data",)

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def __getattr__(self, name: str) -> Any:
        try:
            value = self._data[name]
        except KeyError:
            raise AttributeError(name) from None
        if isinstance(value, dict):
            return _AttrDict(value)
        return value


def policy_yaml_to_nono_config(
    yaml_path: str,
    *,
    base: NonoConfig | None = None,
) -> NonoConfig:
    """Load a sandbox policy YAML file and convert it to a :class:`NonoConfig`.

    The YAML is parsed with ``yaml.safe_load`` and exposed to
    :func:`nono_config_from_policy` via an attribute view. This keeps the
    converter dependency-free (it does not import the Agent-OS
    ``PolicyDocument`` model) while still honoring the ``sandbox_mounts``
    block, which is a native ``PolicyDocument`` field.

    Parameters
    ----------
    yaml_path:
        Path to the policy YAML file.
    base:
        Optional starting :class:`NonoConfig` (e.g. to pin timeout or
        mount defaults before policy fields are merged).

    Returns
    -------
    NonoConfig
        Provider-specific configuration derived from the YAML policy.
    """
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise ImportError(
            "PyYAML is required to load policy YAML: pip install pyyaml"
        ) from exc

    with open(yaml_path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(
            f"policy YAML at '{yaml_path}' must be a mapping, "
            f"got {type(data).__name__}"
        )
    return nono_config_from_policy(_AttrDict(data), base=base)
