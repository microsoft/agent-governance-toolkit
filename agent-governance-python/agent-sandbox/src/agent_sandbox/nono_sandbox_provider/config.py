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
typed, dependency-free :class:`NonoConfig`. Building the actual
``CapabilitySet`` and ``ProxyConfig`` objects requires ``nono_py`` and is
performed by :class:`NonoSandboxProvider`.
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

        ``timeout_seconds`` carries over. Network settings preserve host
        allowlists and require an explicit default allow for unrestricted
        egress. ``input_dir`` is granted read-only and ``output_dir``
        read-write.
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
        allowed_hosts = (
            list(getattr(cfg, "network_allowlist", []) or [])
            if network_enabled
            else []
        )
        allow_unrestricted = bool(
            network_enabled
            and not allowed_hosts
            and getattr(cfg, "network_default", "deny") == "allow"
        )
        timeout_seconds = float(
            getattr(cfg, "timeout_seconds", _DEFAULT_TIMEOUT_SECONDS)
        )
        env_vars = dict(getattr(cfg, "env_vars", {}) or {})

        return cls(
            readonly_paths=readonly,
            readwrite_paths=readwrite,
            allow_outbound=bool(allowed_hosts or allow_unrestricted),
            allowed_hosts=allowed_hosts,
            allow_unrestricted_egress=allow_unrestricted,
            timeout_seconds=max(0.001, timeout_seconds),
            env_vars=env_vars,
            include_system_paths=include_system_paths,
        )
