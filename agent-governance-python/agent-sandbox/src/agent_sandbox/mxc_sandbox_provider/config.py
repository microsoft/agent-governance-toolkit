# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Configuration helpers for :class:`MxcSandboxProvider`.

`MXC <https://github.com/microsoft/mxc>`_ (Microsoft eXecution Container)
is a native, JSON-configured sandbox runner with multiple containment
backends (ProcessContainer on Windows, Bubblewrap / LXC on Linux,
Seatbelt on macOS, plus experimental MicroVM / Hyperlight / Windows
Sandbox shapes).  It exposes no Python SDK; the integration point is the
native ``wxc-exec`` / ``lxc-exec`` / ``mxc-exec-mac`` binary, which takes
a single JSON configuration document (by file path or base64) and couples
the sandboxed process's stdio to the caller.

This module models the documented schema-``0.6.0-alpha`` surface as a
typed :class:`MxcConfig` and renders it to the JSON document the binary
consumes.

Only the well-known schema fields are modelled directly
(``version``, ``process.commandLine``, ``filesystem.readonlyPaths`` /
``readwritePaths``, ``network.allowOutbound`` + host filtering, and
``timeoutMs``).  Any additional schema keys an operator needs (UI policy,
backend-specific tuning) can be supplied verbatim through
``extra_config`` and are merged into the rendered document without this
provider interpreting them.
"""

from __future__ import annotations

import copy
import logging
from dataclasses import dataclass, field
from typing import Any

from agent_sandbox._hardening import sanitize_env_vars, validate_mount_path
from agent_sandbox.sandbox_provider import SandboxConfig

logger = logging.getLogger(__name__)

# Default schema version. ``0.6.0-alpha`` is the current *stable* schema
# recommended for new code on every supported platform per the MXC
# README. ``0.7.0-dev`` adds experimental backends and the state-aware
# lifecycle but is explicitly a dev schema.
DEFAULT_SCHEMA_VERSION = "0.6.0-alpha"

# Containment backends documented by MXC. The stable one-shot backends
# (``processcontainer``, ``bubblewrap``, ``lxc``) do not require
# experimental mode; everything else does. ``None`` means "let MXC pick
# the platform-appropriate default" (processcontainer on Windows,
# bubblewrap on Linux, seatbelt on macOS).
_STABLE_BACKENDS: frozenset[str] = frozenset(
    {"processcontainer", "bubblewrap", "lxc"}
)
_EXPERIMENTAL_BACKENDS: frozenset[str] = frozenset(
    {
        "windows_sandbox",
        "wslc",
        "microvm",
        "seatbelt",
        "isolation_session",
        "hyperlight",
    }
)
_KNOWN_BACKENDS: frozenset[str] = _STABLE_BACKENDS | _EXPERIMENTAL_BACKENDS

_DEFAULT_TIMEOUT_MS = 60_000


def backend_requires_experimental(backend: str | None) -> bool:
    """Return ``True`` if *backend* needs MXC's experimental opt-in.

    ``seatbelt`` is the platform default on macOS but is still listed as
    an experimental backend by MXC, so selecting it explicitly requires
    the experimental flag. ``None`` (platform default) never does.
    """
    if backend is None:
        return False
    return backend in _EXPERIMENTAL_BACKENDS


@dataclass
class MxcConfig:
    """Provider-specific configuration for an MXC sandbox invocation.

    Attributes
    ----------
    version:
        MXC configuration schema version. Defaults to the current stable
        ``0.6.0-alpha``.
    backend:
        Containment backend identifier (for example ``"bubblewrap"`` or
        ``"processcontainer"``). ``None`` lets MXC select the
        platform-appropriate default. Experimental backends are
        accepted but require ``experimental=True`` (or the provider's
        ``--experimental`` opt-in) at spawn time.
    readonly_paths / readwrite_paths:
        Host paths exposed to the sandbox read-only and read-write
        respectively. These map to ``filesystem.readonlyPaths`` /
        ``filesystem.readwritePaths``.
    allow_outbound:
        Whether the sandbox may open outbound network connections. Maps
        to ``network.allowOutbound``. Defaults to ``False`` (no egress).
    allowed_hosts:
        Optional outbound host allowlist. Only meaningful when
        ``allow_outbound`` is ``True``. Egress is **fail-closed**: when
        ``allow_outbound`` is ``True`` the host list must be non-empty
        *unless* ``allow_unrestricted_egress`` is explicitly set, so a
        config never silently emits "any host" egress.
    allow_unrestricted_egress:
        Explicit opt-in for unrestricted outbound (``allow_outbound`` set
        with an empty ``allowed_hosts``). Defaults to ``False`` so the
        only way to get unrestricted egress is to ask for it on purpose
        (for example via a policy ``defaults.network_default: allow``).
    timeout_ms:
        Wall-clock execution budget in milliseconds. Maps to
        ``timeoutMs``.
    experimental:
        Request MXC's experimental mode. Implied automatically when
        ``backend`` is an experimental backend.
    env_vars:
        Host-side environment exposed to the sandboxed process where the
        backend supports it.
    extra_config:
        Verbatim JSON fragment merged into the rendered configuration
        document (deep-merged over the modelled fields). Use this for
        schema keys this provider does not model directly, such as UI
        policy. MXC validates the merged document; this provider does
        not interpret ``extra_config``.
    """

    version: str = DEFAULT_SCHEMA_VERSION
    backend: str | None = None
    readonly_paths: list[str] = field(default_factory=list)
    readwrite_paths: list[str] = field(default_factory=list)
    allow_outbound: bool = False
    allowed_hosts: list[str] = field(default_factory=list)
    allow_unrestricted_egress: bool = False
    timeout_ms: int = _DEFAULT_TIMEOUT_MS
    experimental: bool = False
    env_vars: dict[str, str] = field(default_factory=dict)
    extra_config: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.version, str) or not self.version:
            raise ValueError("version must be a non-empty string")
        if self.backend is not None and self.backend not in _KNOWN_BACKENDS:
            raise ValueError(
                f"Unknown MXC backend '{self.backend}'. Expected one of "
                f"{sorted(_KNOWN_BACKENDS)} or None for the platform default."
            )
        if self.timeout_ms <= 0:
            raise ValueError("timeout_ms must be positive")
        # An experimental backend forces experimental mode on so callers
        # cannot accidentally select one without the opt-in propagating.
        if backend_requires_experimental(self.backend):
            self.experimental = True
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
                "host allowlist. Refusing to emit unrestricted egress by "
                "default. Provide allowed_hosts to restrict egress, or set "
                "allow_unrestricted_egress=True (for example via a policy "
                "'defaults.network_default: allow') to opt in explicitly."
            )

    @property
    def needs_experimental(self) -> bool:
        """Whether spawning with this config requires ``--experimental``."""
        return self.experimental or backend_requires_experimental(self.backend)

    @classmethod
    def from_sandbox_config(
        cls,
        cfg: SandboxConfig,
        *,
        backend: str | None = None,
        experimental: bool = False,
    ) -> MxcConfig:
        """Translate the generic :class:`SandboxConfig` into an
        :class:`MxcConfig`.

        ``timeout_seconds`` becomes ``timeoutMs``. Network configuration
        remains fail-closed unless an allowlist or explicit default allow
        is supplied. ``input_dir`` is exposed read-only and ``output_dir``
        read-write. ``memory_mb`` / ``cpu_limit`` are
        not expressed in the ``0.6.0-alpha`` schema and are dropped (MXC
        relies on the backend's own resource model).

        ``input_dir`` / ``output_dir`` are rejected if they target a
        protected system directory.
        """
        readonly: list[str] = []
        readwrite: list[str] = []
        if cfg.input_dir:
            validate_mount_path(str(cfg.input_dir), "input_dir")
            readonly.append(cfg.input_dir)
        if cfg.output_dir:
            validate_mount_path(str(cfg.output_dir), "output_dir")
            readwrite.append(cfg.output_dir)
        allowed_hosts = (
            list(cfg.network_allowlist) if cfg.network_enabled else []
        )
        allow_unrestricted = bool(
            cfg.network_enabled
            and not allowed_hosts
            and cfg.network_default == "allow"
        )
        return cls(
            backend=backend,
            readonly_paths=readonly,
            readwrite_paths=readwrite,
            allow_outbound=bool(allowed_hosts or allow_unrestricted),
            allowed_hosts=allowed_hosts,
            allow_unrestricted_egress=allow_unrestricted,
            timeout_ms=max(1, int(cfg.timeout_seconds * 1000)),
            experimental=experimental,
            env_vars=dict(cfg.env_vars),
        )

    def to_mxc_json(self, command_line: str) -> dict[str, Any]:
        """Render the configuration document MXC consumes.

        *command_line* is the single command string the sandbox runs
        (MXC's ``process.commandLine``). The returned ``dict`` is
        JSON-serialisable and ready to write to a config file or
        base64-encode for ``--config-base64``.

        Guest environment variables are sanitised (dangerous loader hooks
        like ``LD_PRELOAD`` / ``PYTHONSTARTUP`` are stripped) and the
        security-critical keys (network egress, filesystem mounts,
        timeout) are re-asserted *after* the ``extra_config`` merge so a
        verbatim fragment can never weaken them.
        """
        self._check_egress()
        doc: dict[str, Any] = {
            "version": self.version,
            "process": {"commandLine": command_line},
            "filesystem": {
                "readonlyPaths": list(self.readonly_paths),
                "readwritePaths": list(self.readwrite_paths),
            },
            "network": {"allowOutbound": bool(self.allow_outbound)},
            "timeoutMs": int(self.timeout_ms),
        }
        if self.backend is not None:
            doc["backend"] = self.backend
        if self.allow_outbound and self.allowed_hosts:
            doc["network"]["allowedHosts"] = list(self.allowed_hosts)
        sanitised_env = sanitize_env_vars(self.env_vars) if self.env_vars else {}
        if sanitised_env:
            doc["process"]["environment"] = sanitised_env
        if self.extra_config:
            _deep_merge(doc, self.extra_config)
            self._reassert_security_keys(doc)
        return doc

    def _reassert_security_keys(self, doc: dict[str, Any]) -> None:
        """Restore security-critical keys after an ``extra_config`` merge.

        ``extra_config`` is operator-supplied and merged verbatim, so it
        could otherwise flip ``network.allowOutbound``, widen the host
        filter, swap the filesystem mounts, or extend the timeout. Pin
        those keys back to the modelled values; unrelated keys the
        operator added (UI policy, backend tuning) are left untouched.
        """
        net = doc.get("network")
        if not isinstance(net, dict):
            net = {}
            doc["network"] = net
        net["allowOutbound"] = bool(self.allow_outbound)
        if self.allow_outbound and self.allowed_hosts:
            net["allowedHosts"] = list(self.allowed_hosts)
        else:
            net.pop("allowedHosts", None)

        fs = doc.get("filesystem")
        if not isinstance(fs, dict):
            fs = {}
            doc["filesystem"] = fs
        fs["readonlyPaths"] = list(self.readonly_paths)
        fs["readwritePaths"] = list(self.readwrite_paths)

        doc["timeoutMs"] = int(self.timeout_ms)


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> None:
    """Recursively merge *overlay* into *base* in place.

    Nested dicts are merged key-by-key; every other value (including
    lists) replaces the value in *base*. Used to layer ``extra_config``
    over the modelled fields without clobbering whole sub-objects.
    """
    for key, value in overlay.items():
        if (
            key in base
            and isinstance(base[key], dict)
            and isinstance(value, dict)
        ):
            _deep_merge(base[key], value)
        else:
            base[key] = copy.deepcopy(value)
