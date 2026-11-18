# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Configuration helpers for :class:`HyperLightSandboxProvider`.

The configuration mirrors the design doc's ``HyperlightConfig`` surface:

* ``backend`` and ``module`` select which upstream backend / guest the
  session runs on.
* ``heap_size_bytes`` / ``stack_size_bytes`` are passed to upstream's
  ``Sandbox`` as its ``heap_size`` / ``stack_size`` strings (``"128Mi"``).
* ``max_execution_time_ms`` is checked by the provider after the guest
  returns: a run that took longer is reported as killed with a timeout
  reason, but nothing stops the guest at the deadline, because the pinned
  SDK (hyperlight-sandbox 0.4.x) has no execution-time knob.
* ``input_dir`` / ``output_dir`` are mounted in the guest as read-only
  ``/input`` and writable ``/output``.
* ``env_vars`` cannot be forwarded: the pinned SDK has no environment
  model, so a non-empty value is rejected at session creation.

"""

from __future__ import annotations

from dataclasses import dataclass, field
from agent_sandbox.sandbox_provider import SandboxConfig

# Upstream backend identifiers. Kept as plain strings (not an Enum) to
# avoid forcing callers to import a hyperlight-specific symbol just to
# pass ``backend="wasm"``.
_VALID_BACKENDS: frozenset[str] = frozenset({"wasm", "hyperlightjs", "nanvix"})

# Default heap size is the provider's own cap. The default stack size
# matches upstream's Linux default (``"35Mi"`` at hyperlight-sandbox
# v0.4.0); the packaged Python guest needs that much to start.
_DEFAULT_HEAP_BYTES = 64 * 1024 * 1024
_DEFAULT_STACK_BYTES = 35 * 1024 * 1024
_DEFAULT_MAX_EXEC_MS = 60_000

_KIB = 1024
_MIB = 1024 * 1024


def format_size(num_bytes: int) -> str:
    """Render a byte count in the ``"<n>Mi"`` / ``"<n>Ki"`` form the
    upstream ``Sandbox`` constructor takes for ``heap_size`` and
    ``stack_size``.

    Values that are not a whole number of KiB round up to the next KiB
    so a configured limit is never undercut.
    """
    if num_bytes <= 0:
        raise ValueError("size must be positive")
    if num_bytes % _MIB == 0:
        return f"{num_bytes // _MIB}Mi"
    kib = -(-num_bytes // _KIB)
    return f"{kib}Ki"


@dataclass
class HyperlightConfig:
    """Provider-specific configuration for a Hyperlight session.

    Attributes
    ----------
    backend:
        Upstream backend selector — ``"wasm"`` (default; supports the
        packaged Python and JS guests), ``"hyperlightjs"`` (JS-only,
        smaller footprint), or ``"nanvix"`` (preview microkernel; no
        tools, FS, network, or snapshots).
    module:
        Guest module identifier passed to upstream when ``backend ==
        "wasm"``. ``"python_guest"`` runs real Python source via
        ``Sandbox.run("…")``; ``"javascript_guest"`` runs JS source.
        Ignored for ``hyperlightjs`` and ``nanvix``.
    heap_size_bytes / stack_size_bytes:
        Guest heap and stack limits. Passed to upstream as the
        ``heap_size`` / ``stack_size`` strings (see :attr:`heap_size`).
    max_execution_time_ms:
        Host-side execution budget checked by the provider. The pinned
        SDK has no execution-time knob of its own.
    input_dir / output_dir:
        Optional host paths mounted in the guest as ``/input``
        (read-only) and ``/output`` (writable, per-session).
    env_vars:
        Host-side environment for the guest. The pinned SDK cannot
        forward it, so the provider rejects a non-empty value instead
        of starting a guest without it.
    """

    backend: str = "wasm"
    module: str | None = "python_guest"
    heap_size_bytes: int = _DEFAULT_HEAP_BYTES
    stack_size_bytes: int = _DEFAULT_STACK_BYTES
    max_execution_time_ms: int = _DEFAULT_MAX_EXEC_MS
    input_dir: str | None = None
    output_dir: str | None = None
    env_vars: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.backend not in _VALID_BACKENDS:
            raise ValueError(
                f"Unknown Hyperlight backend '{self.backend}'. "
                f"Expected one of: {sorted(_VALID_BACKENDS)}"
            )
        if self.heap_size_bytes <= 0:
            raise ValueError("heap_size_bytes must be positive")
        if self.stack_size_bytes <= 0:
            raise ValueError("stack_size_bytes must be positive")
        if self.max_execution_time_ms <= 0:
            raise ValueError("max_execution_time_ms must be positive")
        # ``module`` is upstream-validated when the Sandbox is built; we
        # don't enforce a hardcoded list here so future packaged guests
        # work without an SDK release.

    @property
    def heap_size(self) -> str:
        """``heap_size_bytes`` in the SDK's string form (``"128Mi"``)."""
        return format_size(self.heap_size_bytes)

    @property
    def stack_size(self) -> str:
        """``stack_size_bytes`` in the SDK's string form (``"35Mi"``)."""
        return format_size(self.stack_size_bytes)

    @classmethod
    def from_sandbox_config(
        cls,
        cfg: SandboxConfig,
        *,
        backend: str = "wasm",
        module: str | None = "python_guest",
    ) -> HyperlightConfig:
        """Translate the generic :class:`SandboxConfig` into a
        :class:`HyperlightConfig`.

        ``memory_mb`` becomes the upstream heap size and
        ``timeout_seconds`` the duration the provider compares against
        after the run returns (it is not enforced during the run).
        ``cpu_limit`` is dropped because Hyperlight pins one vCPU per
        micro-VM.
        """
        return cls(
            backend=backend,
            module=module,
            heap_size_bytes=int(cfg.memory_mb) * 1024 * 1024,
            stack_size_bytes=_DEFAULT_STACK_BYTES,
            max_execution_time_ms=int(cfg.timeout_seconds * 1000),
            input_dir=cfg.input_dir,
            output_dir=cfg.output_dir,
            env_vars=dict(cfg.env_vars),
        )
