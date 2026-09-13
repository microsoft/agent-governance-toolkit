# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Configuration helpers for :class:`HyperLightSandboxProvider`.

The configuration mirrors the design doc's ``HyperlightConfig`` surface:

* ``backend`` and ``module`` select which upstream backend / guest the
  session runs on.
* ``heap_size_bytes`` / ``stack_size_bytes`` / ``max_execution_time_ms``
  map to upstream's ``SandboxConfiguration`` knobs.
* ``input_dir`` / ``output_dir`` are mounted in the guest as read-only
  ``/input`` and writable ``/output``.

"""

from __future__ import annotations

from dataclasses import dataclass, field
from agent_sandbox.sandbox_provider import SandboxConfig

# Upstream backend identifiers. Kept as plain strings (not an Enum) to
# avoid forcing callers to import a hyperlight-specific symbol just to
# pass ``backend="wasm"``.
_VALID_BACKENDS: frozenset[str] = frozenset({"wasm", "hyperlightjs", "nanvix"})

# Default heap / stack sizes follow upstream's ``SandboxConfiguration``
# defaults at hyperlight-sandbox v0.4.0.
_DEFAULT_HEAP_BYTES = 64 * 1024 * 1024
_DEFAULT_STACK_BYTES = 2 * 1024 * 1024
_DEFAULT_MAX_EXEC_MS = 60_000


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
    heap_size_bytes / stack_size_bytes / max_execution_time_ms:
        Upstream ``SandboxConfiguration`` knobs.
    input_dir / output_dir:
        Optional host paths mounted in the guest as ``/input``
        (read-only) and ``/output`` (writable, per-session).
    env_vars:
        Optional host-side environment exposed to the guest where the
        backend supports it. Ignored on backends that have no env model.
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

        Resource limits (``memory_mb``, ``timeout_seconds``) become
        upstream heap / max-execution-time. ``cpu_limit`` is dropped
        because Hyperlight pins one vCPU per micro-VM.
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
