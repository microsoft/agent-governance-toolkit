# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Validated configuration for the proposed loopback-only Studio profile."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


class ConfigurationError(ValueError):
    """A safe, actionable configuration diagnostic."""


@dataclass(frozen=True)
class Limits:
    body_bytes: int = 8 * 1024 * 1024
    response_bytes: int = 16 * 1024 * 1024
    concurrent_requests: int = 2
    requests_per_minute: int = 60
    probes_per_minute: int = 120
    receive_seconds: float = 5
    execution_seconds: float = 10
    startup_seconds: float = 10
    shutdown_seconds: float = 3
    policy_files: int = 256
    policy_file_bytes: int = 1024 * 1024
    policy_tree_bytes: int = 16 * 1024 * 1024

    def __post_init__(self) -> None:
        import math

        if any(
            not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0
            for value in vars(self).values()
        ):
            raise ConfigurationError("Resource limits must be finite positive values.")
        for name, value in vars(self).items():
            if not name.endswith("_seconds") and (not isinstance(value, int) or isinstance(value, bool)):
                raise ConfigurationError("Count and byte limits must be positive integers.")


@dataclass(frozen=True)
class Configuration:
    host: str = "127.0.0.1"
    port: int = 8080
    policy_dir: Path | None = None
    limits: Limits = Limits()

    def __post_init__(self) -> None:
        if self.host != "127.0.0.1":
            raise ConfigurationError("Only --host 127.0.0.1 is supported; remote and IPv6 modes are blocked.")
        if not isinstance(self.port, int) or isinstance(self.port, bool) or not 1 <= self.port <= 65535:
            raise ConfigurationError("--port must be an integer from 1 through 65535.")
        if not isinstance(self.limits, Limits):
            raise ConfigurationError("A validated finite Limits configuration is required.")
        if self.policy_dir is not None:
            try:
                root = Path(self.policy_dir).resolve(strict=True)
                if not root.is_dir():
                    raise ConfigurationError("--policy-dir must identify a readable directory.")
            except OSError:
                raise ConfigurationError("--policy-dir must identify an existing readable directory.") from None
            object.__setattr__(self, "policy_dir", root)

    @property
    def authority(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def origin(self) -> str:
        return f"http://{self.authority}"


def configure(
    host: str = "127.0.0.1",
    port: int = 8080,
    policy_dir: str | Path | None = None,
    *,
    environ: Mapping[str, str] | None = None,
) -> Configuration:
    env = os.environ if environ is None else environ
    if "AGT_STUDIO_TOKEN" in env:
        raise ConfigurationError("AGT_STUDIO_TOKEN is unsupported, even when empty; unset it for this profile.")
    token_path = Path.home() / ".config" / "agt" / "studio-token"
    try:
        token_path.lstat()
    except FileNotFoundError:
        token_configured = False
    except OSError:
        raise ConfigurationError("Cannot inspect Studio credential configuration; credential-based mode is unsupported.") from None
    else:
        token_configured = True
    if token_configured:
        raise ConfigurationError("A Studio token file is configured; credential-based mode is not supported.")
    root = policy_dir if policy_dir is not None else env.get("AGT_STUDIO_POLICY_DIR")
    if root is None:
        return Configuration(host, port)
    if not str(root).strip():
        raise ConfigurationError("The explicitly configured policy directory must not be empty.")
    try:
        path = Path(root).resolve(strict=True)
        if not path.is_dir():
            raise ConfigurationError("--policy-dir must identify a readable directory.")
        with os.scandir(path) as entries:
            next(entries, None)
    except OSError:
        raise ConfigurationError("--policy-dir must identify an existing readable directory.") from None
    return Configuration(host, port, path)
