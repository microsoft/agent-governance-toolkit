# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Shared sandbox-hardening primitives.

These guards are backend-agnostic and are reused by every sandbox
provider so the fail-closed guarantees stay identical no matter which
containment backend renders the request:

* :data:`BLOCKED_ENV_VARS` / :func:`sanitize_env_vars` strip environment
  variables an interpreter or loader sources *before* the sandbox
  entrypoint runs (``LD_PRELOAD``, ``PYTHONSTARTUP``, ``NODE_OPTIONS``,
  ...). Letting those through would redirect execution ahead of the
  sandbox hardening.
* :data:`PROTECTED_PATHS_UNIX` / :func:`is_protected_path` /
  :func:`validate_mount_path` reject bind/mount requests that target
  system roots (``/``, ``/etc``, ``C:\\Windows``, every user's profile,
  ...).

This module is a leaf: it imports nothing from the provider packages so
it can be shared without creating import cycles or pulling optional
backend SDKs into a provider that does not need them.
"""

from __future__ import annotations

import logging
import os
import platform

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Protected filesystem paths
# ---------------------------------------------------------------------------

# Protected system directories that must never be bind-mounted.
PROTECTED_PATHS_UNIX = frozenset(
    {
        "/", "/etc", "/proc", "/sys", "/usr", "/var",
        "/boot", "/dev", "/sbin", "/bin", "/lib",
    }
)

# Windows system directories that must never be bind-mounted.  Compared
# case-insensitively against the realpath of the requested mount.
PROTECTED_PATHS_WINDOWS = frozenset(
    p.lower()
    for p in (
        "C:\\Windows",
        "C:\\Program Files",
        "C:\\Program Files (x86)",
        "C:\\ProgramData",
        "C:\\System Volume Information",
    )
)

# Paths blocked only when mounted at their exact root — not their
# subdirectories. Mounting ``C:\Users`` exposes every user's profile
# (documents, browser data, SSH keys); mounting a specific subdir like
# ``C:\Users\agent\workspace`` is a legitimate per-user pattern and
# remains allowed.
PROTECTED_PATHS_WINDOWS_ROOT_ONLY = frozenset(
    p.lower() for p in ("C:\\Users",)
)


def is_protected_path(path: str) -> bool:
    """Check whether *path* is a system directory that must not be mounted."""
    system = platform.system()

    if system == "Windows":
        normalised = os.path.normpath(os.path.realpath(path))
        # Block drive roots like C:\, D:\
        if len(normalised) <= 3 and normalised.endswith((":\\", ":")):
            return True
        # Block well-known Windows system directories (case-insensitive).
        lowered = normalised.lower()
        if lowered in PROTECTED_PATHS_WINDOWS_ROOT_ONLY:
            return True
        for protected in PROTECTED_PATHS_WINDOWS:
            if lowered == protected or lowered.startswith(protected + "\\"):
                return True
        return False

    # Unix-like: resolve symlinks then normalize
    import posixpath

    resolved = os.path.realpath(path)
    normalised = posixpath.normpath(resolved)
    return normalised in PROTECTED_PATHS_UNIX


def validate_mount_path(path: str, label: str) -> None:
    """Raise ``ValueError`` if *path* is a protected system directory."""
    if is_protected_path(path):
        raise ValueError(
            f"Cannot mount protected system directory '{path}' as {label}"
        )


# ---------------------------------------------------------------------------
# Environment-variable hardening
# ---------------------------------------------------------------------------

# Environment variables that could break sandbox hardening.
# Anything an interpreter/loader will source at startup belongs here:
# each variable below redirects code execution before the sandbox's
# entrypoint runs, defeating the containment hardening.
BLOCKED_ENV_VARS = frozenset(
    {
        # glibc dynamic linker
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "LD_DEBUG",
        "LD_PROFILE",
        "LD_SHOW_AUXV",
        "LD_DYNAMIC_WEAK",
        # POSIX shell startup hooks (bash, dash, sh)
        "BASH_ENV",
        "ENV",
        # Python
        "PYTHONSTARTUP",
        "PYTHONPATH",
        "PYTHONHOME",
        # Node.js
        "NODE_OPTIONS",
        # Ruby
        "RUBYOPT",
        # Perl
        "PERL5LIB",
        "PERL5OPT",
        # Java
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
    }
)


def sanitize_env_vars(env_vars: dict[str, str]) -> dict[str, str]:
    """Remove dangerous env vars that could escape sandbox hardening."""
    blocked_found = [
        k for k in env_vars if k.upper() in BLOCKED_ENV_VARS
    ]
    if blocked_found:
        logger.warning(
            "Blocked dangerous environment variables: %s",
            blocked_found,
        )
    return {
        k: v
        for k, v in env_vars.items()
        if k.upper() not in BLOCKED_ENV_VARS
    }
