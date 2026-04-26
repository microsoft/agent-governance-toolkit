# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Inter-package version compatibility validation.

Detects version skew between governance toolkit packages and warns when
running untested combinations. Ships a machine-readable compatibility
matrix and a ``doctor()`` function that validates the current environment.

Usage:
    from agent_os.integrations.compat import doctor, check_compatibility

    report = doctor()
    print(report)

    # Or check specific pair:
    ok, msg = check_compatibility("agent-os-kernel", "2.0.2", "agentmesh-platform", "2.0.2")
"""

from __future__ import annotations

import importlib.metadata
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# Machine-readable compatibility matrix.
# Each entry maps (package_a, package_b) -> list of tested version-pair ranges.
# Format: (min_a, max_a, min_b, max_b) — all inclusive.
COMPATIBILITY_MATRIX: dict[tuple[str, str], list[tuple[str, str, str, str]]] = {
    ("agent-os-kernel", "agentmesh-platform"): [
        ("2.0.0", "2.99.99", "2.0.0", "2.99.99"),
        ("1.2.0", "1.99.99", "1.0.0", "1.99.99"),
    ],
    ("agent-os-kernel", "agent-sre"): [
        ("2.0.0", "2.99.99", "1.0.0", "1.99.99"),
    ],
    ("agent-os-kernel", "agent-governance-toolkit"): [
        ("2.0.0", "2.99.99", "1.0.0", "1.99.99"),
        ("1.0.0", "1.99.99", "1.0.0", "1.99.99"),
    ],
    ("agentmesh-platform", "agent-governance-toolkit"): [
        ("2.0.0", "2.99.99", "1.0.0", "1.99.99"),
        ("1.0.0", "1.99.99", "1.0.0", "1.99.99"),
    ],
    ("agentmesh-platform", "agent-sre"): [
        ("2.0.0", "2.99.99", "1.0.0", "1.99.99"),
    ],
}

KNOWN_PACKAGES = [
    "agent-os-kernel",
    "agentmesh-platform",
    "agent-sre",
    "agent-governance-toolkit",
    "agentmesh-runtime",
]


def _parse_version(v: str) -> tuple[int, ...]:
    """Parse a version string into a comparable tuple."""
    parts = []
    for p in v.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def _version_in_range(version: str, min_v: str, max_v: str) -> bool:
    """Check if version is within [min_v, max_v] inclusive."""
    v = _parse_version(version)
    return _parse_version(min_v) <= v <= _parse_version(max_v)


def _get_installed_version(package_name: str) -> Optional[str]:
    """Get the installed version of a package, or None if not installed."""
    try:
        return importlib.metadata.version(package_name)
    except importlib.metadata.PackageNotFoundError:
        return None


def check_compatibility(
    pkg_a: str,
    ver_a: str,
    pkg_b: str,
    ver_b: str,
) -> tuple[bool, str]:
    """Check if two package versions are in a tested-compatible range.

    Args:
        pkg_a: Name of the first package.
        ver_a: Version of the first package.
        pkg_b: Name of the second package.
        ver_b: Version of the second package.

    Returns:
        Tuple of (compatible, message). ``compatible`` is True if the
        versions fall within a known-good range, False if they are known
        to be outside tested ranges, or True with a warning if no
        compatibility data exists for the pair.
    """
    key = (pkg_a, pkg_b)
    alt_key = (pkg_b, pkg_a)

    ranges = COMPATIBILITY_MATRIX.get(key)
    if ranges is None:
        ranges = COMPATIBILITY_MATRIX.get(alt_key)
        if ranges is not None:
            # Swap versions to match the key order
            ver_a, ver_b = ver_b, ver_a

    if ranges is None:
        return True, f"No compatibility data for {pkg_a} + {pkg_b} (assumed OK)"

    for min_a, max_a, min_b, max_b in ranges:
        if _version_in_range(ver_a, min_a, max_a) and _version_in_range(
            ver_b, min_b, max_b
        ):
            return True, f"{pkg_a}=={ver_a} + {pkg_b}=={ver_b}: compatible"

    return (
        False,
        f"WARNING: {pkg_a}=={ver_a} + {pkg_b}=={ver_b} is outside tested ranges",
    )


@dataclass
class CompatReport:
    """Report from the compatibility doctor."""

    installed: dict[str, str] = field(default_factory=dict)
    not_installed: list[str] = field(default_factory=list)
    compatible_pairs: list[str] = field(default_factory=list)
    incompatible_pairs: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True if no incompatible pairs were found."""
        return len(self.incompatible_pairs) == 0

    def __str__(self) -> str:
        lines = ["=== Governance Toolkit Compatibility Report ===", ""]

        lines.append("Installed packages:")
        if self.installed:
            for pkg, ver in sorted(self.installed.items()):
                lines.append(f"  ✓ {pkg}=={ver}")
        if self.not_installed:
            for pkg in self.not_installed:
                lines.append(f"  ✗ {pkg} (not installed)")
        lines.append("")

        if self.compatible_pairs:
            lines.append("Compatible pairs:")
            for msg in self.compatible_pairs:
                lines.append(f"  ✓ {msg}")
            lines.append("")

        if self.incompatible_pairs:
            lines.append("INCOMPATIBLE pairs:")
            for msg in self.incompatible_pairs:
                lines.append(f"  ✗ {msg}")
            lines.append("")

        if self.warnings:
            lines.append("Warnings:")
            for msg in self.warnings:
                lines.append(f"  ⚠ {msg}")
            lines.append("")

        status = "OK" if self.ok else "ISSUES FOUND"
        lines.append(f"Status: {status}")
        return "\n".join(lines)


def doctor() -> CompatReport:
    """Run a full compatibility check on all installed governance packages.

    Discovers installed packages, checks every pair against the
    compatibility matrix, and returns a structured report.

    Returns:
        A ``CompatReport`` with installed versions and pair-wise results.
    """
    report = CompatReport()

    for pkg in KNOWN_PACKAGES:
        ver = _get_installed_version(pkg)
        if ver:
            report.installed[pkg] = ver
        else:
            report.not_installed.append(pkg)

    installed_list = list(report.installed.items())
    for i, (pkg_a, ver_a) in enumerate(installed_list):
        for pkg_b, ver_b in installed_list[i + 1 :]:
            ok, msg = check_compatibility(pkg_a, ver_a, pkg_b, ver_b)
            if ok:
                if "assumed" in msg:
                    report.warnings.append(msg)
                else:
                    report.compatible_pairs.append(msg)
            else:
                report.incompatible_pairs.append(msg)

    if report.incompatible_pairs:
        logger.warning(
            "Version skew detected: %d incompatible package pairs",
            len(report.incompatible_pairs),
        )

    return report


def warn_on_import() -> None:
    """Run at import time to log version skew warnings.

    Call this from a package's ``__init__.py`` to emit a warning
    if incompatible peer packages are detected.
    """
    report = doctor()
    for msg in report.incompatible_pairs:
        logger.warning(msg)
