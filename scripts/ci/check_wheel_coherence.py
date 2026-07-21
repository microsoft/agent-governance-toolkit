#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Fail if two built wheels install the same top-level import path.

Two AGT distributions that both ship, say, a ``hypervisor/`` package write to
the same ``site-packages`` path. Whichever wheel is installed second silently
overwrites the first, so a clean install becomes order- and version-dependent
(the "Frankenstein install"). This is exactly the defect that occurred when the
``agent-governance-toolkit-core`` meta wheel force-included sibling source that
the standalone stub wheels *also* shipped.

This scanner inspects the contents of every ``.whl`` under the given paths,
maps each top-level import name to the set of wheels that ship it, and exits
non-zero if any top-level name is shipped by more than one wheel. It is the CI
gate that keeps the standalone deprecation stubs dep-only: if a future change
re-adds ``packages = ["src/..."]`` to a stub, that stub's wheel will ship a
module ``-core`` already owns and this check fails.

Usage::

    python scripts/ci/check_wheel_coherence.py dist/            # scan a dir
    python scripts/ci/check_wheel_coherence.py a.whl b.whl ...  # scan wheels

Exit codes: ``0`` coherent, ``1`` collision detected or no wheels found.
"""

from __future__ import annotations

import argparse
import sys
import zipfile
from collections import defaultdict
from pathlib import Path

# Of a wheel's ``*.data/<category>/`` trees, only these land in site-packages
# (and can therefore collide on import); scripts/headers/data do not.
_IMPORTABLE_DATA_CATEGORIES = ("purelib", "platlib")
# A single top-level file is importable only if it is a module file; its import
# name is the part before the first dot (``foo.py`` -> ``foo``,
# ``foo.cpython-311-x86_64-linux-gnu.so`` -> ``foo``).
_MODULE_FILE_SUFFIXES = (".py", ".so", ".pyd")


def _wheel_dist_name(wheel: Path) -> str:
    """Return the distribution name encoded in a wheel filename.

    ``agent_hypervisor-5.0.0-py3-none-any.whl`` -> ``agent_hypervisor``.
    """
    return wheel.name.split("-", 1)[0]


def _import_top_level(rel_path: str) -> str | None:
    """Map a site-packages-relative path to the top-level import name it creates.

    Returns ``None`` for paths that are not importable (a bare data file). A path
    inside a directory yields that directory (regular and PEP 420 namespace
    packages); a bare top-level file yields its module name only when it is a
    module file, so ``foo.py`` and ``foo/`` both resolve to ``foo`` and collide.
    """
    head, sep, _ = rel_path.partition("/")
    if not head:
        return None
    if sep:
        return head
    for suffix in _MODULE_FILE_SUFFIXES:
        if head.endswith(suffix):
            return head.split(".", 1)[0]
    return None


def top_level_names(wheel: Path) -> set[str]:
    """Return the set of top-level import names a wheel installs.

    Mirrors what pip unpacks into ``site-packages``: package directories and
    top-level module files at the wheel root, plus the ``purelib``/``platlib``
    subtrees of ``*.data/`` (which pip relocates into site-packages).
    ``*.dist-info/`` and the non-importable ``*.data`` categories are ignored.
    """
    names: set[str] = set()
    with zipfile.ZipFile(wheel) as zf:
        for entry in zf.namelist():
            head = entry.split("/", 1)[0]
            if head.endswith(".dist-info"):
                continue
            if head.endswith(".data"):
                # <name>-<ver>.data/<category>/<rest>
                parts = entry.split("/", 2)
                if len(parts) < 3 or parts[1] not in _IMPORTABLE_DATA_CATEGORIES:
                    continue
                name = _import_top_level(parts[2])
            else:
                name = _import_top_level(entry)
            if name:
                names.add(name)
    return names


def collect_wheels(paths: list[str]) -> list[Path]:
    wheels: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            wheels.extend(sorted(p.glob("*.whl")))
        elif p.suffix == ".whl" and p.is_file():
            wheels.append(p)
        else:
            print(f"::warning::ignoring non-wheel path {p}", file=sys.stderr)
    return wheels


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "paths",
        nargs="+",
        help="Wheel files and/or directories containing wheels to check.",
    )
    args = parser.parse_args(argv)

    wheels = collect_wheels(args.paths)
    if not wheels:
        print("::error::no wheels found to check", file=sys.stderr)
        return 1

    owners: dict[str, set[str]] = defaultdict(set)
    for wheel in wheels:
        dist = _wheel_dist_name(wheel)
        tops = top_level_names(wheel)
        if tops:
            for name in tops:
                owners[name].add(dist)
        else:
            print(f"  {dist}: dep-only wheel (ships no top-level module)")

    collisions = {name: sorted(dists) for name, dists in owners.items() if len(dists) > 1}

    print("\nTop-level module ownership:")
    for name in sorted(owners):
        print(f"  {name:24s} <- {', '.join(sorted(owners[name]))}")

    if collisions:
        print("\n::error::top-level import paths shipped by more than one wheel:", file=sys.stderr)
        for name, dists in sorted(collisions.items()):
            print(f"::error::  {name} shipped by {', '.join(dists)}", file=sys.stderr)
        print(
            "\nEach top-level module must be owned by exactly one distribution. "
            "Standalone deprecation stubs must stay dep-only (no packages / "
            "bypass-selection) and let agent-governance-toolkit-core own the source.",
            file=sys.stderr,
        )
        return 1

    print(f"\nOK: {len(wheels)} wheel(s) form a coherent set — no top-level module collisions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
