# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Single-source the Agent Governance Toolkit Python package version.

The canonical version for the ``agent-governance-toolkit-*`` / ``agentmesh_*``
family lives in ``agent-governance-python/VERSION``. This script propagates that
value into every family ``pyproject.toml`` (write mode) or verifies that none has
drifted (``--check`` mode, intended for CI).

Packages whose version does not start with the family major are skipped, which
deliberately exempts ``agt-policies`` (5.x) and the ACS line
(``agent-control-specification`` / ``acs-generator`` at 0.3.x, which live under
``policy-engine/`` and are not scanned here at all).

Usage::

    python scripts/sync_version.py            # rewrite each family pyproject file to VERSION
    python scripts/sync_version.py --check     # fail if any family pyproject drifted
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

VERSION_RE = re.compile(r'(?m)^(version\s*=\s*)"([^"]*)"')

# In every family pyproject.toml the project version is the first ``version =``
# key (under ``[project]``), so ``count=1`` in the substitution below rewrites
# only that key and never a coincidental ``version`` in a later tool table.

# Directory holding VERSION and the family pyproject.toml files.
ROOT = Path(__file__).resolve().parent.parent


def read_canonical_version() -> str:
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if not version:
        raise SystemExit("VERSION file is empty")
    return version


def family_major(version: str) -> str:
    return version.split(".", 1)[0]


def iter_pyproject_files() -> list[Path]:
    return sorted(p for p in ROOT.rglob("pyproject.toml") if p.is_file())


def current_version(text: str) -> str | None:
    match = VERSION_RE.search(text)
    return match.group(2) if match else None


def sync(check_only: bool) -> int:
    canonical = read_canonical_version()
    major = family_major(canonical)
    drifted: list[tuple[Path, str]] = []
    rewritten: list[Path] = []

    for pyproject in iter_pyproject_files():
        text = pyproject.read_text(encoding="utf-8")
        version = current_version(text)
        # Only manage the version-aligned family; skip packages on a different
        # major line (agt-policies 5.x) and anything without a static version.
        if version is None or family_major(version) != major:
            continue
        if version == canonical:
            continue
        rel = pyproject.relative_to(ROOT)
        if check_only:
            drifted.append((rel, version))
        else:
            new_text = VERSION_RE.sub(
                lambda m: f'{m.group(1)}"{canonical}"', text, count=1
            )
            pyproject.write_text(new_text, encoding="utf-8")
            rewritten.append(rel)

    if check_only:
        if drifted:
            print(f"Version drift detected (canonical {canonical}):")
            for rel, version in drifted:
                print(f"  {rel}: {version}")
            print("Run: python scripts/sync_version.py")
            return 1
        print(f"All family pyproject.toml files match VERSION {canonical}.")
        return 0

    if rewritten:
        print(f"Updated {len(rewritten)} pyproject.toml files to {canonical}:")
        for rel in rewritten:
            print(f"  {rel}")
    else:
        print(f"No changes; family already at {canonical}.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify pyproject versions match VERSION instead of rewriting",
    )
    args = parser.parse_args()
    return sync(check_only=args.check)


if __name__ == "__main__":
    sys.exit(main())
