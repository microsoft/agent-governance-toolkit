#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Flag PRs that add or modify Python ``setup.py`` or Rust ``build.rs``.

These two files execute arbitrary code at *build time*, before any code
review can intervene at runtime:

* ``setup.py`` runs as Python during ``pip install`` (and during
  ``python -m build``, ``pip wheel``, etc.). A compromised ``setup.py`` is
  the classic ``ctx``-style PyPI supply-chain attack.
* ``build.rs`` runs as Rust at ``cargo build``, ``cargo test``,
  ``cargo install``. A compromised ``build.rs`` is the ``rustdecimal``-
  style crates.io supply-chain attack.

This scanner is intentionally *coarse*: it only flags the presence of an
add or modification. It does NOT try to inspect the contents for obvious
malware — content-analysis would be a deep static-analysis project and
would produce a false-positive flood on legitimate compiled-extension
crates. Coarse detection is sufficient because the goal here is to direct
*reviewer attention*, not to make a final security determination.

Defensive contracts:

* Uses ``common.changed_manifests`` (Python-side basename filter) so a
  ``build.rs`` at the repo root is matched as well as one inside a
  subdirectory. The git-pathspec ``**/build.rs`` form alone would silently
  miss the repo-root form (this was the M2 finding).
* ``--strict`` flips warning to error (exit 1). The workflow opts in to
  strict; local developers running the script get a warning by default.
* No network access, no filesystem write — read-only inspection of the
  git diff. Safe to run on hostile PRs.

Usage::

    python scripts/check_build_hooks.py
    python scripts/check_build_hooks.py --base origin/main --strict
"""

from __future__ import annotations

import argparse
import sys

import _supply_chain_common as common

BUILD_HOOK_BASENAMES = ["setup.py", "build.rs"]


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("--base", default="origin/main",
                   help="Git ref to diff against (default: origin/main)")
    p.add_argument("--strict", action="store_true",
                   help="Treat findings as errors (exit 1). Default warns and exits 0.")
    return p


def main_with_args(argv: list[str]) -> int:
    args = _build_parser().parse_args(argv)
    paths = common.changed_manifests(args.base, BUILD_HOOK_BASENAMES)
    if not paths:
        print("OK: no setup.py or build.rs files added or modified.")
        return 0

    print(
        f"Found {len(paths)} build-hook file(s) added or modified in this PR. "
        f"These run code at build time — please review each carefully:"
    )
    for path in paths:
        print(f"  BUILD-HOOK: {path}")

    print()
    print("Build hooks are the primary payload-delivery vector for:")
    print("  - PyPI: malicious setup.py running during 'pip install'")
    print("  - crates.io: malicious build.rs running during 'cargo build'")
    print()
    print("Reviewer checklist for each file above:")
    print("  - Does the script perform network I/O?")
    print("  - Does it shell out to subprocess / Command?")
    print("  - Does it write outside the build directory?")
    print("  - Does it import code from an external URL?")
    print("  - Does it base64-decode obfuscated payloads?")
    print()
    print("If any of those are present without a clear, documented reason, ")
    print("block the PR and escalate.")
    return 1 if args.strict else 0


def main() -> int:
    return main_with_args(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
