#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Block PRs that introduce npm dependencies with install-time scripts.

Install-time scripts (``preinstall`` / ``install`` / ``postinstall``) are
the primary payload-delivery vector for npm supply-chain attacks: malware
runs *as part of* ``npm install``, before any code review or runtime check.
This scanner refuses adoption of any npm package whose latest version
declares any of those scripts unless the package is on the allow-list.

Two manifest sources are inspected:

1. ``package.json`` adds — parsed structurally via ``git show <ref>:<path>``
   and JSON-loaded at both base and HEAD. We flag pkg→ver pairs that are
   *new at HEAD* (added or version-bumped). This is immune to the
   ``++ b/<path>`` diff-line injection class because we never look at the
   raw diff stream for this surface.

2. ``package-lock.json`` / ``npm-shrinkwrap.json`` — closes the
   first-iteration bypass: a PR could ship a transitive dep only in the
   lockfile while leaving ``package.json`` untouched. We walk every entry
   in ``packages`` (npm v7+ lockfile v2/v3) and ``dependencies`` (legacy
   v1) and diff base→HEAD. Nested ``node_modules/foo/node_modules/bar``
   keys are correctly unwrapped via ``rsplit("node_modules/", 1)[-1]`` so
   the deep entry is *not* silently skipped (which was C5 in the red-team
   pass).

Defensive contracts:

* We never trust the lockfile's ``hasInstallScript`` flag as a *skip*
  signal. Attackers control lockfile contents end-to-end; the previous
  ``if hint is False: continue`` was C4 — a one-line bypass where a hostile
  PR could mark its malware package ``hasInstallScript: false`` and never
  hit the registry. We always query the registry for every new/bumped
  candidate. The lockfile's hint may be *reported* alongside the finding
  for context, but it is never used to short-circuit.
* A network failure on a *changed* dependency is fail-closed (recorded as
  a finding, returns exit 1). The previous warn-and-pass was a timing
  bypass against transient registry outages.
* A wall-clock budget (``--total-deadline-sec``, default 120) caps the
  candidate loop. Unscanned candidates after expiry become findings.
* Package and version strings are validated against strict character
  classes before being interpolated into the registry URL. All URL
  segments are also passed through ``urllib.parse.quote`` so a future
  relaxation of the regex cannot silently introduce a traversal.

Usage::

    python scripts/check_install_scripts.py
    python scripts/check_install_scripts.py --base origin/main
    python scripts/check_install_scripts.py --allow esbuild --allow puppeteer
"""

from __future__ import annotations

import argparse
import sys
from pathlib import PurePosixPath

import _supply_chain_common as common

DEFAULT_MAX_DEPS = 100
DEFAULT_DEADLINE_SEC = 120
LIFECYCLE_KEYS = ("preinstall", "install", "postinstall")
ALLOWLIST: frozenset[str] = frozenset({
    "esbuild",
    "puppeteer",
    "puppeteer-core",
    "playwright",
    "@playwright/test",
    "@playwright/browser-chromium",
    "@playwright/browser-firefox",
    "@playwright/browser-webkit",
    "node-gyp",
    "deasync",
    "node-sass",
    "sass-embedded",
})

MANIFEST_BASENAMES = ["package.json", "package-lock.json", "npm-shrinkwrap.json"]


def _basename(path: str) -> str:
    return PurePosixPath(path.replace("\\", "/")).name


# --------------------------- structural manifest extraction ---------------------------

def _extract_pkgjson_pairs(tree: dict | None) -> dict[str, str]:
    """Return the merged exact-pin dep map from a package.json.

    Range specifiers (``^``, ``~``, ``workspace:``, ``git+``, etc.) are
    filtered out — we can't verify the resolved version from the manifest
    alone, and they'll be visible in the lockfile sweep if they actually
    resolve to something new.
    """
    if not isinstance(tree, dict):
        return {}
    out: dict[str, str] = {}
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        block = tree.get(section)
        if not isinstance(block, dict):
            continue
        for name, ver in block.items():
            if not isinstance(name, str) or not isinstance(ver, str):
                continue
            ver = ver.strip()
            if not ver or any(ver.startswith(p) for p in (
                "workspace:", "file:", "link:", "git+", "github:", "http:", "https:",
                "^", "~", ">", "<", "=", "*",
            )):
                continue
            if not common.is_safe_name(name) or not common.is_safe_version(ver):
                continue
            out[name] = ver
    return out


def _unwrap_lockfile_path(key: str) -> str | None:
    """Strip nested ``node_modules/x/node_modules/y`` prefixes.

    Returns ``"y"`` from ``"node_modules/x/node_modules/y"``, ``"x"`` from
    ``"node_modules/x"``, and ``None`` for the workspace root entry
    (``""``) or unrecognised shapes. The previous ``if "/node_modules/" in
    name: continue`` was the C5 bypass — a transitive package buried at
    depth 2+ would be silently dropped.
    """
    if not key:
        return None
    if "node_modules/" not in key:
        return None
    tail = key.rsplit("node_modules/", 1)[-1]
    tail = tail.strip("/")
    if not tail:
        return None
    return tail


def _extract_lockfile_pairs(tree: dict | None) -> dict[tuple[str, str], bool | None]:
    """Return ``{(pkg, ver): hasInstallScript_hint}``.

    The hint is *informational only* — we always query the registry. It's
    reported alongside the finding so reviewers can spot lockfiles that
    declare ``hasInstallScript: false`` while the registry says otherwise
    (a strong tampering signal).
    """
    if not isinstance(tree, dict):
        return {}
    out: dict[tuple[str, str], bool | None] = {}

    # npm v7+ lockfile v2/v3
    packages = tree.get("packages")
    if isinstance(packages, dict):
        for raw_key, meta in packages.items():
            if not isinstance(raw_key, str) or not isinstance(meta, dict):
                continue
            name = _unwrap_lockfile_path(raw_key)
            if not name:
                # The root workspace entry sometimes carries a ``name`` field
                # but we don't treat the root as a candidate dep.
                continue
            ver = meta.get("version")
            if not isinstance(ver, str):
                continue
            ver = ver.strip()
            if not common.is_safe_name(name) or not common.is_safe_version(ver):
                continue
            hint = meta.get("hasInstallScript")
            hint = hint if isinstance(hint, bool) else None
            # Multiple entries can resolve to the same (name, version); keep
            # the *first* hint we see — but if we ever see a True hint,
            # surface it (defensive: don't let a later False overwrite True).
            existing = out.get((name, ver))
            if existing is True:
                continue
            out[(name, ver)] = hint

    # legacy v1
    deps = tree.get("dependencies")
    if isinstance(deps, dict):
        _walk_legacy_deps(deps, out)

    return out


def _walk_legacy_deps(node: dict, out: dict[tuple[str, str], bool | None]) -> None:
    """Recursively walk the legacy v1 ``dependencies`` tree."""
    for name, meta in node.items():
        if not isinstance(name, str) or not isinstance(meta, dict):
            continue
        ver = meta.get("version")
        if isinstance(ver, str) and common.is_safe_name(name) and common.is_safe_version(ver.strip()):
            ver = ver.strip()
            existing = out.get((name, ver))
            if existing is not True:
                out[(name, ver)] = None  # v1 doesn't carry the hint
        nested = meta.get("dependencies")
        if isinstance(nested, dict):
            _walk_legacy_deps(nested, out)


# --------------------------- candidate collection ---------------------------

def collect_candidates(base: str) -> list[tuple[str, str, bool | None, str]]:
    """Return ``(pkg, ver, hint, source_path)`` tuples for new/bumped npm deps.

    De-duplicated on ``(pkg, ver)`` so the same triplet appearing in
    multiple manifests only spends one registry call.
    """
    by_key: dict[tuple[str, str], tuple[bool | None, str]] = {}
    paths = common.changed_manifests(base, MANIFEST_BASENAMES)

    for path in paths:
        bn = _basename(path)
        if bn == "package.json":
            base_map = _extract_pkgjson_pairs(common.load_json_at(base, path))
            head_map = _extract_pkgjson_pairs(common.load_json_at("HEAD", path))
            for name, ver in head_map.items():
                if base_map.get(name) == ver:
                    continue
                if (name, ver) in by_key:
                    continue
                by_key[(name, ver)] = (None, path)
        elif bn in ("package-lock.json", "npm-shrinkwrap.json"):
            base_map = _extract_lockfile_pairs(common.load_json_at(base, path))
            head_map = _extract_lockfile_pairs(common.load_json_at("HEAD", path))
            for (name, ver), hint in head_map.items():
                if (name, ver) in base_map:
                    continue
                if (name, ver) in by_key:
                    # Prefer a more specific hint (True wins over None/False).
                    prev_hint, prev_path = by_key[(name, ver)]
                    if prev_hint is True or hint is None:
                        continue
                by_key[(name, ver)] = (hint, path)

    return [(n, v, h, p) for (n, v), (h, p) in by_key.items()]


# --------------------------- registry probe ---------------------------

def fetch_install_scripts(package: str, version: str) -> dict[str, str] | None:
    """Return the lifecycle script map for ``package@version``, or ``{}``.

    Returns ``None`` only on transient errors (timeout / 5xx / network).
    Raises ``LookupError`` on 404 (the version does not exist — typosquat
    or unpublished signal). An empty dict means the package has no
    lifecycle scripts.
    """
    if not common.is_safe_name(package) or not common.is_safe_version(version):
        raise LookupError(f"unsafe package/version syntax: {package!r}@{version!r}")
    url = f"https://registry.npmjs.org/{common.safe_url_path(package)}/{common.safe_url_path(version)}"
    data = common.fetch_json(url)
    if data is None:
        return None
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if not isinstance(scripts, dict):
        return {}
    return {k: v for k, v in scripts.items() if k in LIFECYCLE_KEYS and isinstance(v, str) and v.strip()}


# --------------------------- CLI / main ---------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("--base", default="origin/main",
                   help="Git ref to diff against (default: origin/main)")
    p.add_argument("--strict", action="store_true",
                   help="Treat findings as errors (exit 1). Default warns "
                        "and exits 0 — workflows should opt into --strict.")
    p.add_argument("--max-deps", type=int, default=DEFAULT_MAX_DEPS,
                   help=f"Refuse to inspect more than this many candidates "
                        f"(default: {DEFAULT_MAX_DEPS}). ``--max-deps 0`` "
                        f"disables the cap.")
    p.add_argument("--total-deadline-sec", type=int, default=DEFAULT_DEADLINE_SEC,
                   help=f"Wall-clock budget in seconds (default: {DEFAULT_DEADLINE_SEC}). "
                        f"Unscanned candidates after expiry become findings.")
    p.add_argument("--allow", action="append", default=[],
                   help="Package name to allow even if it has install scripts "
                        "(in addition to the built-in allow-list)")
    p.add_argument("--explicit", action="append", default=[],
                   metavar="PKG@VERSION",
                   help="Skip diff parsing and check exactly these versions")
    return p


def main_with_args(argv: list[str]) -> int:
    args = _build_parser().parse_args(argv)
    allow = set(ALLOWLIST) | {a.strip() for a in args.allow if a.strip()}

    candidates: list[tuple[str, str, bool | None, str]] = []
    if args.explicit:
        for spec in args.explicit:
            try:
                pkg, ver = spec.rsplit("@", 1)
            except ValueError:
                print(f"::error::bad --explicit spec {spec!r}, expected PKG@VERSION",
                      file=sys.stderr)
                return 2
            candidates.append((pkg, ver, None, "(explicit)"))
    else:
        candidates = collect_candidates(args.base)

    if not candidates:
        print("OK: no new npm dependencies to check for install scripts.")
        return 0

    if args.max_deps > 0 and len(candidates) > args.max_deps:
        print(
            f"::error::PR adds {len(candidates)} npm dependency candidates, "
            f"exceeding --max-deps={args.max_deps}. Refusing to scan: split the "
            "PR or pass --max-deps=N explicitly.",
            file=sys.stderr,
        )
        return 2

    deadline = common.Deadline(budget_seconds=args.total_deadline_sec)
    findings: list[str] = []
    print(
        f"Checking {len(candidates)} npm package(s) for install-time scripts "
        f"(wall-clock budget {args.total_deadline_sec}s)..."
    )
    for i, (pkg, ver, hint, source) in enumerate(candidates):
        if deadline.expired():
            common.emit_deadline_warning("check_install_scripts", deadline)
            unscanned = candidates[i:]
            for u_pkg, u_ver, _u_hint, u_src in unscanned:
                findings.append(
                    f"  DEADLINE-UNSCANNED: {u_pkg}@{u_ver} could not be verified "
                    f"before the wall-clock budget expired  [{u_src}]"
                )
            break

        if pkg in allow:
            print(f"  SKIP (allow-list): {pkg}@{ver}  [{source}]")
            continue

        if not common.is_safe_name(pkg) or not common.is_safe_version(ver):
            findings.append(
                f"  REJECTED: {pkg}@{ver} has unsafe name/version syntax  [{source}]"
            )
            continue

        try:
            scripts = fetch_install_scripts(pkg, ver)
        except LookupError as e:
            findings.append(
                f"  HARD FAIL: {pkg}@{ver} not found in npm registry — {e}  [{source}]"
            )
            continue

        if scripts is None:
            findings.append(
                f"  UNVERIFIED: {pkg}@{ver} — npm registry transient failure  [{source}]"
            )
            continue

        if scripts:
            keys = ", ".join(sorted(scripts.keys()))
            hint_note = ""
            if hint is False:
                hint_note = " (LOCKFILE LIED: hasInstallScript=false but registry disagrees)"
            elif hint is True:
                hint_note = " (lockfile hint: hasInstallScript=true)"
            findings.append(
                f"  INSTALL-SCRIPT: {pkg}@{ver} declares {keys}{hint_note}  [{source}]"
            )
        else:
            print(f"  OK: {pkg}@{ver} declares no install-time scripts")

    if findings:
        print()
        print("Install-script scan FAILED — newly-introduced npm packages run code at install time:")
        print()
        for f in findings:
            print(f)
        print()
        print("Install-time scripts (preinstall/install/postinstall) are the primary payload")
        print("delivery vector for npm supply-chain attacks. Options:")
        print("  - Pick an alternative package without install scripts.")
        print("  - If the package is well-known and trusted, add it via --allow.")
        print("  - Pin to a previous version that did not declare install scripts.")
        return 1 if args.strict else 0

    print()
    print("OK: all new npm packages are install-script-free.")
    return 0


def main() -> int:
    return main_with_args(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
