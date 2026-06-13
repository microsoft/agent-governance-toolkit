#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Block PRs that adopt freshly-published dependency versions.

Defends against the *new-release* class of supply-chain attacks where a
compromised maintainer or hijacked publishing key ships a malicious version
that ecosystem responders typically catch and yank within a week. By
refusing to adopt a version that is less than N days old (default 7), we
let the broader community absorb the first-discovery shock before AGT pulls
the version into its own dependency tree. This rule is *not* sufficient
defense by itself; it composes with ``check_install_scripts.py`` (payload
delivery), the Birsan dependency-confusion allow-list (typosquats), and the
trip-wire guard in ``supply-chain-check.yml`` (the scanner-modifying-PR
class).

Manifest sources are parsed *structurally*, not via diff-line regex:

* ``package.json`` — loaded as JSON via ``git show <ref>:<path>`` at both
  the base and HEAD ref, then resolved dep maps are compared. This is
  immune to the ``++ b/<path>`` diff-injection class (where a triple-quoted
  string in another file confuses a diff-line parser into re-attributing
  the current file).
* ``Cargo.toml`` and ``pyproject.toml`` — parsed via stdlib ``tomllib``,
  which correctly handles multi-line tables like
  ``[dependencies.foo]\\nversion="x"``. This was the H2 finding from the
  red-team pass.
* ``requirements*.txt`` — line-oriented format, so we still consume added
  lines via ``diff_lines_added`` (which uses a hardened header detector
  that rejects the ``++ b/`` injection class structurally).

Only exact-pin versions are checked. Range specifiers (``^1.0``, ``>=1.0``)
are intentionally skipped — those are caught by the ``check-version-pinning``
job in ``supply-chain-check.yml`` at the manifest level.

Defensive contracts:

* A network failure on a *changed* dependency is fail-closed (logged as a
  finding, returns exit 1). The previous warn-then-pass behavior allowed an
  attacker to time their PR for a registry outage. The only fail-open case
  is "the package isn't even a candidate" — i.e., the version string
  doesn't parse as exact-pin, so we never queried the registry.
* A 404 from the registry — the version does not exist — is treated as a
  hard failure because it's a strong typosquat / dep-confusion signal.
* A wall-clock budget (``--total-deadline-sec``, default 120) caps the
  whole candidate loop. When the budget is exhausted, *unscanned* candidates
  become findings — never silently dropped.
* Package and version strings are validated against strict character
  classes before being interpolated into any registry URL. Even after
  parsing, every URL segment is double-encoded via ``urllib.parse.quote``
  so that a future regex relaxation cannot silently introduce a path
  traversal.
* npm uses the per-version endpoint (``/{pkg}/{ver}``) rather than the full
  packument so a hostile mirror cannot OOM the runner with a megabyte
  ``time`` map.

Usage::

    python scripts/check_release_age.py
    python scripts/check_release_age.py --base origin/release/v3.2
    python scripts/check_release_age.py --min-age-days 14
    python scripts/check_release_age.py --allow requests==2.32.0
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath

import _supply_chain_common as common

DEFAULT_MAX_DEPS = 50
DEFAULT_DEADLINE_SEC = 120
MANIFEST_BASENAMES = [
    "package.json",
    "Cargo.toml",
    "pyproject.toml",
    "requirements*.txt",
]
LINE_ORIENTED_BASENAMES = ("requirements",)  # files inside requirements/ dirs too


def _basename(path: str) -> str:
    return PurePosixPath(path.replace("\\", "/")).name


def _is_requirements_path(path: str) -> bool:
    p = PurePosixPath(path.replace("\\", "/"))
    if p.suffix != ".txt":
        return False
    if p.name.startswith("requirements"):
        return True
    return any(part == "requirements" for part in p.parts)


# --------------------------- structural parsers ---------------------------

def _resolve_pkgjson_deps(tree: dict | None) -> dict[str, str]:
    """Return the merged dep map (name → exact-pin version) from a package.json.

    Range specifiers (^, ~, workspace:, file:, git+) are filtered out here so
    they never become candidates. The caller compares base→HEAD maps to find
    additions and version bumps; entries unchanged in version are skipped.
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
            if not ver:
                continue
            if any(ver.startswith(p) for p in (
                "workspace:", "file:", "link:", "git+", "github:", "http:", "https:",
                "^", "~", ">", "<", "=", "*",
            )):
                continue
            if not common.is_safe_name(name) or not common.is_safe_version(ver):
                continue
            out[name] = ver
    return out


def _resolve_cargo_deps(tree: dict | None) -> dict[str, str]:
    """Return the merged dep map from a Cargo.toml's ``[dependencies]`` table.

    Handles both forms parsed by tomllib:

    * ``serde = "1.0.228"`` — value is a string → use it directly.
    * ``[dependencies.tokio]`` / ``tokio = { version = "1.40", ... }`` — value
      is a table → look up ``version``.

    Workspace inheritance (``foo = { workspace = true }``) is skipped: the
    actual version is pinned in the root workspace Cargo.toml, which we'll
    also see if it changed.
    """
    if not isinstance(tree, dict):
        return {}
    out: dict[str, str] = {}
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        block = tree.get(section)
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            if not isinstance(name, str):
                continue
            ver: str | None = None
            if isinstance(spec, str):
                ver = spec.strip()
            elif isinstance(spec, dict):
                if spec.get("workspace") is True:
                    continue
                raw = spec.get("version")
                if isinstance(raw, str):
                    ver = raw.strip()
            if not ver:
                continue
            # Cargo allows ^1.0 as the implicit form; only treat as exact-pin
            # when it strictly looks like a pin (no ^ ~ >= <= * inside).
            if any(c in ver for c in ("^", "~", ">", "<", "*", " ", ",")):
                continue
            if not common.is_safe_name(name) or not common.is_safe_version(ver):
                continue
            out[name] = ver
    return out


def _resolve_pyproject_deps(tree: dict | None) -> dict[str, str]:
    """Return exact-pin (==) deps from a pyproject.toml.

    Walks ``[project].dependencies``, ``[project].optional-dependencies.*``,
    and ``[tool.poetry.dependencies]``. Range specifiers (``>=``, ``~=``,
    ``^``) and markers are dropped — only ``name==X.Y.Z`` style entries
    become candidates.
    """
    if not isinstance(tree, dict):
        return {}
    out: dict[str, str] = {}

    project = tree.get("project")
    if isinstance(project, dict):
        for entry in (project.get("dependencies") or []):
            if isinstance(entry, str):
                _add_pep508_pin(entry, out)
        opt = project.get("optional-dependencies")
        if isinstance(opt, dict):
            for group in opt.values():
                if isinstance(group, list):
                    for entry in group:
                        if isinstance(entry, str):
                            _add_pep508_pin(entry, out)

    tool = tree.get("tool")
    if isinstance(tool, dict):
        poetry = tool.get("poetry")
        if isinstance(poetry, dict):
            deps = poetry.get("dependencies")
            if isinstance(deps, dict):
                for name, spec in deps.items():
                    if not isinstance(name, str):
                        continue
                    ver: str | None = None
                    if isinstance(spec, str):
                        ver = spec.strip()
                    elif isinstance(spec, dict):
                        raw = spec.get("version")
                        if isinstance(raw, str):
                            ver = raw.strip()
                    if not ver:
                        continue
                    # Strip a single leading == to allow poetry's "==1.0.0".
                    if ver.startswith("=="):
                        ver = ver[2:].strip()
                    if any(c in ver for c in ("^", "~", ">", "<", "*", " ", ",")):
                        continue
                    if not common.is_safe_name(name) or not common.is_safe_version(ver):
                        continue
                    out[name] = ver
    return out


def _add_pep508_pin(entry: str, out: dict[str, str]) -> None:
    """If ``entry`` looks like ``name==version[;marker]``, record it."""
    # Split off any environment marker.
    spec = entry.split(";", 1)[0].strip()
    if "==" not in spec:
        return
    name, _, ver = spec.partition("==")
    name = name.strip().split("[", 1)[0].strip()  # drop extras like "foo[bar]"
    # If there are any range operators or whitespace in `ver`, this is a
    # compound spec (e.g. "name==1.0,>=0.9"); drop it.
    ver = ver.strip()
    if not ver or any(c in ver for c in ("<", ">", " ", ",")):
        return
    if not common.is_safe_name(name) or not common.is_safe_version(ver):
        return
    out[name] = ver


def _parse_requirements_added_line(line: str) -> tuple[str, str] | None:
    """Return (name, version) from a ``name==X.Y.Z`` line, or None.

    Comments, environment markers, and extras are stripped. Any line that
    contains range operators (``>=``, ``<``, ``~=``, ``!=``, etc.) is
    rejected because those aren't exact pins.
    """
    s = line.strip()
    if not s or s.startswith("#") or s.startswith("-"):
        return None
    # Strip trailing comment and environment marker.
    s = s.split("#", 1)[0].split(";", 1)[0].strip()
    if "==" not in s:
        return None
    name, _, ver = s.partition("==")
    name = name.strip().split("[", 1)[0].strip()
    ver = ver.strip()
    if any(op in ver for op in ("<", ">", "~", "!", " ", ",")):
        return None
    if not common.is_safe_name(name) or not common.is_safe_version(ver):
        return None
    return name, ver


# --------------------------- candidate collection ---------------------------

def collect_candidates(base: str) -> list[tuple[str, str, str, str]]:
    """Return ``(ecosystem, package, version, source_path)`` tuples.

    Each tuple is a *change* (new pin or version bump). Versions unchanged
    between base and HEAD are filtered out at the structural-diff level.
    The list is de-duplicated on ``(ecosystem, package, version)`` so the
    same dep declared in multiple manifests only spends one registry call.
    """
    candidates: list[tuple[str, str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    paths = common.changed_manifests(base, MANIFEST_BASENAMES)
    for path in paths:
        bn = _basename(path)
        if bn == "package.json":
            base_map = _resolve_pkgjson_deps(common.load_json_at(base, path))
            head_map = _resolve_pkgjson_deps(common.load_json_at("HEAD", path))
            for name, ver in head_map.items():
                if base_map.get(name) == ver:
                    continue
                key = ("npm", name, ver)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append((*key, path))
        elif bn == "Cargo.toml":
            base_map = _resolve_cargo_deps(common.load_toml_at(base, path))
            head_map = _resolve_cargo_deps(common.load_toml_at("HEAD", path))
            for name, ver in head_map.items():
                if base_map.get(name) == ver:
                    continue
                key = ("cargo", name, ver)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append((*key, path))
        elif bn == "pyproject.toml":
            base_map = _resolve_pyproject_deps(common.load_toml_at(base, path))
            head_map = _resolve_pyproject_deps(common.load_toml_at("HEAD", path))
            for name, ver in head_map.items():
                if base_map.get(name) == ver:
                    continue
                key = ("pypi", name, ver)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append((*key, path))

    # requirements files: line-oriented, so we still consume added lines
    # through the hardened diff_lines_added helper.
    req_paths = [p for p in paths if _is_requirements_path(p)]
    for path, added in common.diff_lines_added(base, req_paths):
        parsed = _parse_requirements_added_line(added)
        if not parsed:
            continue
        name, ver = parsed
        key = ("pypi", name, ver)
        if key in seen:
            continue
        seen.add(key)
        candidates.append((*key, path))

    return candidates


# --------------------------- registry fetchers ---------------------------

def fetch_release_time(ecosystem: str, package: str, version: str) -> datetime | None:
    """Return the release timestamp as a UTC datetime, or ``None`` on transient failure.

    Raises ``LookupError`` when the registry returns 404 (a real signal: the
    package or version does not exist — possible typosquat or unpublished
    version). Both ``package`` and ``version`` MUST already be validated by
    ``common.is_safe_name`` / ``common.is_safe_version``.
    """
    if not common.is_safe_name(package) or not common.is_safe_version(version):
        raise LookupError(f"unsafe package/version syntax: {package!r}@{version!r}")

    if ecosystem == "pypi":
        url = f"https://pypi.org/pypi/{common.safe_url_path(package)}/{common.safe_url_path(version)}/json"
        data = common.fetch_json(url)
        if data is None:
            return None
        urls = data.get("urls") or []
        if urls:
            stamp = urls[0].get("upload_time_iso_8601") or urls[0].get("upload_time")
        else:
            releases = (data.get("releases") or {}).get(version) or []
            if not releases:
                raise LookupError(f"PyPI has no files for {package}=={version}")
            stamp = releases[0].get("upload_time_iso_8601") or releases[0].get("upload_time")
        return _parse_iso(stamp)

    if ecosystem == "npm":
        # Per-version endpoint, NOT the full packument: a hostile mirror
        # cannot OOM us with a multi-MB ``time`` map this way.
        url = f"https://registry.npmjs.org/{common.safe_url_path(package)}/{common.safe_url_path(version)}"
        data = common.fetch_json(url)
        if data is None:
            return None
        # The per-version endpoint embeds ``time`` only on some mirrors; the
        # canonical signal is the version doc itself with a top-level
        # ``time`` field on the parent (which we don't fetch). When the
        # per-version doc doesn't carry a timestamp, fall back to the
        # packument's ``time`` map — bounded by MAX_RESPONSE_BYTES.
        stamp = data.get("time") if isinstance(data.get("time"), str) else None
        if stamp:
            return _parse_iso(stamp)
        # Fall back: packument with bounded read.
        packument_url = f"https://registry.npmjs.org/{common.safe_url_path(package)}"
        pack = common.fetch_json(packument_url)
        if pack is None:
            return None
        times = pack.get("time") or {}
        stamp = times.get(version) if isinstance(times, dict) else None
        if not stamp:
            raise LookupError(f"npm has no release timestamp for {package}@{version}")
        return _parse_iso(stamp)

    if ecosystem == "cargo":
        url = (
            f"https://crates.io/api/v1/crates/"
            f"{common.safe_url_path(package)}/{common.safe_url_path(version)}"
        )
        data = common.fetch_json(url)
        if data is None:
            return None
        ver = data.get("version") or {}
        stamp = ver.get("created_at") if isinstance(ver, dict) else None
        if not stamp:
            raise LookupError(f"crates.io has no release timestamp for {package}@{version}")
        return _parse_iso(stamp)

    return None


def _parse_iso(stamp: str | None) -> datetime | None:
    if not isinstance(stamp, str) or not stamp:
        return None
    s = stamp.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# --------------------------- CLI / main ---------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("--base", default="origin/main",
                   help="Git ref to diff against (default: origin/main)")
    p.add_argument("--min-age-days", type=int, default=7,
                   help="Minimum release age in days (default: 7)")
    p.add_argument("--max-deps", type=int, default=DEFAULT_MAX_DEPS,
                   help=f"Refuse to inspect more than this many candidates "
                        f"(default: {DEFAULT_MAX_DEPS}). A larger PR should be "
                        f"split or reviewed manually. ``--max-deps 0`` disables "
                        f"the cap entirely (use only for explicit batch overrides).")
    p.add_argument("--total-deadline-sec", type=int, default=DEFAULT_DEADLINE_SEC,
                   help=f"Wall-clock budget in seconds for the candidate loop "
                        f"(default: {DEFAULT_DEADLINE_SEC}). When exhausted, "
                        f"unscanned candidates become findings (fail-closed). "
                        f"``0`` disables the budget.")
    p.add_argument("--allow", action="append", default=[],
                   metavar="PKG==VERSION",
                   help="Allow a specific pkg==version to bypass the age check")
    p.add_argument("--explicit", action="append", default=[],
                   metavar="ECO:PKG@VERSION",
                   help="Skip diff parsing and check exactly these versions "
                        "(for tests/manual use)")
    return p


def main_with_args(argv: list[str]) -> int:
    args = _build_parser().parse_args(argv)
    allow_set = {a.strip() for a in args.allow}
    threshold = timedelta(days=args.min_age_days)
    now = datetime.now(timezone.utc)

    candidates: list[tuple[str, str, str, str]] = []
    if args.explicit:
        for spec in args.explicit:
            try:
                eco, rest = spec.split(":", 1)
                pkg, ver = rest.rsplit("@", 1)
            except ValueError:
                print(
                    f"::error::bad --explicit spec {spec!r}, expected ECO:PKG@VERSION",
                    file=sys.stderr,
                )
                return 2
            candidates.append((eco, pkg, ver, "(explicit)"))
    else:
        candidates = collect_candidates(args.base)

    if not candidates:
        print("OK: no exact-pinned dependency additions or bumps to check.")
        return 0

    if args.max_deps > 0 and len(candidates) > args.max_deps:
        print(
            f"::error::PR adds {len(candidates)} pinned dependency candidates, "
            f"exceeding --max-deps={args.max_deps}. Refusing to scan: a PR this "
            "large should be broken up or reviewed manually. Override with "
            "--max-deps=N if you genuinely need to ship a bigger bump.",
            file=sys.stderr,
        )
        return 2

    deadline = common.Deadline(budget_seconds=args.total_deadline_sec)
    findings: list[str] = []
    print(
        f"Checking {len(candidates)} dependency version(s) against "
        f"{args.min_age_days}-day cooling-off rule "
        f"(wall-clock budget {args.total_deadline_sec}s)..."
    )
    for i, (eco, pkg, ver, source) in enumerate(candidates):
        if deadline.expired():
            common.emit_deadline_warning("check_release_age", deadline)
            unscanned = candidates[i:]
            for u_eco, u_pkg, u_ver, u_src in unscanned:
                findings.append(
                    f"  DEADLINE-UNSCANNED: {u_eco} {u_pkg}@{u_ver} could not be "
                    f"verified before the wall-clock budget expired  [{u_src}]"
                )
            break

        spec = f"{pkg}=={ver}" if eco == "pypi" else f"{pkg}@{ver}"
        if spec in allow_set:
            print(f"  SKIP (allow-list): {eco} {spec}  [{source}]")
            continue

        if not common.is_safe_name(pkg) or not common.is_safe_version(ver):
            findings.append(
                f"  REJECTED: {eco} {pkg}@{ver} has unsafe name/version syntax  [{source}]"
            )
            continue

        try:
            released = fetch_release_time(eco, pkg, ver)
        except LookupError as e:
            findings.append(
                f"  HARD FAIL: {eco} {spec} not found in registry — {e}  [{source}]"
            )
            continue

        if released is None:
            # Fail-closed: a transient registry failure on a *changed* dep
            # cannot be ignored. If the run was retried in 5 minutes and the
            # registry was back, the check would run; this is the "we tried,
            # we still don't know" case, which an attacker could exploit.
            findings.append(
                f"  UNVERIFIED: {eco} {spec} — registry transient failure, "
                f"retry the run or wait for the registry to recover  [{source}]"
            )
            continue

        age = now - released
        if age < threshold:
            findings.append(
                f"  TOO FRESH: {eco} {spec} released {released.isoformat()} "
                f"({age.days}d {age.seconds // 3600}h ago, threshold "
                f"{args.min_age_days}d)  [{source}]"
            )
        else:
            print(f"  OK: {eco} {spec} released {released.date()} ({age.days}d ago)")

    if findings:
        print()
        print("Supply-chain check FAILED — newly-published or unverifiable versions detected:")
        print()
        for f in findings:
            print(f)
        print()
        print("This rule (copilot-instructions.md > Supply Chain Security > Version Selection)")
        print("blocks adoption of releases under the cooling-off threshold to defend against")
        print("compromised-maintainer attacks.")
        print()
        print("Options:")
        print(f"  - Wait until the version is at least {args.min_age_days} days old.")
        print("  - Pin to the previous stable release.")
        print("  - If urgent and the release is verified safe, bypass with:")
        print("      --allow PKG==VERSION  (PyPI)  or  --allow PKG@VERSION  (npm/cargo)")
        return 1

    print()
    print("OK: all newly-pinned versions satisfy the cooling-off rule.")
    return 0


def main() -> int:
    return main_with_args(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
