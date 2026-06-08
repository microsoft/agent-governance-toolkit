#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""OSSF Scorecard check for new direct dependencies introduced by a PR.

For each NEW direct dependency added by a PR (npm package.json, Python
pyproject.toml, Cargo Cargo.toml), resolve the project's source repository
via registry metadata, query the hosted OSSF Scorecard API, and warn if the
score is below a configurable threshold (default 5.0).

Scope:
    * Direct dependencies only (not transitive).
    * Only newly added names (version bumps of existing deps are ignored).
    * Only GitHub-hosted source repositories are scored; other VCS hosts and
      Scorecard-untracked projects yield neutral notices, never failures.

Default behaviour is warn-only (``::warning::`` annotations, exit 0). Pass
``--strict`` to exit 1 when any new direct dep falls below the threshold.

Network: queries are limited to the Scorecard API plus the three fixed
registry hosts (registry.npmjs.org, pypi.org, crates.io). Every resolved
repository URL is validated against a strict ``https://github.com/<owner>/<repo>``
regex before being embedded into the Scorecard API URL. HTTP redirects are
NOT followed (defense-in-depth against a compromised registry redirecting
the runner at an internal endpoint).

Trust model: this check runs from the PR's own checkout under a
``pull_request`` trigger with ``contents: read`` and no secrets. A malicious
PR can no-op this script — the check is therefore advisory, and reviewers
must inspect changes to this file and its workflow before approving.

Privacy: every newly added dep name is queried against the public registry.
For private repos, use ``--skip-pattern`` to exclude internal scopes (e.g.
``--skip-pattern '^@myorg/'``) and avoid leaking internal package names.

Usage:
    python scripts/check_dependency_scorecard.py \
        --base-ref origin/main --head-ref HEAD \
        [--min-score 5.0] [--max-deps 50] [--strict] \
        [--skip-pattern '^@internal/']
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable
from urllib.parse import urlparse

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python <3.11 fallback
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:  # pragma: no cover
        tomllib = None  # type: ignore[assignment]

# --- Constants ---------------------------------------------------------------

DEFAULT_MIN_SCORE = 5.0
DEFAULT_MAX_DEPS = 50
DEFAULT_BASE_REF = "origin/main"
DEFAULT_HEAD_REF = "HEAD"

EXIT_OK = 0
EXIT_STRICT_FAIL = 1
EXIT_OVERFLOW = 2
EXIT_USAGE = 3

SCORECARD_API_BASE = "https://api.securityscorecards.dev/projects/github.com"

# Strict pattern for github.com/<owner>/<repo> URLs. Owner and repo names are
# restricted to safe characters (alphanumerics, dash, underscore, dot) and a
# bounded length. This is the SSRF gate: the resolved URL is matched against
# this regex BEFORE being embedded into the Scorecard API URL.
_GH_OWNER = r"[A-Za-z0-9][A-Za-z0-9-]{0,38}"
_GH_REPO = r"[A-Za-z0-9._-]{1,100}"
GITHUB_REPO_RE = re.compile(
    rf"^https://github\.com/(?P<owner>{_GH_OWNER})/(?P<repo>{_GH_REPO})/?$"
)

# Cap response sizes to keep memory bounded for hostile registries.
MAX_RESPONSE_BYTES = 2_000_000

# Bounded npm package name: matches the npm spec (lowercase, dot, dash,
# underscore, optional @scope/). Used both to reject malicious diff input
# and to safely build registry URLs.
_NPM_BASIC = r"[a-z0-9][a-z0-9._-]{0,213}"
NPM_NAME_RE = re.compile(rf"^(?:@{_NPM_BASIC}/)?{_NPM_BASIC}$")

# PyPI normalized names (PEP 503-ish, kept simple and safe).
PYPI_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")

# crates.io names.
CRATE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$")


# --- Data classes ------------------------------------------------------------


@dataclass
class NewDep:
    """A newly added direct dependency."""

    ecosystem: str  # "npm" | "pypi" | "cargo"
    name: str
    file: str  # manifest path the dep was added to


@dataclass
class ScoreResult:
    """Outcome of scoring a single new dep."""

    dep: NewDep
    repo_url: str | None = None
    score: float | None = None
    checks: list[dict[str, Any]] = field(default_factory=list)
    status: str = "unknown"  # "below" | "above" | "untracked" | "no-repo" | "error"
    message: str = ""


# --- Diff helpers ------------------------------------------------------------


def _run_git(args: list[str]) -> str:
    """Run ``git`` with the given args and return stdout (text)."""
    # No shell=True; args list only; tight cwd inheritance.
    result = subprocess.run(
        ["git", *args], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed (exit {result.returncode}): "
            f"{result.stderr.strip()}"
        )
    return result.stdout


def changed_manifests(
    base_ref: str,
    head_ref: str,
    runner: Callable[[list[str]], str] = _run_git,
) -> list[str]:
    """Return manifest paths that changed between base_ref and head_ref."""
    out = runner(["diff", "--name-only", f"{base_ref}...{head_ref}"])
    paths: list[str] = []
    for line in out.splitlines():
        p = line.strip()
        if not p:
            continue
        if p.endswith(("package.json", "Cargo.toml", "pyproject.toml")):
            paths.append(p)
    return paths


def _read_blob(
    ref: str,
    path: str,
    runner: Callable[[list[str]], str] = _run_git,
) -> str | None:
    """Return contents of ``path`` at ``ref`` or None if missing at that ref."""
    try:
        return runner(["show", f"{ref}:{path}"])
    except RuntimeError:
        return None


# --- Manifest parsers --------------------------------------------------------


def parse_npm_direct_deps(text: str) -> set[str]:
    """Direct dep names from a package.json.

    Includes ``dependencies``, ``devDependencies``, and ``optionalDependencies``
    — all three trigger install-time code execution via npm lifecycle scripts.
    ``peerDependencies`` is intentionally excluded (not installed by npm).
    """
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return set()
    out: set[str] = set()
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        block = data.get(section) or {}
        if not isinstance(block, dict):
            continue
        for name in block.keys():
            if isinstance(name, str) and NPM_NAME_RE.match(name):
                out.add(name)
    return out


def parse_pyproject_direct_deps(text: str) -> set[str]:
    """Direct dep names from a pyproject.toml.

    Includes:
      * ``[build-system].requires`` — executed by pip in a PEP 517 build env
      * ``[project].dependencies`` and ``[project.optional-dependencies]``
      * ``[dependency-groups]`` (PEP 735)
      * ``[tool.poetry.dependencies]`` and ``[tool.poetry.group.*.dependencies]``
    """
    if tomllib is None:  # pragma: no cover
        return set()
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return set()
    out: set[str] = set()

    # [build-system].requires — runs at install time via pip's build backend.
    build_system = data.get("build-system") or {}
    if isinstance(build_system, dict):
        for entry in build_system.get("requires") or []:
            name = _pep508_name(entry)
            if name:
                out.add(name)

    project = data.get("project") or {}
    if isinstance(project, dict):
        for entry in project.get("dependencies") or []:
            name = _pep508_name(entry)
            if name:
                out.add(name)
        optional = project.get("optional-dependencies") or {}
        if isinstance(optional, dict):
            for group in optional.values():
                for entry in group or []:
                    name = _pep508_name(entry)
                    if name:
                        out.add(name)

    # PEP 735 dependency groups.
    dep_groups = data.get("dependency-groups") or {}
    if isinstance(dep_groups, dict):
        for group in dep_groups.values():
            for entry in group or []:
                # Entries can be strings or {include-group = "..."} mappings;
                # ignore the latter — it just references another group.
                name = _pep508_name(entry)
                if name:
                    out.add(name)

    # Poetry-style sections (kept for parity with how some org repos pin).
    tool = data.get("tool") or {}
    poetry = tool.get("poetry") if isinstance(tool, dict) else None
    if isinstance(poetry, dict):
        for name in (poetry.get("dependencies") or {}).keys():
            if isinstance(name, str) and name != "python" and PYPI_NAME_RE.match(name):
                out.add(name)
        groups = poetry.get("group") or {}
        if isinstance(groups, dict):
            for grp in groups.values():
                if not isinstance(grp, dict):
                    continue
                for name in (grp.get("dependencies") or {}).keys():
                    if isinstance(name, str) and PYPI_NAME_RE.match(name):
                        out.add(name)
    return out


def _pep508_name(entry: Any) -> str | None:
    """Extract the bare distribution name from a PEP 508 requirement string."""
    if not isinstance(entry, str):
        return None
    # Strip environment markers, extras, version specifiers, whitespace.
    head = re.split(r"[\s;\[<>=!~]", entry.strip(), maxsplit=1)[0]
    head = head.strip()
    if PYPI_NAME_RE.match(head):
        return head
    return None


def parse_cargo_direct_deps(text: str) -> set[str]:
    """Direct dep names from a Cargo.toml.

    Includes ``[dependencies]``, ``[dev-dependencies]``, and
    ``[build-dependencies]`` (the latter drives ``build.rs``, which compiles
    and runs at build time). Also walks ``[target.<cfg>.dependencies]`` and
    ``[target.<cfg>.build-dependencies]`` for cfg-gated entries.
    """
    if tomllib is None:  # pragma: no cover
        return set()
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return set()
    out: set[str] = set()
    _collect_cargo_section(data, out)
    targets = data.get("target") or {}
    if isinstance(targets, dict):
        for cfg in targets.values():
            if isinstance(cfg, dict):
                _collect_cargo_section(cfg, out)
    return out


def _collect_cargo_section(table: dict[str, Any], out: set[str]) -> None:
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        block = table.get(section) or {}
        if not isinstance(block, dict):
            continue
        for name in block.keys():
            if isinstance(name, str) and CRATE_NAME_RE.match(name):
                out.add(name)


_PARSERS: dict[str, tuple[str, Callable[[str], set[str]]]] = {
    "package.json": ("npm", parse_npm_direct_deps),
    "pyproject.toml": ("pypi", parse_pyproject_direct_deps),
    "Cargo.toml": ("cargo", parse_cargo_direct_deps),
}


def ecosystem_for(path: str) -> tuple[str, Callable[[str], set[str]]] | None:
    """Map a manifest path to its (ecosystem, parser) tuple."""
    for suffix, info in _PARSERS.items():
        if path.endswith(suffix):
            return info
    return None


# --- New-dep diff computation ------------------------------------------------


def compute_new_deps(
    base_ref: str,
    head_ref: str,
    runner: Callable[[list[str]], str] = _run_git,
) -> list[NewDep]:
    """Compute the set of NEW direct deps added between two refs."""
    new_deps: list[NewDep] = []
    seen: set[tuple[str, str]] = set()  # (ecosystem, name) dedupe
    for path in changed_manifests(base_ref, head_ref, runner=runner):
        info = ecosystem_for(path)
        if info is None:
            continue
        ecosystem, parser = info
        head_text = _read_blob(head_ref, path, runner=runner)
        if head_text is None:
            # Manifest was removed in head — nothing to score.
            continue
        head_names = parser(head_text)
        base_text = _read_blob(base_ref, path, runner=runner)
        base_names = parser(base_text) if base_text is not None else set()
        added = head_names - base_names
        for name in sorted(added):
            key = (ecosystem, name)
            if key in seen:
                continue
            seen.add(key)
            new_deps.append(NewDep(ecosystem=ecosystem, name=name, file=path))
    return new_deps


# --- Registry resolution -----------------------------------------------------


def _http_get_json(
    url: str,
    opener: Callable[[str], tuple[int, bytes]],
) -> tuple[int, Any]:
    """GET ``url``, return ``(status, parsed_json_or_None)``."""
    status, body = opener(url)
    if status != 200:
        return status, None
    try:
        return status, json.loads(body.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, ValueError):
        return status, None


def _default_opener(url: str) -> tuple[int, bytes]:
    """urllib-based opener with HTTPS-only enforcement and NO redirect following.

    The four hosts this script talks to (registry.npmjs.org, pypi.org,
    crates.io, api.securityscorecards.dev) do not require redirects for the
    endpoints we use. Following redirects would let a compromise of any of
    those hosts turn into a runner-side SSRF that bypasses the up-front
    HTTPS / host check.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(f"refusing non-HTTPS URL: {url!r}")
    req = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": "agt-scorecard-check/1"}
    )
    opener = urllib.request.build_opener(_NoRedirectHandler())
    try:
        with opener.open(req, timeout=15) as resp:  # noqa: S310 - HTTPS gated, no redirects
            body = resp.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise ValueError(f"response exceeded {MAX_RESPONSE_BYTES} bytes")
            return resp.status, body
    except urllib.error.HTTPError as e:
        return e.code, b""


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject every redirect; return the 3xx response as-is so callers see it."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def resolve_repo_url(
    dep: NewDep,
    opener: Callable[[str], tuple[int, bytes]] = _default_opener,
) -> str | None:
    """Resolve a NewDep to a canonical https://github.com/<owner>/<repo> URL.

    Returns None when no GitHub source URL could be discovered. The returned
    URL is always validated by GITHUB_REPO_RE.
    """
    candidate = _resolve_raw(dep, opener)
    if not candidate:
        return None
    return _canonicalize_github_url(candidate)


def _resolve_raw(
    dep: NewDep,
    opener: Callable[[str], tuple[int, bytes]],
) -> str | None:
    if dep.ecosystem == "npm":
        if not NPM_NAME_RE.match(dep.name):
            return None
        # npm registry tolerates @scope/name unencoded.
        url = f"https://registry.npmjs.org/{dep.name}"
        _, data = _http_get_json(url, opener)
        if not isinstance(data, dict):
            return None
        repo = data.get("repository")
        if isinstance(repo, dict):
            return _stringify(repo.get("url"))
        return _stringify(repo)
    if dep.ecosystem == "pypi":
        if not PYPI_NAME_RE.match(dep.name):
            return None
        url = f"https://pypi.org/pypi/{dep.name}/json"
        _, data = _http_get_json(url, opener)
        if not isinstance(data, dict):
            return None
        info = data.get("info") or {}
        urls = info.get("project_urls") or {}
        if isinstance(urls, dict):
            for key in ("Source", "Source Code", "Repository", "Homepage", "Home"):
                candidate = _stringify(urls.get(key))
                if candidate:
                    return candidate
        return _stringify(info.get("home_page"))
    if dep.ecosystem == "cargo":
        if not CRATE_NAME_RE.match(dep.name):
            return None
        url = f"https://crates.io/api/v1/crates/{dep.name}"
        _, data = _http_get_json(url, opener)
        if not isinstance(data, dict):
            return None
        crate = data.get("crate") or {}
        return _stringify(crate.get("repository"))
    return None


def _stringify(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _canonicalize_github_url(raw: str) -> str | None:
    """Normalize a registry-supplied URL to ``https://github.com/<owner>/<repo>``.

    Returns None when the URL is not unambiguously a GitHub project URL.
    All non-GitHub hosts are rejected. The result is then validated by
    GITHUB_REPO_RE so callers can safely embed it into the Scorecard URL.
    """
    candidate = raw.strip()
    # Strip git+ prefix and .git suffix; common on npm metadata.
    if candidate.startswith("git+"):
        candidate = candidate[4:]
    # ssh form: git@github.com:owner/repo(.git)
    m = re.match(r"^git@github\.com:([A-Za-z0-9-]+)/([A-Za-z0-9._-]+?)(?:\.git)?$", candidate)
    if m:
        candidate = f"https://github.com/{m.group(1)}/{m.group(2)}"
    # git:// or http:// → upgrade to https for matching only.
    if candidate.startswith("git://github.com/"):
        candidate = "https://github.com/" + candidate[len("git://github.com/"):]
    if candidate.startswith("http://github.com/"):
        candidate = "https://github.com/" + candidate[len("http://github.com/"):]
    if candidate.endswith(".git"):
        candidate = candidate[:-4]

    try:
        parsed = urlparse(candidate)
    except ValueError:
        return None
    if parsed.scheme != "https" or parsed.netloc != "github.com":
        return None
    # Reject any URL with extra path segments or traversal markers.
    # github.com/<owner>/<repo>(/) is the ONLY accepted shape.
    if ".." in parsed.path or "//" in parsed.path:
        return None
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) != 2:
        return None
    owner, repo = parts
    if owner in (".", "..") or repo in (".", ".."):
        return None
    canonical = f"https://github.com/{owner}/{repo}"
    if not GITHUB_REPO_RE.match(canonical):
        return None
    return canonical


# --- Scorecard query ---------------------------------------------------------


def query_scorecard(
    repo_url: str,
    opener: Callable[[str], tuple[int, bytes]] = _default_opener,
) -> tuple[int, dict[str, Any] | None]:
    """Query the OSSF Scorecard hosted API for a GitHub project URL.

    Returns ``(status, payload)`` where status is the HTTP status code and
    payload is the parsed JSON body (or None on non-200).
    """
    if not GITHUB_REPO_RE.match(repo_url):
        raise ValueError(f"refusing un-validated repo URL: {repo_url!r}")
    suffix = repo_url[len("https://github.com/"):]
    api_url = f"{SCORECARD_API_BASE}/{suffix}"
    return _http_get_json(api_url, opener)


# --- Orchestration -----------------------------------------------------------


def score_deps(
    deps: Iterable[NewDep],
    min_score: float,
    opener: Callable[[str], tuple[int, bytes]] = _default_opener,
    skip_patterns: Iterable[re.Pattern[str]] | None = None,
) -> list[ScoreResult]:
    """Resolve and score every dep; never raises on per-dep network errors.

    Names matching any pattern in ``skip_patterns`` are recorded with
    ``status="skipped"`` and never trigger a registry call — used to avoid
    leaking internal package names to public registries.
    """
    patterns = list(skip_patterns or [])
    results: list[ScoreResult] = []
    for dep in deps:
        result = ScoreResult(dep=dep)
        if any(p.search(dep.name) for p in patterns):
            result.status = "skipped"
            result.message = "matched --skip-pattern; not queried against public registry"
            results.append(result)
            continue
        try:
            repo_url = resolve_repo_url(dep, opener=opener)
        except Exception as exc:  # noqa: BLE001 - network/parse robustness
            result.status = "error"
            result.message = f"registry lookup failed: {exc}"
            results.append(result)
            continue
        if not repo_url:
            result.status = "no-repo"
            result.message = "no GitHub source URL discoverable from registry metadata"
            results.append(result)
            continue
        result.repo_url = repo_url
        try:
            status, payload = query_scorecard(repo_url, opener=opener)
        except Exception as exc:  # noqa: BLE001
            result.status = "error"
            result.message = f"scorecard query failed: {exc}"
            results.append(result)
            continue
        if status == 404 or payload is None:
            result.status = "untracked"
            result.message = "not tracked by Scorecard; consider manual review"
            results.append(result)
            continue
        score = payload.get("score")
        if isinstance(score, (int, float)):
            result.score = float(score)
        checks = payload.get("checks")
        if isinstance(checks, list):
            result.checks = checks
        if result.score is None:
            result.status = "untracked"
            result.message = "Scorecard response missing score; treat as untracked"
        elif result.score < min_score:
            result.status = "below"
            result.message = (
                f"score {result.score:.1f} below threshold {min_score:.1f}"
            )
        else:
            result.status = "above"
            result.message = f"score {result.score:.1f}"
        results.append(result)
    return results


# --- Reporting ---------------------------------------------------------------


def format_report(results: list[ScoreResult], min_score: float) -> str:
    """Render a markdown report for the workflow log."""
    if not results:
        return "No new direct dependencies detected."
    lines: list[str] = []
    lines.append(f"## OSSF Scorecard check (threshold: {min_score:.1f})\n")
    lines.append("| Ecosystem | Package | Repo | Score | Status | Notes |")
    lines.append("|-----------|---------|------|-------|--------|-------|")
    for r in results:
        repo = r.repo_url or "—"
        score = f"{r.score:.1f}" if r.score is not None else "—"
        notes = r.message.replace("|", "\\|")
        lines.append(
            f"| {r.dep.ecosystem} | `{r.dep.name}` | {repo} | {score} "
            f"| {r.status} | {notes} |"
        )
    return "\n".join(lines) + "\n"


def emit_annotations(results: list[ScoreResult]) -> None:
    """Emit GitHub Actions annotations for non-passing results."""
    for r in results:
        if r.status == "below":
            print(
                f"::warning file={r.dep.file}::OSSF Scorecard {r.score:.1f} "
                f"for {r.dep.ecosystem} dep '{r.dep.name}' ({r.repo_url}) "
                f"is below threshold — review before merging."
            )
        elif r.status == "untracked":
            print(
                f"::notice file={r.dep.file}::{r.dep.ecosystem} dep "
                f"'{r.dep.name}' is not tracked by OSSF Scorecard; "
                f"consider manual due diligence."
            )
        elif r.status == "no-repo":
            print(
                f"::notice file={r.dep.file}::{r.dep.ecosystem} dep "
                f"'{r.dep.name}' has no discoverable GitHub source URL; "
                f"consider manual due diligence."
            )
        elif r.status == "error":
            print(
                f"::notice file={r.dep.file}::{r.dep.ecosystem} dep "
                f"'{r.dep.name}' could not be checked: {r.message}"
            )


# --- CLI ---------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="check_dependency_scorecard",
        description="OSSF Scorecard check for new direct deps in a PR diff.",
    )
    p.add_argument("--base-ref", default=DEFAULT_BASE_REF)
    p.add_argument("--head-ref", default=DEFAULT_HEAD_REF)
    p.add_argument(
        "--min-score", type=float, default=DEFAULT_MIN_SCORE,
        help=f"Score threshold (default: {DEFAULT_MIN_SCORE})",
    )
    p.add_argument(
        "--max-deps", type=int, default=DEFAULT_MAX_DEPS,
        help=f"Hard cap on number of new deps to check (default: {DEFAULT_MAX_DEPS})",
    )
    p.add_argument(
        "--strict", action="store_true",
        help="Exit non-zero if any new dep falls below the threshold.",
    )
    p.add_argument(
        "--skip-pattern", action="append", default=[], metavar="REGEX",
        help=(
            "Regex of package names to exclude from registry lookup. May be "
            "given multiple times. Use to avoid leaking internal scoped "
            "names (e.g. --skip-pattern '^@myorg/') to public registries."
        ),
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.min_score < 0 or args.min_score > 10:
        print("::error::--min-score must be between 0 and 10", file=sys.stderr)
        return EXIT_USAGE
    if args.max_deps < 1:
        print("::error::--max-deps must be >= 1", file=sys.stderr)
        return EXIT_USAGE
    try:
        skip_patterns = [re.compile(pat) for pat in args.skip_pattern]
    except re.error as exc:
        print(f"::error::invalid --skip-pattern regex: {exc}", file=sys.stderr)
        return EXIT_USAGE
    try:
        deps = compute_new_deps(args.base_ref, args.head_ref)
    except RuntimeError as exc:
        print(f"::error::failed to compute new deps: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if len(deps) > args.max_deps:
        print(
            f"::error::found {len(deps)} new direct dependencies, exceeds "
            f"--max-deps={args.max_deps}; split this PR or raise the cap.",
            file=sys.stderr,
        )
        return EXIT_OVERFLOW
    results = score_deps(deps, args.min_score, skip_patterns=skip_patterns)
    print(format_report(results, args.min_score))
    emit_annotations(results)
    if args.strict and any(r.status == "below" for r in results):
        return EXIT_STRICT_FAIL
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
