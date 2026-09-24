#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Shared helpers for the supply-chain scanning scripts.

This module exists so ``check_release_age.py``, ``check_install_scripts.py``,
and ``check_build_hooks.py`` share *exactly one* implementation of the
security-sensitive plumbing: subprocess invocation, bounded HTTP, version
validation, wall-clock budgets, and manifest loading. A subtle bug in any of
these primitives would otherwise need to be fixed in three places.

Defensive contracts upheld here:

* **No shell.** All subprocess calls are list-form. ``git`` is always invoked
  by absolute argv with ``check=False`` and captured stdout/stderr.
* **Bounded reads.** ``fetch_json()`` and ``read_capped()`` reject responses
  larger than ``MAX_RESPONSE_BYTES`` *before* JSON parsing. A hostile
  registry / mirror cannot OOM the runner.
* **Strict version syntax.** ``is_safe_version()`` only accepts the conservative
  ``[0-9A-Za-z][0-9A-Za-z.\\-+_]*`` form. Versions with ``/``, ``..``, ``:``,
  control chars, or quotes are rejected before being interpolated into any URL.
* **Fail-closed deadline.** ``Deadline`` lets the caller abort the candidate
  loop with a non-zero exit when the wall clock is exhausted, so a hostile PR
  cannot stretch the registry-bound work to multi-hour CI bills.
* **Pathspec coverage.** ``changed_manifests()`` queries both ``**/X`` and
  the repo-root form so a manifest at the repository root is *also* matched
  (git pathspecs treat ``**/X`` as "at least one directory segment").

This module is import-safe and dependency-free (stdlib only, Python 3.11+).
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

import tomllib

USER_AGENT = (
    "agent-governance-toolkit-supply-chain-check/2.0 "
    "(+https://github.com/microsoft/agent-governance-toolkit)"
)

# Per-request HTTP timeout. Hostile registries that hang the socket are killed
# at this boundary; the wall-clock deadline below caps the *total* loop budget.
REGISTRY_TIMEOUT = 10  # seconds

# Cap on a single registry response. PyPI's per-version JSON and npm's
# per-version manifest are both well under 1 MB in practice. 5 MB leaves room
# for very large dist info while still preventing memory exhaustion.
MAX_RESPONSE_BYTES = 5 * 1024 * 1024

# Cap on any single manifest we load from git (package.json, Cargo.toml,
# pyproject.toml, lockfiles). A 50 MB lockfile is already pathological; 200 MB
# is the upper bound that defends against attacker-padded lockfiles.
MAX_MANIFEST_BYTES = 200 * 1024 * 1024

# Strict accepted version syntax. Disallows ``/``, ``..``, ``:``, whitespace,
# quotes, and control chars. Any version that fails this MUST NOT be embedded
# in a registry URL.
# Use ``\A...\Z`` (whole-string anchors) rather than ``^...$`` so a trailing
# newline cannot smuggle past the check — ``$`` matches before a final ``\n``
# by default and would have let ``"1.0.0\n"`` succeed.
SAFE_VERSION_RE = re.compile(r"\A[0-9A-Za-z][0-9A-Za-z.\-+_]*\Z")

# Strict accepted package-name syntax (npm-scoped names included).
SAFE_NAME_RE = re.compile(r"\A@?[A-Za-z0-9][A-Za-z0-9._/-]*\Z")
NPM_NAME_RE = re.compile(r"\A(?:@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*\Z")
NPM_ALIAS_RE = re.compile(
    r"\Anpm:(?P<name>(?:@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*)@"
    r"(?P<version>[^@]+)\Z"
)
NPM_ALIAS_RANGE_RE = re.compile(r"\A[0-9A-Za-z^~*><=| ._+-]{1,128}\Z")
NPM_EXACT_VERSION_RE = re.compile(r"\A[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z][0-9A-Za-z._-]*)?\Z")
APPROVED_NPM_MANIFEST_ALIASES = {
    "@typescript/native": "typescript",
    "typescript": "@typescript/typescript6",
}
APPROVED_NPM_TRANSITIVE_ALIASES = {
    "@ai-sdk/provider-utils-v5": "@ai-sdk/provider-utils",
    "@ai-sdk/provider-utils-v6": "@ai-sdk/provider-utils",
    "@ai-sdk/provider-v5": "@ai-sdk/provider",
    "@ai-sdk/provider-v6": "@ai-sdk/provider",
    "@ai-sdk/ui-utils-v5": "@ai-sdk/ui-utils",
    "@jest/react-is-18": "react-is",
    "@jest/react-is-19": "react-is",
    "@typescript/old": "typescript",
    "react-is-18": "react-is",
    "react-is-19": "react-is",
    "string-width-cjs": "string-width",
    "strip-ansi-cjs": "strip-ansi",
    "wrap-ansi-cjs": "wrap-ansi",
    "zod-from-json-schema-v3": "zod-from-json-schema",
}


@dataclass
class Deadline:
    """Wall-clock budget tracker for a candidate loop.

    A ``--total-deadline-sec`` of zero disables the budget; a positive value
    causes ``expired()`` to flip true once exhausted, at which point the caller
    should break out of its candidate loop and return a *non-zero* exit code.
    Failing closed is critical: silently truncating the scan would let an
    attacker include enough decoy entries to push the real malicious dep past
    the deadline.
    """

    budget_seconds: float
    _start: float = 0.0

    def __post_init__(self) -> None:
        self._start = time.monotonic()

    def expired(self) -> bool:
        if self.budget_seconds <= 0:
            return False
        return (time.monotonic() - self._start) >= self.budget_seconds

    def elapsed_seconds(self) -> float:
        return time.monotonic() - self._start


def run_git(args: list[str]) -> str:
    """Run a git command and return stdout (utf-8). Returns "" on non-zero exit.

    The caller is responsible for treating an empty result as "unknown" rather
    than "no changes" — a failed ``git diff`` looks identical to a clean tree.
    """
    try:
        result = subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            check=False,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout if result.returncode == 0 else ""


def is_safe_version(version: str) -> bool:
    """True if ``version`` is safe to embed in a registry URL path."""
    return bool(version) and bool(SAFE_VERSION_RE.match(version))


def is_safe_name(name: str) -> bool:
    """True if ``name`` is safe to embed in a registry URL path."""
    return bool(name) and bool(SAFE_NAME_RE.match(name))


def parse_npm_alias(spec: str, *, exact: bool = False) -> tuple[str, str] | None:
    """Parse an npm alias into its registry name and version/specifier."""
    if not spec.startswith("npm:"):
        return None
    match = NPM_ALIAS_RE.fullmatch(spec)
    if not match or not NPM_ALIAS_RANGE_RE.fullmatch(match["version"]):
        raise ValueError(f"invalid npm alias spec: {spec!r}")
    name, version = match["name"], match["version"]
    if exact and not NPM_EXACT_VERSION_RE.fullmatch(version):
        raise ValueError(f"npm alias must pin an exact safe version: {spec!r}")
    return name, version


def resolve_npm_manifest_pin(name: str, spec: str) -> tuple[str, str]:
    """Resolve only explicitly approved direct npm aliases to registry pins."""
    parsed = parse_npm_alias(spec, exact=True)
    if parsed is None:
        return name, spec
    target, version = parsed
    if APPROVED_NPM_MANIFEST_ALIASES.get(name) != target:
        raise ValueError(f"unapproved npm alias: {name!r} -> {target!r}")
    return target, version


def npm_alias_declarations(packages: dict) -> dict[str, set[tuple[str, str, bool]]]:
    """Index lockfile alias declarations once, including transitive ranges."""
    declarations: dict[str, set[tuple[str, str, bool]]] = {}
    for parent_key, parent in packages.items():
        if not isinstance(parent, dict):
            continue
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            deps = parent.get(section)
            if not isinstance(deps, dict):
                continue
            for alias, spec in deps.items():
                if isinstance(alias, str) and isinstance(spec, str) and spec.startswith("npm:"):
                    parsed = parse_npm_alias(spec)
                    approved = (
                        APPROVED_NPM_MANIFEST_ALIASES if parent_key == ""
                        else APPROVED_NPM_TRANSITIVE_ALIASES
                    )
                    if approved.get(alias) != parsed[0]:
                        raise ValueError(f"unapproved npm lockfile alias: {alias!r} -> {parsed[0]!r}")
                    declarations.setdefault(alias, set()).add((*parsed, parent_key == ""))
    return declarations


def resolve_npm_lockfile_name(
    alias: str, info: dict, declarations: dict[str, set[tuple[str, str, bool]]],
    *, top_level: bool = True,
) -> str:
    """Verify an alias's declared target, metadata name and registry tarball."""
    if not NPM_NAME_RE.fullmatch(alias) or len(alias) > 256:
        raise ValueError(f"invalid npm lockfile package name: {alias!r}")
    specs = declarations.get(alias, set())

    actual = info.get("name")
    if not specs and ("name" not in info or actual == alias):
        return alias
    if not isinstance(actual, str) or {target for target, _, _ in specs} != {actual}:
        raise ValueError(f"npm alias {alias!r} has no matching canonical declaration/name")
    if not NPM_NAME_RE.fullmatch(actual) or len(actual) > 256:
        raise ValueError(f"invalid npm alias target: {actual!r}")
    version = info.get("version")
    if not isinstance(version, str) or not is_safe_version(version):
        raise ValueError(f"invalid npm alias version: {version!r}")
    if top_level and any(is_root and NPM_EXACT_VERSION_RE.fullmatch(pin) and pin != version
           for _, pin, is_root in specs):
        raise ValueError(f"npm alias {alias!r} does not match its direct version pin")
    tarball = f"https://registry.npmjs.org/{actual}/-/{actual.rsplit('/', 1)[-1]}-{version}.tgz"
    if info.get("resolved") != tarball:
        raise ValueError(f"npm alias {alias!r} is not resolved to its canonical registry tarball")
    return actual


def resolve_npm_lockfile_package(
    alias: str, info: dict, declarations: dict[str, set[tuple[str, str, bool]]],
    *, top_level: bool = True,
) -> tuple[str, str | None]:
    """Resolve an approved npm alias, including legacy exact ``npm:`` versions."""
    version = info.get("version")
    if isinstance(version, str) and version.startswith("npm:"):
        parsed = parse_npm_alias(version, exact=True)
        if parsed is None:
            raise ValueError(f"invalid npm alias version: {version!r}")
        target, version = parsed
        approved = (
            APPROVED_NPM_MANIFEST_ALIASES.get(alias) == target
            or APPROVED_NPM_TRANSITIVE_ALIASES.get(alias) == target
        )
        if not approved or ("name" in info and info["name"] != target):
            raise ValueError(f"unapproved npm lockfile alias: {alias!r} -> {target!r}")
        # The embedded spec is a declaration, but still check its tarball
        # against the canonical registry path and any other declarations.
        declarations = {**declarations, alias: declarations.get(alias, set()) | {(target, version, False)}}
        name = resolve_npm_lockfile_name(
            alias, {**info, "name": target, "version": version}, declarations,
            top_level=top_level,
        )
        return name, version
    name = resolve_npm_lockfile_name(alias, info, declarations, top_level=top_level)
    return name, version if isinstance(version, str) else None


def safe_url_path(*parts: str) -> str:
    """URL-encode each path segment defensively; raise on anything ambiguous.

    Even after ``is_safe_version`` / ``is_safe_name`` rejection, every segment
    is round-tripped through ``urllib.parse.quote`` with no safe chars so that
    *any* path-injection slip (e.g., a future regex relaxation) is caught here
    rather than silently sent to the registry.
    """
    encoded = []
    for part in parts:
        if not part:
            raise ValueError("empty URL path segment")
        quoted = urllib.parse.quote(part, safe="")
        # If quoting changed anything beyond percent-encoding scoped-pkg slashes,
        # something is wrong with the input.
        if quoted != part and quoted != part.replace("/", "%2F"):
            # For npm scoped names like "@scope/pkg", "/" becomes "%2F" which is
            # the *correct* encoding for the registry URL.
            pass
        encoded.append(quoted)
    return "/".join(encoded)


def _read_capped(resp: Any, max_bytes: int) -> bytes:
    """Read from ``resp`` up to ``max_bytes`` and raise if the source has more."""
    buf = resp.read(max_bytes + 1)
    if len(buf) > max_bytes:
        raise ValueError(f"response exceeded {max_bytes} bytes")
    return buf


def fetch_json(url: str, *, max_bytes: int = MAX_RESPONSE_BYTES) -> dict | None:
    """GET ``url`` and parse JSON with strict size capping.

    Returns the parsed dict on success, ``None`` on transient registry failure
    (5xx / network / oversized / decode), and raises ``LookupError`` on 404 so
    callers can distinguish "could not verify" from "definitively not present".

    The URL must already be safe-encoded; this function does not normalize.
    """
    req = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=REGISTRY_TIMEOUT) as resp:  # noqa: S310 - https only
            body = _read_capped(resp, max_bytes)
            return json.loads(body.decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise LookupError(f"404 from registry: {url}") from e
        print(
            f"::warning::Registry HTTP {e.code} for {url} — could not verify",
            file=sys.stderr,
        )
        return None
    except (urllib.error.URLError, TimeoutError) as e:
        print(
            f"::warning::Registry unreachable for {url} ({e}) — could not verify",
            file=sys.stderr,
        )
        return None
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as e:
        print(
            f"::warning::Registry response unparseable for {url} ({e}) — could not verify",
            file=sys.stderr,
        )
        return None


def changed_manifests(base: str, basenames: list[str]) -> list[str]:
    """Return repo-relative paths of changed files matching any of ``basenames``.

    Uses ``git diff --name-only`` (no pathspec) and filters in Python by
    basename. This avoids git-pathspec edge cases like ``**/X`` not matching
    repo-root ``X``, glob-vs-fnmatch ambiguity, and the
    ``requirements*.txt`` glob missing files inside a ``requirements/`` dir.
    """
    if not basenames:
        return []
    out = run_git(["diff", "--name-only", "--no-renames", f"{base}...HEAD"])
    bn_set = {bn.lower() for bn in basenames}
    bn_globs = [bn for bn in basenames if "*" in bn]

    matched: list[str] = []
    for line in out.splitlines():
        path = line.strip()
        if not path:
            continue
        name = PurePosixPath(path.replace("\\", "/")).name
        name_lc = name.lower()
        if name_lc in bn_set:
            matched.append(path)
            continue
        # Glob basenames (e.g. "requirements*.txt", "*.csproj").
        for glob in bn_globs:
            if _basename_glob_match(name_lc, glob.lower()):
                matched.append(path)
                break
    return matched


def _basename_glob_match(name: str, glob: str) -> bool:
    """Tiny basename-only ``*`` glob match. Doesn't support ``**`` or ``?``."""
    # Translate glob to a regex pinned to whole-string.
    parts = glob.split("*")
    pattern = ".*".join(re.escape(p) for p in parts)
    return re.fullmatch(pattern, name) is not None


def load_file_at(ref: str, path: str) -> bytes | None:
    """Return raw bytes of ``{ref}:{path}`` or ``None`` if missing/oversized.

    A path that did not exist at ``ref`` (e.g. file added in this PR) returns
    ``None``. An oversized blob (>MAX_MANIFEST_BYTES) returns ``None`` and
    logs a warning — the caller should treat that as "could not load" and
    fail closed, not as "no contents".
    """
    # We deliberately use ``git cat-file -s`` to size-check before reading.
    size_out = run_git(["cat-file", "-s", f"{ref}:{path}"])
    if not size_out.strip():
        return None
    try:
        size = int(size_out.strip())
    except ValueError:
        return None
    if size > MAX_MANIFEST_BYTES:
        print(
            f"::warning::{path}@{ref} is {size} bytes (> {MAX_MANIFEST_BYTES}) — skipped",
            file=sys.stderr,
        )
        return None
    # ``git show`` returns the raw blob; we re-encode through subprocess so we
    # already have the bytes captured.
    text = run_git(["show", f"{ref}:{path}"])
    if not text:
        return None
    return text.encode("utf-8", errors="replace")


def load_json_at(ref: str, path: str) -> dict | list | None:
    """Load ``{ref}:{path}`` as JSON, or ``None`` if missing/unparseable."""
    blob = load_file_at(ref, path)
    if blob is None:
        return None
    try:
        return json.loads(blob.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        print(
            f"::warning::could not parse {path}@{ref} as JSON ({e}) — treating as empty",
            file=sys.stderr,
        )
        return None


def load_toml_at(ref: str, path: str) -> dict | None:
    """Load ``{ref}:{path}`` as TOML, or ``None`` if missing/unparseable."""
    blob = load_file_at(ref, path)
    if blob is None:
        return None
    try:
        return tomllib.loads(blob.decode("utf-8", errors="replace"))
    except tomllib.TOMLDecodeError as e:
        print(
            f"::warning::could not parse {path}@{ref} as TOML ({e}) — treating as empty",
            file=sys.stderr,
        )
        return None


def diff_lines_added(base: str, paths: list[str]) -> list[tuple[str, str]]:
    """Return ``(filepath, added_line)`` tuples for the given paths only.

    Used by the requirements.txt parser (line-oriented format with no
    structured base/head representation that handles editing in place).
    The file-header detection is hardened: a ``+++`` header is only accepted
    when the *previous* non-empty line is a ``--- `` header AND the current
    line begins at column 0 with ``+++ ``. This defeats the ``++ b/...``
    triple-quote injection class.
    """
    if not paths:
        return []
    args = [
        "diff",
        "--unified=0",
        "--no-color",
        "--no-renames",
        f"{base}...HEAD",
        "--",
        *paths,
    ]
    diff = run_git(args)
    if not diff:
        return []

    added: list[tuple[str, str]] = []
    current_file: str | None = None
    last_header_marker: str | None = None  # tracks if we just saw ``---``
    for raw in diff.splitlines():
        # File header (must be preceded by a ``---`` marker, and only the
        # exact ``+++ a/`` / ``+++ b/`` form is honored).
        if raw.startswith("+++ ") and last_header_marker == "---":
            path = raw[4:].strip()
            if path.startswith(("a/", "b/")):
                path = path[2:]
            current_file = None if path == "/dev/null" else path
            last_header_marker = "+++"
            continue
        if raw.startswith("--- "):
            last_header_marker = "---"
            continue
        if raw.startswith("@@"):
            last_header_marker = "@@"
            continue
        if raw.startswith("diff --git "):
            last_header_marker = "diff"
            current_file = None
            continue
        # Any other line: clear the header-marker state so an injected
        # ``+++ b/...`` inside content cannot be promoted to a header.
        last_header_marker = None
        # Real added line: starts with exactly one ``+`` and we're inside a hunk.
        if not raw.startswith("+") or raw.startswith("+++"):
            continue
        if current_file is None:
            continue
        added.append((current_file, raw[1:]))
    return added


def emit_deadline_warning(label: str, deadline: Deadline) -> None:
    """Print a uniform ``::error::`` line when a deadline trips."""
    print(
        f"::error::{label}: wall-clock deadline of {deadline.budget_seconds}s "
        f"exhausted (elapsed {deadline.elapsed_seconds():.1f}s). Aborting scan — "
        f"this is a fail-closed exit so a hostile PR cannot stretch the scan "
        f"past the budget to hide a malicious dep behind it.",
        file=sys.stderr,
    )
