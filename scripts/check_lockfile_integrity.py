#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. Licensed under the MIT License.
"""Verify lockfile integrity hashes against upstream registry metadata.

For every added or changed entry in a lockfile (npm `package-lock.json`,
Cargo `Cargo.lock`, or `pip` requirements files with ``--hash`` pins), this
script compares the locally pinned cryptographic hash against what the
upstream package registry actually publishes for that exact version.

This catches **lockfile poisoning** — a supply-chain attack where the version
number is unchanged but the bytes have been swapped (e.g. tampered tarball,
locally edited integrity field). It is intentionally distinct from
install-script bypass checks: those guard *new* entries, while this guards
the bytes of entries we already trust.

Supported ecosystems:
    - npm ``package-lock.json`` (lockfileVersion 2/3 ``packages`` map)
    - Cargo ``Cargo.lock`` (``[[package]]`` ``checksum`` field)
    - pip ``requirements*.txt`` lines with ``--hash=sha256:<hex>``

Out of scope (noted as future work): yarn.lock, pnpm-lock.yaml,
NuGet packages.lock.json.

Exit codes:
    0 - all integrity hashes verified (or no lockfile entries to check)
    1 - one or more mismatches / unfetchable upstream metadata
    2 - DoS cap exceeded (more entries than ``--max-deps``)
    3 - usage / configuration error

Usage:
    python scripts/check_lockfile_integrity.py
    python scripts/check_lockfile_integrity.py --base origin/main
    python scripts/check_lockfile_integrity.py path/to/package-lock.json
    python scripts/check_lockfile_integrity.py --max-deps 5000
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Iterable

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python <3.11 fallback
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:  # pragma: no cover - no toml parser available
        tomllib = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Security constants
# ---------------------------------------------------------------------------

# Maximum bytes to read from a single registry response. Even the largest
# package metadata documents on npmjs.org are well under 5 MB; we cap to
# prevent a hostile or compromised registry from exhausting memory.
MAX_RESPONSE_BYTES = 5 * 1024 * 1024

# Maximum bytes to read from any on-disk lockfile. Real-world lockfiles
# top out at single-digit MB; 16 MB is comfortable headroom. An attacker
# who can land a multi-GB ``package-lock.json`` in a PR would otherwise
# OOM the CI runner before any parsing happened.
MAX_LOCKFILE_BYTES = 16 * 1024 * 1024

# Maximum bytes to read from a ``git`` subprocess. Bounds both the
# ``git show <ref>:<lockfile>`` blob read (same DoS vector as on-disk
# lockfiles, except sourced from history) and the ``git ls-files`` /
# ``git diff --name-only`` listings on absurdly large repos.
MAX_GIT_STDOUT_BYTES = 64 * 1024 * 1024

# HTTP timeout (seconds) per registry request.
REQUEST_TIMEOUT = 15

# Only HTTPS to these exact hosts. SSRF defense — no user input is ever
# allowed to control the scheme or hostname.
NPM_HOST = "registry.npmjs.org"
CRATES_INDEX_HOST = "index.crates.io"
PYPI_HOST = "pypi.org"

# Tight character classes for ecosystem identifiers. Used both for sanity
# checking parsed values and for safe log emission (avoid log-injection via
# control characters in attacker-controlled package names).
NPM_NAME_RE = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$", re.IGNORECASE)
CARGO_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]+$")
PYPI_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+\-]*$")
SRI_RE = re.compile(r"^(sha256|sha384|sha512)-([A-Za-z0-9+/]+={0,2})$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

USER_AGENT = "agt-lockfile-integrity/1.0 (+https://github.com/microsoft/agent-governance-toolkit)"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LockEntry:
    """A single pinned dependency parsed from a lockfile."""

    ecosystem: str  # "npm" | "cargo" | "pip"
    name: str
    version: str
    integrity: str  # raw lockfile value (SRI for npm, hex for cargo/pip)
    location: str  # human-readable lockfile path / key for diagnostics


@dataclass
class Finding:
    """A verification result worth surfacing to the user."""

    severity: str  # "error" | "warn"
    entry: LockEntry
    message: str


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    checked: int = 0
    skipped: int = 0
    capped: bool = False

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "error"]


# ---------------------------------------------------------------------------
# Safe-logging helper
# ---------------------------------------------------------------------------


def _safe(token: str, *, max_len: int = 128) -> str:
    """Return *token* with control chars stripped and length capped.

    Defends against log-injection by attacker-controlled package names that
    contain newlines or ANSI escapes. The character allowlist is broader
    than the format regexes because we want to retain enough information
    for human triage of malformed input.
    """
    if not isinstance(token, str):
        token = repr(token)
    cleaned = "".join(c for c in token if 32 <= ord(c) < 127)
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len] + "..."
    return cleaned or "<empty>"


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


class RegistryError(Exception):
    """Raised when a registry lookup cannot be completed."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse all HTTP redirects.

    SSRF defense-in-depth: even though :func:`_http_get` validates the
    requested URL against an allowlist, the default ``HTTPRedirectHandler``
    would follow a 30x to any host (including ``http://``, ``ftp://``, or
    AWS metadata IPs) without re-running our check. The registries we talk
    to (npm, crates.io sparse index, PyPI JSON) all serve 200s directly
    today, so a redirect *is itself a hostile signal*.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        raise urllib.error.HTTPError(
            req.full_url, code, f"redirect to {newurl[:120]!r} refused", headers, fp
        )


_NOREDIRECT_OPENER = urllib.request.build_opener(_NoRedirect())

# Identifier length cap — defense in depth before regex application. Real-
# world npm scoped names top out around 80 chars; PyPI enforces 214; crates
# enforces 64. 256 leaves comfortable headroom while bounding the cost of
# a pathological lockfile entry.
MAX_IDENT_LEN = 256


def _http_get(url: str, *, allowed_hosts: tuple[str, ...]) -> bytes:
    """Fetch *url* with strict scheme/host validation and size caps.

    The allowed-host whitelist is the SSRF defense. Even though no caller
    today builds URLs from user input, this guard makes that property a
    structural invariant rather than a code-review obligation. Redirects
    are refused (see :class:`_NoRedirect`).
    """
    if not url.startswith("https://"):
        raise RegistryError(f"refusing non-https URL: {_safe(url)}")
    # urllib.parse handles userinfo / port stripping safely.
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.hostname not in allowed_hosts:
        raise RegistryError(f"refusing host outside allowlist: {_safe(parsed.hostname or '')}")

    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with _NOREDIRECT_OPENER.open(req, timeout=REQUEST_TIMEOUT) as resp:  # noqa: S310 - host pinned, redirects refused
            # read 1 byte past cap to detect overflow without buffering forever
            data = resp.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise RegistryError(f"http {exc.code} for {_safe(url)}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RegistryError(f"network error for {_safe(url)}: {_safe(str(exc))}") from exc

    if len(data) > MAX_RESPONSE_BYTES:
        raise RegistryError(f"response too large for {_safe(url)}")
    return data


def _http_get_json(url: str, *, allowed_hosts: tuple[str, ...]) -> dict:
    raw = _http_get(url, allowed_hosts=allowed_hosts)
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RegistryError(f"invalid json from {_safe(url)}: {_safe(str(exc))}") from exc


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------


def parse_npm_lockfile(content: str, path: str) -> list[LockEntry]:
    """Parse an npm ``package-lock.json`` (v2/v3) into LockEntry rows.

    Only entries under ``packages`` with a non-empty key, a ``version``,
    and an ``integrity`` field are returned. Workspace roots (empty key)
    and link/symlink entries (no integrity) are deliberately skipped — they
    do not represent registry-installable artifacts.
    """
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []

    packages = data.get("packages")
    if not isinstance(packages, dict):
        return []

    entries: list[LockEntry] = []
    for key, info in packages.items():
        if not isinstance(info, dict):
            continue
        if not key:
            continue  # workspace root
        if info.get("link") is True:
            continue
        version = info.get("version")
        integrity = info.get("integrity")
        if not isinstance(version, str) or not isinstance(integrity, str):
            continue
        # The trailing path segment after the last `node_modules/` is the
        # canonical package name; this handles nested transitive copies.
        marker = "node_modules/"
        idx = key.rfind(marker)
        name = key[idx + len(marker):] if idx >= 0 else key
        if not NPM_NAME_RE.match(name) or not VERSION_RE.match(version):
            continue
        if len(name) > MAX_IDENT_LEN or len(version) > MAX_IDENT_LEN:
            continue
        # Multi-algorithm SRI is space-separated, e.g.
        # ``sha512-AAA== sha256-BBB==``. compare_npm() handles either, but
        # the anchored SRI_RE rejects strings with spaces, so we split first.
        if len(integrity) > MAX_IDENT_LEN * 4:
            continue
        tokens = [tok for tok in integrity.split() if SRI_RE.match(tok)]
        if not tokens:
            continue
        # W3C SRI / ssri semantics: multiple tokens of the *same* algorithm
        # are treated as alternatives — a payload passes if ANY listed
        # digest matches. An attacker can exploit this by listing
        # ``sha512-EVIL sha512-LEGIT`` plus an attacker-controlled
        # ``resolved`` URL: our intersection-based compare_npm would see
        # the LEGIT token shared with upstream and report OK, while
        # ``npm ci`` would happily accept bytes hashing to EVIL. Flag
        # any same-algorithm multi-token integrity as suspicious — it
        # is not how npm publishes lockfiles and the only legitimate
        # multi-token shape is one-token-per-algorithm.
        algos = [tok.split("-", 1)[0].lower() for tok in tokens]
        if len(algos) != len(set(algos)):
            entries.append(
                LockEntry(
                    ecosystem="npm-suspicious",
                    name=name,
                    version=version,
                    integrity=_safe(integrity, max_len=200),
                    location=f"{path}::{key}",
                )
            )
            continue
        entries.append(
            LockEntry(
                ecosystem="npm",
                name=name,
                version=version,
                integrity=integrity,
                location=f"{path}::{key}",
            )
        )
    return entries


def fetch_npm_integrity(name: str, version: str) -> str:
    """Return the registry-published SRI integrity for *name*@*version*."""
    if not NPM_NAME_RE.match(name):
        raise RegistryError(f"invalid npm name: {_safe(name)}")
    if not VERSION_RE.match(version):
        raise RegistryError(f"invalid npm version: {_safe(version)}")
    # urllib quoting is not needed since both fields are tightly validated.
    url = f"https://{NPM_HOST}/{name}/{version}"
    payload = _http_get_json(url, allowed_hosts=(NPM_HOST,))
    dist = payload.get("dist")
    if not isinstance(dist, dict):
        raise RegistryError(f"no dist for {_safe(name)}@{_safe(version)}")
    integrity = dist.get("integrity")
    if isinstance(integrity, str) and SRI_RE.match(integrity):
        return integrity
    # Older registry entries only publish shasum (sha1, hex).
    shasum = dist.get("shasum")
    if isinstance(shasum, str) and re.fullmatch(r"[0-9a-f]{40}", shasum):
        return f"sha1-{base64.b64encode(bytes.fromhex(shasum)).decode('ascii')}"
    raise RegistryError(f"no integrity for {_safe(name)}@{_safe(version)}")


def compare_npm(local: str, upstream: str) -> bool:
    """Return True if the two SRI strings represent the same digest.

    Direct string equality is the common case. We also accept the situation
    where the upstream and local use *different* hash algorithms but the
    underlying tarball is the same — npm sometimes returns multi-algorithm
    SRI like ``sha512-... sha1-...``. In that case any matching algorithm
    is sufficient.
    """
    local_parts = {p for p in local.split() if SRI_RE.match(p)}
    upstream_parts = {p for p in upstream.split() if SRI_RE.match(p)}
    if not local_parts or not upstream_parts:
        return False
    return bool(local_parts & upstream_parts)


# ---------------------------------------------------------------------------
# Cargo
# ---------------------------------------------------------------------------


def parse_cargo_lockfile(content: str, path: str) -> list[LockEntry]:
    if tomllib is None:  # pragma: no cover - guarded at import time
        return []
    try:
        data = tomllib.loads(content)
    except (tomllib.TOMLDecodeError, ValueError):
        return []
    packages = data.get("package")
    if not isinstance(packages, list):
        return []
    entries: list[LockEntry] = []
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name")
        version = pkg.get("version")
        checksum = pkg.get("checksum")
        # Path / git dependencies have no checksum — skip those rather than
        # treat them as suspicious (they are not registry artifacts).
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        if not isinstance(checksum, str):
            continue
        if not CARGO_NAME_RE.match(name) or not VERSION_RE.match(version):
            continue
        if len(name) > MAX_IDENT_LEN or len(version) > MAX_IDENT_LEN:
            continue
        if not HEX64_RE.match(checksum):
            continue
        entries.append(
            LockEntry(
                ecosystem="cargo",
                name=name,
                version=version,
                integrity=checksum,
                location=f"{path}::{name} {version}",
            )
        )
    return entries


def crates_index_path(name: str) -> str:
    """Return the sparse-index path component for *name*.

    Mirrors the documented crates.io sparse layout:
      1-char  -> "1/<name>"
      2-char  -> "2/<name>"
      3-char  -> "3/<first>/<name>"
      4+      -> "<first2>/<chars3-4>/<name>"
    Names are lowercased per index convention.
    """
    if not CARGO_NAME_RE.match(name):
        raise RegistryError(f"invalid crate name: {_safe(name)}")
    lower = name.lower()
    n = len(lower)
    if n == 1:
        return f"1/{lower}"
    if n == 2:
        return f"2/{lower}"
    if n == 3:
        return f"3/{lower[0]}/{lower}"
    return f"{lower[0:2]}/{lower[2:4]}/{lower}"


def fetch_cargo_checksum(name: str, version: str) -> str:
    if not CARGO_NAME_RE.match(name):
        raise RegistryError(f"invalid crate name: {_safe(name)}")
    if not VERSION_RE.match(version):
        raise RegistryError(f"invalid crate version: {_safe(version)}")
    url = f"https://{CRATES_INDEX_HOST}/{crates_index_path(name)}"
    raw = _http_get(url, allowed_hosts=(CRATES_INDEX_HOST,))
    # Sparse index serves one JSON object per line, one per published version.
    text = raw.decode("utf-8", errors="strict")
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if entry.get("vers") == version:
            cksum = entry.get("cksum")
            if isinstance(cksum, str) and HEX64_RE.match(cksum):
                return cksum
            raise RegistryError(f"malformed cksum for {_safe(name)}@{_safe(version)}")
    raise RegistryError(f"version not in index: {_safe(name)}@{_safe(version)}")


def compare_cargo(local: str, upstream: str) -> bool:
    return local.lower() == upstream.lower()


# ---------------------------------------------------------------------------
# pip
# ---------------------------------------------------------------------------

_PIP_HASH_RE = re.compile(r"--hash=(sha256|sha384|sha512):([0-9a-f]+)", re.IGNORECASE)
_PIP_LINE_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*(?P<version>[A-Za-z0-9][A-Za-z0-9._+\-]*)"
)
_PIP_HASH_PRESENT_RE = re.compile(r"--hash=", re.IGNORECASE)
_PIP_HASH_LEN = {"sha256": 64, "sha384": 96, "sha512": 128}


def parse_pip_lockfile(content: str, path: str) -> list[LockEntry]:
    """Parse pip-tools / pip-compile style requirements with ``--hash`` pins.

    Emits one :class:`LockEntry` per ``--hash=`` pin on lines of the form
    ``name==version --hash=<algo>:<hex>``. Supports sha256, sha384, sha512
    (all three are accepted by pip itself).

    Lines that contain ``--hash=`` but do **not** match the strict
    ``name==version`` shape — for example PEP 508 direct references
    (``pkg @ https://...``), VCS references, or unknown hash algorithms —
    are emitted as a sentinel ``pip-suspicious`` entry so the verifier
    surfaces them loudly rather than silently dropping them. Without that
    sentinel, a hostile contributor could swap a registry-backed pin for
    a URL pin and the script would happily report ``OK``.
    """
    entries: list[LockEntry] = []
    # Logical line reconstruction — pip continuations use backslash newlines.
    buffer: list[str] = []
    logical_lines: list[tuple[int, str]] = []  # (1-based source line, joined text)
    start_lineno = 1
    current_start = 1
    for lineno, raw in enumerate(content.splitlines(), start=1):
        if not buffer:
            current_start = lineno
        stripped = raw.rstrip()
        if stripped.endswith("\\"):
            buffer.append(stripped[:-1])
            continue
        buffer.append(stripped)
        logical_lines.append((current_start, " ".join(buffer)))
        buffer = []
        start_lineno = lineno + 1
    if buffer:
        logical_lines.append((current_start, " ".join(buffer)))
    del start_lineno  # silence unused after-loop bookkeeping

    # Pip directives that fetch arbitrary code without ``--hash=``. The
    # first-pass sentinel only catches lines that *try to look like* pinned
    # requirements; these directives sidestep that entirely.
    # Matched as the first whitespace-delimited token on a stripped line.
    _PIP_DIRECTIVE_PREFIXES = (
        "-r", "--requirement",
        "-c", "--constraint",
        "-e", "--editable",
        "-i", "--index-url",
        "--extra-index-url",
        "-f", "--find-links",
        "--trusted-host",
    )
    # Short forms that take an argument and that pip's optparse-based
    # requirements parser accepts in the attached form (``-ihttps://x/``,
    # ``-rfoo.txt``). Without this set, a hostile line ``-ihttps://attacker``
    # would slip past both the exact-equality check and the ``p + "="``
    # startswith check, and would not be parsed as ``name==version`` either.
    _PIP_SHORT_DIRECTIVES = ("-r", "-c", "-e", "-i", "-f")

    for source_line, line in logical_lines:
        # Preserve a copy with comments for sentinel detection, then strip.
        raw_for_check = line
        if "#" in line:
            line = line.split("#", 1)[0]
        line = line.strip()
        if not line:
            continue
        match = _PIP_LINE_RE.match(line)
        hash_matches = _PIP_HASH_RE.findall(line)
        has_hash_token = bool(_PIP_HASH_PRESENT_RE.search(raw_for_check))

        if not match:
            # Any non-conforming line that nonetheless looks like it is
            # *pretending* to be a pinned requirement (has --hash=) must be
            # flagged. Otherwise an attacker can smuggle URL/VCS pins past us.
            if has_hash_token:
                entries.append(
                    LockEntry(
                        ecosystem="pip-suspicious",
                        name="<unparsed>",
                        version="<unparsed>",
                        integrity=_safe(line, max_len=200),
                        location=f"{path}:{source_line}",
                    )
                )
                continue
            # Pip directives (``-r other.txt``, ``-e git+https://...``,
            # ``--index-url https://attacker/``) fetch arbitrary code with
            # no hash check at all. They never carry ``--hash=`` so the
            # sentinel above misses them — flag them on their own merits.
            # Also handle pip's optparse short-attached-arg form
            # (``-ihttps://attacker/``, ``-rfoo.txt``) which would
            # otherwise slip past both the equality and the ``p + "="``
            # check.
            first = line.split(None, 1)[0] if line.split() else ""
            is_directive = (
                first in _PIP_DIRECTIVE_PREFIXES
                or any(first.startswith(p + "=") for p in _PIP_DIRECTIVE_PREFIXES)
                or any(
                    first.startswith(p) and len(first) > len(p)
                    for p in _PIP_SHORT_DIRECTIVES
                )
            )
            if is_directive:
                entries.append(
                    LockEntry(
                        ecosystem="pip-suspicious",
                        name="<directive>",
                        version="<directive>",
                        integrity=_safe(line, max_len=200),
                        location=f"{path}:{source_line}",
                    )
                )
            continue

        name = match.group("name")
        version = match.group("version")
        if not PYPI_NAME_RE.match(name) or not VERSION_RE.match(version):
            continue
        if len(name) > MAX_IDENT_LEN or len(version) > MAX_IDENT_LEN:
            continue
        if not hash_matches:
            # name==version but no recognised hash algorithm. If --hash=
            # appears at all, the algorithm string was malformed/unknown.
            if has_hash_token:
                entries.append(
                    LockEntry(
                        ecosystem="pip-suspicious",
                        name=name,
                        version=version,
                        integrity=_safe(line, max_len=200),
                        location=f"{path}:{source_line}",
                    )
                )
            continue
        # Multiple hashes per line are common (sdist + wheels). Emit one
        # entry per hash so each is checked independently.
        for algo, h in hash_matches:
            algo_l = algo.lower()
            if len(h) != _PIP_HASH_LEN[algo_l]:
                entries.append(
                    LockEntry(
                        ecosystem="pip-suspicious",
                        name=name,
                        version=version,
                        integrity=f"malformed {algo_l} length {len(h)}",
                        location=f"{path}:{source_line}",
                    )
                )
                continue
            entries.append(
                LockEntry(
                    ecosystem="pip",
                    name=name,
                    version=version,
                    integrity=f"{algo_l}:{h.lower()}",
                    location=f"{path}::{name}=={version}",
                )
            )
    return entries


def fetch_pypi_hashes(name: str, version: str) -> set[str]:
    if not PYPI_NAME_RE.match(name):
        raise RegistryError(f"invalid pypi name: {_safe(name)}")
    if not VERSION_RE.match(version):
        raise RegistryError(f"invalid pypi version: {_safe(version)}")
    url = f"https://{PYPI_HOST}/pypi/{name}/{version}/json"
    payload = _http_get_json(url, allowed_hosts=(PYPI_HOST,))
    urls = payload.get("urls")
    if not isinstance(urls, list):
        raise RegistryError(f"no artifacts for {_safe(name)}@{_safe(version)}")
    # Returned as algorithm-prefixed strings ("sha256:abc...", "sha512:...")
    # so the verifier can compare like-for-like across all three algorithms
    # pip itself accepts (PEP 503/440).
    hashes: set[str] = set()
    for artifact in urls:
        if not isinstance(artifact, dict):
            continue
        digests = artifact.get("digests")
        if not isinstance(digests, dict):
            continue
        for algo, expected_len in _PIP_HASH_LEN.items():
            value = digests.get(algo)
            if isinstance(value, str) and len(value) == expected_len and re.fullmatch(r"[0-9a-f]+", value, re.IGNORECASE):
                hashes.add(f"{algo}:{value.lower()}")
    if not hashes:
        raise RegistryError(f"no usable digests for {_safe(name)}@{_safe(version)}")
    return hashes


def compare_pip(local: str, upstream: set[str]) -> bool:
    return local.lower() in {u.lower() for u in upstream}


# ---------------------------------------------------------------------------
# Git diff helpers
# ---------------------------------------------------------------------------


def _run_git(args: list[str]) -> tuple[int, str, str]:
    """Run ``git`` with stdin closed, returning (rc, stdout, stderr).

    Stdout is hard-capped at ``MAX_GIT_STDOUT_BYTES`` to prevent
    attacker-controlled blobs (``git show <ref>:<huge-lockfile>``) or
    pathological repo listings from exhausting CI memory. On overflow
    the subprocess is killed and a non-zero ``rc`` is returned so the
    caller's existing "couldn't read base" branch takes over.
    """
    proc = subprocess.Popen(  # noqa: S603 - args are constants / repo-local paths
        ["git", *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        raw = proc.stdout.read(MAX_GIT_STDOUT_BYTES + 1) if proc.stdout else b""
        err_raw = proc.stderr.read(MAX_GIT_STDOUT_BYTES + 1) if proc.stderr else b""
    finally:
        if len(raw) > MAX_GIT_STDOUT_BYTES:
            proc.kill()
            proc.wait(timeout=5)
            return 1, "", "git stdout exceeded size cap"
        proc.wait(timeout=30)
    stdout = raw.decode("utf-8", errors="replace")
    stderr = err_raw.decode("utf-8", errors="replace")
    return proc.returncode, stdout, stderr


# Strict ref grammar: ascii alphanum + a tightly bounded set of separators
# that suffice for ``origin/main``, ``refs/heads/x``, tags, and 40-char SHAs.
# Disallowed: leading ``-`` (option injection via argv), leading ``.``,
# ``..`` anywhere (git's own check-ref-format rejects these), ``@`` (blocks
# ``@{upstream}`` revision syntax), ``:`` (blocks ``<ref>:<path>``
# smuggling), ``~``/``^`` (revision arithmetic), whitespace.
_REF_RE = re.compile(r"^[A-Za-z0-9_/][A-Za-z0-9_./-]*$")


def _validate_ref(base_ref: str) -> None:
    if not _REF_RE.match(base_ref):
        raise RegistryError(f"invalid base ref: {_safe(base_ref)}")
    if ".." in base_ref:
        # git's check-ref-format forbids ``..`` for the same reason: it
        # collapses path semantics and enables surprising revision ranges.
        raise RegistryError(f"invalid base ref (contains ..): {_safe(base_ref)}")
    if len(base_ref) > 256:
        raise RegistryError(f"base ref too long: {_safe(base_ref)}")


def read_base_blob(base_ref: str, path: str) -> str | None:
    """Return the contents of *path* at *base_ref*, or None if it didn't exist."""
    _validate_ref(base_ref)
    # ``git show <ref>:<path>`` is a single positional; there is no ``--``
    # variant for this syntax. Path safety is bounded by _is_lockfile()
    # (only specific basenames), and the ``:`` separator between ref and
    # path is interpreted by git, not by argv parsing.
    rc, out, _ = _run_git(["show", f"{base_ref}:{path}"])
    if rc != 0:
        return None
    return out


def discover_lockfiles(base_ref: str | None) -> list[str]:
    """Auto-discover lockfiles in the working tree.

    When *base_ref* is supplied and resolves, we restrict the discovery to
    files changed in the diff range — that keeps PR-time runs fast.
    """
    candidates: list[str] = []
    if base_ref:
        _validate_ref(base_ref)
        # ``--`` sentinel prevents any future change to the diff command
        # from accidentally letting a hostile filename be treated as an
        # option. (No PR-author input flows here today, but defense in
        # depth is cheap.)
        rc, out, _ = _run_git(["diff", "--name-only", f"{base_ref}...HEAD", "--"])
        if rc == 0:
            candidates = [line.strip() for line in out.splitlines() if line.strip()]
    if not candidates:
        rc, out, _ = _run_git(["ls-files", "--"])
        if rc == 0:
            candidates = [line.strip() for line in out.splitlines() if line.strip()]
    return [p for p in candidates if _is_lockfile(p)]


def _is_lockfile(path: str) -> bool:
    base = os.path.basename(path)
    if base == "package-lock.json":
        return True
    if base == "Cargo.lock":
        return True
    if base.startswith("requirements") and base.endswith(".txt"):
        return True
    return False


# ---------------------------------------------------------------------------
# Core driver
# ---------------------------------------------------------------------------


def parse_lockfile(path: str, content: str) -> list[LockEntry]:
    base = os.path.basename(path)
    if base == "package-lock.json":
        return parse_npm_lockfile(content, path)
    if base == "Cargo.lock":
        return parse_cargo_lockfile(content, path)
    if base.startswith("requirements") and base.endswith(".txt"):
        return parse_pip_lockfile(content, path)
    return []


def diff_entries(old: list[LockEntry], new: list[LockEntry]) -> list[LockEntry]:
    """Return entries in *new* that are not byte-for-byte in *old*.

    Identity is (ecosystem, name, version, integrity). A version bump, a
    new dependency, or a silent integrity change all qualify.
    """
    key = lambda e: (e.ecosystem, e.name, e.version, e.integrity)  # noqa: E731
    old_keys = {key(e) for e in old}
    return [e for e in new if key(e) not in old_keys]


FetchFn = Callable[[str, str], object]


def verify_entries(
    entries: Iterable[LockEntry],
    report: Report,
    *,
    npm_fetcher: Callable[[str, str], str] = fetch_npm_integrity,
    cargo_fetcher: Callable[[str, str], str] = fetch_cargo_checksum,
    pip_fetcher: Callable[[str, str], set[str]] = fetch_pypi_hashes,
) -> None:
    for entry in entries:
        report.checked += 1
        try:
            if entry.ecosystem == "npm":
                upstream = npm_fetcher(entry.name, entry.version)
                if not compare_npm(entry.integrity, upstream):
                    report.add(Finding(
                        severity="error",
                        entry=entry,
                        message=(
                            f"npm integrity mismatch for {_safe(entry.name)}@"
                            f"{_safe(entry.version)}: lockfile={_safe(entry.integrity)} "
                            f"upstream={_safe(upstream)}"
                        ),
                    ))
            elif entry.ecosystem == "cargo":
                upstream_hex = cargo_fetcher(entry.name, entry.version)
                if not compare_cargo(entry.integrity, upstream_hex):
                    report.add(Finding(
                        severity="error",
                        entry=entry,
                        message=(
                            f"cargo checksum mismatch for {_safe(entry.name)} "
                            f"{_safe(entry.version)}: lockfile={_safe(entry.integrity)} "
                            f"upstream={_safe(upstream_hex)}"
                        ),
                    ))
            elif entry.ecosystem == "pip":
                upstream_set = pip_fetcher(entry.name, entry.version)
                if not compare_pip(entry.integrity, upstream_set):
                    report.add(Finding(
                        severity="error",
                        entry=entry,
                        message=(
                            f"pip hash mismatch for {_safe(entry.name)}=={_safe(entry.version)}: "
                            f"lockfile {_safe(entry.integrity)} not in upstream set "
                            f"of {len(upstream_set)} digest(s)"
                        ),
                    ))
            elif entry.ecosystem == "npm-suspicious":
                # Sentinel for multi-token-same-algorithm SRI in the
                # lockfile (e.g. ``sha512-EVIL sha512-LEGIT``). ssri/npm
                # treats these as alternatives, so an attacker can keep a
                # legit hash and add a hostile-bytes hash side-by-side.
                # Always escalate to manual review.
                report.add(Finding(
                    severity="error",
                    entry=entry,
                    message=(
                        f"npm integrity contains multiple tokens of the same algorithm "
                        f"for {_safe(entry.name)}@{_safe(entry.version)} - this is treated "
                        f"as alternatives by npm/ssri and can mask a tampered payload: "
                        f"{_safe(entry.integrity, max_len=200)}"
                    ),
                ))
            elif entry.ecosystem == "pip-suspicious":
                # Sentinel emitted by parse_pip_lockfile for lines that
                # contain --hash= but do not match the strict registry-
                # backed name==version shape (URL / VCS / unknown algo).
                # These cannot be verified upstream, so flag them for
                # manual review instead of silently dropping.
                report.add(Finding(
                    severity="error",
                    entry=entry,
                    message=(
                        f"unverifiable pinned requirement at {_safe(entry.location)} "
                        f"(direct-URL, VCS, or unknown hash algorithm) - manual review required: "
                        f"{_safe(entry.integrity, max_len=200)}"
                    ),
                ))
            else:  # pragma: no cover - parser would not produce this
                report.skipped += 1
        except RegistryError as exc:
            # Could not confirm: surface as an error so reviewers look at it.
            # Yanked / 404 versions are suspicious in a freshly added entry.
            report.add(Finding(
                severity="error",
                entry=entry,
                message=f"could not verify {_safe(entry.name)}@{_safe(entry.version)}: {_safe(str(exc))}",
            ))


def run(
    paths: list[str],
    *,
    base_ref: str | None,
    max_deps: int,
    npm_fetcher: Callable[[str, str], str] | None = None,
    cargo_fetcher: Callable[[str, str], str] | None = None,
    pip_fetcher: Callable[[str, str], set[str]] | None = None,
    read_base: Callable[[str, str], str | None] = read_base_blob,
) -> Report:
    # Resolve defaults lazily so that test-time monkeypatching of the
    # module-level fetchers is honoured.
    if npm_fetcher is None:
        npm_fetcher = globals()["fetch_npm_integrity"]
    if cargo_fetcher is None:
        cargo_fetcher = globals()["fetch_cargo_checksum"]
    if pip_fetcher is None:
        pip_fetcher = globals()["fetch_pypi_hashes"]
    report = Report()
    all_new: list[LockEntry] = []
    for path in paths:
        try:
            # Bound the on-disk read so a hostile ``package-lock.json``
            # weighing in at multiple GB can't OOM the runner before
            # parsing even begins. Real lockfiles fit comfortably under
            # the cap; oversize files are skipped with a warning.
            if os.path.getsize(path) > MAX_LOCKFILE_BYTES:
                report.add(Finding(
                    severity="warning",
                    entry=LockEntry("warn", path, "", "", path),
                    message=(
                        f"skipping lockfile larger than "
                        f"{MAX_LOCKFILE_BYTES} bytes: {_safe(path)}"
                    ),
                ))
                continue
            with open(path, encoding="utf-8") as fh:
                head_content = fh.read(MAX_LOCKFILE_BYTES + 1)
            if len(head_content) > MAX_LOCKFILE_BYTES:
                report.add(Finding(
                    severity="warning",
                    entry=LockEntry("warn", path, "", "", path),
                    message=f"lockfile exceeded size cap mid-read: {_safe(path)}",
                ))
                continue
        except OSError:
            continue
        head_entries = parse_lockfile(path, head_content)
        base_entries: list[LockEntry] = []
        if base_ref:
            base_content = read_base(base_ref, path)
            if base_content is not None:
                base_entries = parse_lockfile(path, base_content)
        added = diff_entries(base_entries, head_entries) if base_ref else head_entries
        all_new.extend(added)

    if len(all_new) > max_deps:
        report.capped = True
        report.skipped = len(all_new) - max_deps
        all_new = all_new[:max_deps]

    verify_entries(
        all_new,
        report,
        npm_fetcher=npm_fetcher,
        cargo_fetcher=cargo_fetcher,
        pip_fetcher=pip_fetcher,
    )
    return report


def _print_report(report: Report) -> None:
    print(f"Checked {report.checked} lockfile entr{'y' if report.checked == 1 else 'ies'}.")
    if report.capped:
        print(f"DoS cap reached: {report.skipped} additional entr(y/ies) skipped.")
    for finding in report.findings:
        prefix = "ERROR" if finding.severity == "error" else "WARN"
        print(f"  [{prefix}] {_safe(finding.entry.location)}: {finding.message}")
    if not report.findings:
        print("OK: all integrity hashes match upstream registry metadata.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="*", help="Lockfile paths to check (default: auto-discover).")
    parser.add_argument("--base", default="origin/main", help="Base git ref to diff against. Pass empty to scan all entries.")
    parser.add_argument("--max-deps", type=int, default=2000, help="Maximum entries to verify (DoS cap).")
    parser.add_argument("--all", action="store_true", help="Verify every entry, not just added/changed.")
    args = parser.parse_args(argv)

    if args.max_deps < 1:
        print("--max-deps must be >= 1", file=sys.stderr)
        return 3

    base_ref: str | None = None if args.all or not args.base else args.base

    if args.paths:
        paths = [p for p in args.paths if _is_lockfile(p)]
        if not paths:
            print("No recognised lockfiles in the provided paths.")
            return 0
    else:
        paths = discover_lockfiles(base_ref)
        if not paths:
            print("No lockfiles to check.")
            return 0

    report = run(paths, base_ref=base_ref, max_deps=args.max_deps)
    _print_report(report)

    if report.capped:
        return 2
    if report.errors:
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
