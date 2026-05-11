# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Supply chain security guards for AI agent dependency management.

Detects supply chain poisoning attempts including:
- Freshly published package versions (< 7 days)
- Unpinned dependency versions (^ or ~ ranges)
- Typosquatting on popular package names
- Sudden maintainer changes
- Suspicious release patterns
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from difflib import SequenceMatcher
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Popular packages list for typosquatting detection
# ---------------------------------------------------------------------------

KNOWN_POPULAR_PACKAGES: dict[str, set[str]] = {
    "pypi": {
        "requests", "flask", "django", "numpy", "pandas", "scipy", "torch",
        "tensorflow", "transformers", "openai", "anthropic", "langchain",
        "fastapi", "pydantic", "cryptography", "boto3", "azure-identity",
        "pillow", "matplotlib", "scikit-learn", "pytest", "httpx",
    },
    "npm": {
        "express", "react", "axios", "lodash", "typescript", "webpack",
        "next", "vue", "angular", "jest", "mocha", "eslint", "prettier",
        "@modelcontextprotocol/sdk",
    },
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SupplyChainFinding:
    """A supply chain risk finding."""

    package: str
    version: str
    severity: str  # "critical", "high", "medium", "low"
    rule: str      # rule identifier
    message: str


@dataclass
class SupplyChainConfig:
    """Configuration for supply chain checks."""

    freshness_days: int = 7
    allow_ranges: bool = False
    known_packages: Optional[set[str]] = None
    typosquat_threshold: float = 0.85
    # Directory names skipped during recursive scan_directory walks.
    # Vendored dependencies under node_modules/.venv/etc. are not the
    # repository's own supply chain — flagging them would generate
    # noise proportional to dependency-tree size and could leak
    # version data the operator never committed.
    scan_exclude_dirs: frozenset[str] = field(
        default_factory=lambda: frozenset({
            "node_modules",
            ".venv",
            "venv",
            ".tox",
            ".nox",
            "dist",
            "build",
            "__pycache__",
            ".git",
            ".hg",
            ".svn",
            "target",  # Cargo build output
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
        })
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_RANGE_RE = re.compile(r"[\^~]")
_PEP508_PINNED = re.compile(r"==\s*\S+")
_LOOSE_CONSTRAINT = re.compile(r"(>=|<=|~=|!=|>|<)")
# Strict MAJOR.MINOR.PATCH (with optional prerelease/build) used by
# both the Poetry inline-table check and the npm version classifier.
_EXACT_SEMVER = re.compile(
    r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)

# npm version specifiers that bypass the registry trust boundary entirely
# (git URLs, local files, tarballs over HTTP, npm aliases pointing at
# arbitrary registered packages). None of these constitute a pinned
# semver and cannot be reproduced from an SBOM alone.
_NPM_PROTOCOL_PREFIXES = (
    "git+",
    "git://",
    "git@",
    "github:",
    "gitlab:",
    "bitbucket:",
    "gist:",
    "file:",
    "link:",
    "http://",
    "https://",
    "npm:",
    "workspace:",
)

# Wildcard / dist-tag specifiers that resolve dynamically at install time.
_NPM_WILDCARD_SPECIFIERS = {"*", "latest", "next", "x", "X", ""}

# Strict semver match: MAJOR.MINOR.PATCH with optional prerelease/build.
_NPM_EXACT_SEMVER = re.compile(
    r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)


def _classify_npm_version(version: str) -> tuple[str, str] | None:
    """Return (rule, message) when ``version`` is non-pinned, else None.

    Distinguishes three failure modes so operators can triage:
      * ``non-semver-specifier`` — git/file/http/npm-alias prefixes that
        bypass the registry's published-artifact trust boundary entirely
      * ``wildcard-specifier``  — ``*`` / ``latest`` / ``next`` / ``x``
        which resolve to a different artifact every install
      * ``unpinned-range``      — ``^`` / ``~`` / ``>=`` / etc.
    """
    raw = version.strip()
    lower = raw.lower()

    for prefix in _NPM_PROTOCOL_PREFIXES:
        if lower.startswith(prefix):
            return (
                "non-semver-specifier",
                f"uses a non-registry source ('{raw}'); pin to an exact "
                "semver published on the configured registry instead.",
            )

    if raw in _NPM_WILDCARD_SPECIFIERS:
        return (
            "wildcard-specifier",
            f"resolves dynamically ('{raw}'); pin to an exact semver.",
        )

    if _RANGE_RE.search(raw) or _LOOSE_CONSTRAINT.search(raw):
        return (
            "unpinned-range",
            f"uses a range specifier ('{raw}'). Pin to an exact version.",
        )

    if not _NPM_EXACT_SEMVER.match(raw):
        return (
            "non-semver-specifier",
            f"is not a strict MAJOR.MINOR.PATCH semver ('{raw}'); "
            "pin to an exact published version.",
        )

    return None


def _similarity(a: str, b: str) -> float:
    """Return SequenceMatcher ratio between two strings."""
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def _parse_requirements_line(line: str) -> tuple[str, str] | None:
    """Parse a single requirements.txt line into (name, version_spec).

    Returns ``None`` for blank lines, comments, and options.
    """
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("-"):
        return None
    # Strip inline comments and environment markers
    line = line.split("#")[0].split(";")[0].strip()
    if not line:
        return None

    # Split on version specifier operators
    for op in ("===", "==", "~=", "!=", ">=", "<=", ">", "<"):
        if op in line:
            idx = line.index(op)
            name = line[:idx].strip()
            version = line[idx:].strip()
            return name, version

    # No version specifier at all
    return line, ""


# ---------------------------------------------------------------------------
# SupplyChainGuard
# ---------------------------------------------------------------------------

class SupplyChainGuard:
    """Detects supply chain poisoning in agent dependencies."""

    def __init__(self, config: SupplyChainConfig | None = None) -> None:
        self.config = config or SupplyChainConfig()

    # ------------------------------------------------------------------
    # requirements.txt
    # ------------------------------------------------------------------

    def check_requirements(self, path: str) -> list[SupplyChainFinding]:
        """Check a requirements.txt file for supply chain risks."""
        findings: list[SupplyChainFinding] = []
        text = Path(path).read_text(encoding="utf-8")

        for line in text.splitlines():
            parsed = _parse_requirements_line(line)
            if parsed is None:
                continue
            name, version_spec = parsed

            if not _PEP508_PINNED.search(version_spec):
                findings.append(SupplyChainFinding(
                    package=name,
                    version=version_spec or "unspecified",
                    severity="high",
                    rule="unpinned-version",
                    message=f"Package '{name}' is not pinned to an exact version (==).",
                ))

            typo = self.check_typosquatting(name, ecosystem="pypi")
            if typo:
                findings.append(typo)

        return findings

    # ------------------------------------------------------------------
    # package.json
    # ------------------------------------------------------------------

    def check_package_json(self, path: str) -> list[SupplyChainFinding]:
        """Check a package.json for unpinned versions.

        Catches three failure modes:
          * registry-bypassing protocol specifiers
            (``git+https://…``, ``file:…``, ``http://…``, ``npm:…@*``)
          * wildcard / dist-tag specifiers (``*``, ``latest``, ``next``)
          * standard unpinned ranges (``^1.0.0``, ``~1.2``, ``>=1``)

        ``allow_ranges`` only suppresses the third category; protocol
        and wildcard specifiers are flagged regardless because they
        sidestep the registry trust boundary entirely.
        """
        findings: list[SupplyChainFinding] = []
        data = json.loads(Path(path).read_text(encoding="utf-8"))

        for section in ("dependencies", "devDependencies"):
            deps = data.get(section, {})
            for name, version in deps.items():
                if not isinstance(version, str):
                    # package.json schema allows objects in some niche
                    # cases (e.g., bundled deps), but a non-string here
                    # is unusual enough to flag.
                    findings.append(SupplyChainFinding(
                        package=name,
                        version=str(version),
                        severity="high",
                        rule="non-semver-specifier",
                        message=(
                            f"Package '{name}' has a non-string version "
                            f"({type(version).__name__}); pin to an exact "
                            "semver string."
                        ),
                    ))
                else:
                    classification = _classify_npm_version(version)
                    if classification is not None:
                        rule, message = classification
                        # ``allow_ranges`` only relaxes the unpinned-range
                        # rule, never the protocol/wildcard rules.
                        if rule == "unpinned-range" and self.config.allow_ranges:
                            classification = None
                    if classification is not None:
                        rule, message = classification
                        severity = (
                            "high"
                            if rule in ("non-semver-specifier", "wildcard-specifier")
                            else "medium"
                        )
                        findings.append(SupplyChainFinding(
                            package=name,
                            version=version,
                            severity=severity,
                            rule=rule,
                            message=f"Package '{name}' {message}",
                        ))

                typo = self.check_typosquatting(name, ecosystem="npm")
                if typo:
                    findings.append(typo)

        return findings

    # ------------------------------------------------------------------
    # pyproject.toml (tomllib-based, stdlib only)
    # ------------------------------------------------------------------

    def check_pyproject(self, path: str) -> list[SupplyChainFinding]:
        """Check pyproject.toml for loose version constraints.

        Uses ``tomllib`` (Python 3.11+) so the following layouts are all
        covered, including ones the prior string-match-based parser
        silently skipped:

          * ``[project] dependencies = [...]``                (PEP 621)
          * ``[project.optional-dependencies]``               (PEP 621)
          * ``[tool.poetry.dependencies]``                    (Poetry)
          * ``[tool.poetry.dev-dependencies]``                (Poetry, legacy)
          * ``[tool.poetry.group.<name>.dependencies]``       (Poetry, modern)

        Multiline list entries, comments, environment markers, and
        Poetry table-form deps (``foo = {git = "...", rev = "..."}``)
        are handled correctly via the TOML parser instead of being
        misread as regular version strings.
        """
        try:
            import tomllib
        except ImportError:  # Python < 3.11 fallback
            import tomli as tomllib  # type: ignore[no-redef]

        findings: list[SupplyChainFinding] = []
        try:
            with open(path, "rb") as fh:
                data = tomllib.load(fh)
        except (OSError, tomllib.TOMLDecodeError):
            return findings

        # PEP 621: [project] dependencies = ["pep508-string", ...]
        project = data.get("project", {})
        for dep_str in project.get("dependencies", []) or []:
            self._emit_pep508_finding(findings, dep_str)

        # PEP 621: [project.optional-dependencies] with grouped lists
        optional = project.get("optional-dependencies", {}) or {}
        for group_deps in optional.values():
            for dep_str in group_deps or []:
                self._emit_pep508_finding(findings, dep_str)

        # Poetry: [tool.poetry.dependencies] / [tool.poetry.dev-dependencies]
        poetry = data.get("tool", {}).get("poetry", {}) or {}
        self._emit_poetry_findings(findings, poetry.get("dependencies", {}) or {})
        self._emit_poetry_findings(findings, poetry.get("dev-dependencies", {}) or {})

        # Poetry modern: [tool.poetry.group.<name>.dependencies]
        for group in (poetry.get("group", {}) or {}).values():
            self._emit_poetry_findings(findings, group.get("dependencies", {}) or {})

        return findings

    def _emit_pep508_finding(
        self, findings: list[SupplyChainFinding], dep_str: str,
    ) -> None:
        if not isinstance(dep_str, str):
            return
        parsed = _parse_requirements_line(dep_str)
        if not parsed:
            return
        name, version_spec = parsed
        if _PEP508_PINNED.search(version_spec):
            return
        findings.append(SupplyChainFinding(
            package=name,
            version=version_spec or "unspecified",
            severity="medium",
            rule="loose-constraint",
            message=(
                f"Package '{name}' in pyproject.toml uses a loose "
                "version constraint."
            ),
        ))

    def _emit_poetry_findings(
        self, findings: list[SupplyChainFinding], deps: dict,
    ) -> None:
        for name, spec in deps.items():
            if name == "python":
                # The Poetry dependencies table embeds the Python version
                # constraint under the "python" key — that's not a
                # supply-chain dependency and shouldn't surface here.
                continue
            if isinstance(spec, str):
                if not _EXACT_SEMVER.match(spec.strip()):
                    findings.append(SupplyChainFinding(
                        package=name,
                        version=spec,
                        severity="medium",
                        rule="loose-constraint",
                        message=(
                            f"Package '{name}' in pyproject.toml uses a "
                            f"loose version constraint ('{spec}')."
                        ),
                    ))
            elif isinstance(spec, dict):
                # Poetry table-form: foo = {version="^1.0"} or
                # foo = {git="...", rev="..."} or foo = {path="..."}.
                # The git/path/url forms bypass the package index trust
                # boundary entirely.
                for protocol_key in ("git", "url", "path"):
                    if protocol_key in spec:
                        findings.append(SupplyChainFinding(
                            package=name,
                            version=str(spec.get(protocol_key, "")),
                            severity="high",
                            rule="non-semver-specifier",
                            message=(
                                f"Package '{name}' in pyproject.toml is "
                                f"sourced via '{protocol_key}=' "
                                f"({spec.get(protocol_key)!r}); pin to an "
                                "exact published version on the configured "
                                "index instead."
                            ),
                        ))
                        break
                else:
                    inline_version = spec.get("version")
                    if isinstance(inline_version, str) and not _EXACT_SEMVER.match(
                        inline_version.strip()
                    ):
                        findings.append(SupplyChainFinding(
                            package=name,
                            version=inline_version,
                            severity="medium",
                            rule="loose-constraint",
                            message=(
                                f"Package '{name}' in pyproject.toml uses a "
                                f"loose version constraint "
                                f"('{inline_version}')."
                            ),
                        ))

    # ------------------------------------------------------------------
    # Cargo.toml (tomllib-based, stdlib only)
    # ------------------------------------------------------------------

    def check_cargo_toml(self, path: str) -> list[SupplyChainFinding]:
        """Check Cargo.toml for unpinned versions.

        Uses ``tomllib`` (Python 3.11+) so the following layouts are all
        covered, including ones the prior regex-based parser silently
        skipped:

          * ``[dependencies]``                   (standard)
          * ``[dev-dependencies]``               (dev)
          * ``[build-dependencies]``             (build scripts)
          * ``[target.'cfg(...)'.dependencies]``  (platform-specific)
          * Table-form deps: ``foo = { git = "...", rev = "..." }``
          * Table-form deps: ``foo = { path = "../local" }``
          * Workspace-inherited: ``foo = { workspace = true }``
        """
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore[no-redef]

        findings: list[SupplyChainFinding] = []
        try:
            with open(path, "rb") as fh:
                data = tomllib.load(fh)
        except (OSError, tomllib.TOMLDecodeError):
            return findings

        dep_tables: list[dict] = []
        for key in ("dependencies", "dev-dependencies", "build-dependencies"):
            deps = data.get(key)
            if isinstance(deps, dict):
                dep_tables.append(deps)

        # Target-specific: [target.'cfg(...)'.dependencies]
        for target_cfg in (data.get("target") or {}).values():
            if isinstance(target_cfg, dict):
                for key in ("dependencies", "dev-dependencies", "build-dependencies"):
                    deps = target_cfg.get(key)
                    if isinstance(deps, dict):
                        dep_tables.append(deps)

        for deps in dep_tables:
            for name, spec in deps.items():
                self._emit_cargo_finding(findings, name, spec)

        return findings

    def _emit_cargo_finding(
        self, findings: list[SupplyChainFinding], name: str, spec: object,
    ) -> None:
        """Classify a single Cargo dependency and emit a finding if needed."""
        if isinstance(spec, str):
            if not _EXACT_SEMVER.match(spec.strip()):
                findings.append(SupplyChainFinding(
                    package=name,
                    version=spec,
                    severity="medium",
                    rule="unpinned-cargo",
                    message=(
                        f"Crate '{name}' version '{spec}' is not "
                        f"pinned to an exact semver."
                    ),
                ))
        elif isinstance(spec, dict):
            for protocol_key in ("git", "path"):
                if protocol_key in spec:
                    findings.append(SupplyChainFinding(
                        package=name,
                        version=str(spec.get(protocol_key, "")),
                        severity="high",
                        rule="non-registry-source",
                        message=(
                            f"Crate '{name}' is sourced via "
                            f"'{protocol_key}=' ({spec.get(protocol_key)!r})"
                            "; pin to an exact version published on "
                            "crates.io instead."
                        ),
                    ))
                    return
            if spec.get("workspace") is True:
                return
            inline_version = spec.get("version")
            if isinstance(inline_version, str) and not _EXACT_SEMVER.match(
                inline_version.strip()
            ):
                findings.append(SupplyChainFinding(
                    package=name,
                    version=inline_version,
                    severity="medium",
                    rule="unpinned-cargo",
                    message=(
                        f"Crate '{name}' version '{inline_version}' is not "
                        f"pinned to an exact semver."
                    ),
                ))

    # ------------------------------------------------------------------
    # Freshness (offline)
    # ------------------------------------------------------------------

    def check_freshness(
        self,
        package: str,
        version: str,
        publish_time: datetime,
        ecosystem: str = "pypi",
    ) -> SupplyChainFinding | None:
        """Check if a package version was published within the freshness window.

        Does NOT call external APIs — compares against a provided timestamp.
        For actual freshness checks, use ``check_freshness_live()``.

        A future ``publish_time`` (clock skew, tampered registry response,
        or a deliberately spoofed timestamp meant to dodge the
        backdated-package defense) is reported as a separate
        ``future-timestamp`` finding rather than silently triggering the
        "fresh-publish" branch via a negative delta.
        """
        now = datetime.now(timezone.utc)
        if publish_time.tzinfo is None:
            publish_time = publish_time.replace(tzinfo=timezone.utc)

        # A future publish_time is itself a red flag — clamp the delta to
        # zero for the recent-publish check and emit a distinct finding so
        # the operator can see the spoofed/tampered timestamp directly
        # instead of having it masquerade as a normal recent publish.
        if publish_time > now:
            return SupplyChainFinding(
                package=package,
                version=version,
                severity="high",
                rule="future-timestamp",
                message=(
                    f"Package '{package}=={version}' has a publish timestamp "
                    f"{(publish_time - now).total_seconds():.0f}s in the "
                    "future — possible clock skew, tampered registry "
                    "response, or backdating-defense evasion."
                ),
            )

        delta = now - publish_time
        if delta < timedelta(days=self.config.freshness_days):
            return SupplyChainFinding(
                package=package,
                version=version,
                severity="high",
                rule="fresh-publish",
                message=(
                    f"Package '{package}=={version}' was published only "
                    f"{delta.days} day(s) ago "
                    f"(threshold: {self.config.freshness_days} days)."
                ),
            )
        return None

    # ------------------------------------------------------------------
    # Freshness (live – optional network)
    # ------------------------------------------------------------------

    def check_freshness_live(
        self,
        package: str,
        version: str,
        ecosystem: str = "pypi",
    ) -> SupplyChainFinding | None:
        """Check version freshness against live registry (PyPI, npm).

        Calls PyPI JSON API or npm registry.
        Returns finding if version < freshness_days old.
        """
        import urllib.request
        import urllib.error

        try:
            if ecosystem == "pypi":
                url = f"https://pypi.org/pypi/{package}/{version}/json"
                req = urllib.request.Request(url, headers={"Accept": "application/json"})  # noqa: S310 — URL from configured registry endpoint
                with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 — URL from configured registry endpoint
                    data = json.loads(resp.read().decode())
                upload_time_str = data.get("urls", [{}])[0].get("upload_time_iso_8601")
                if not upload_time_str:
                    upload_time_str = data.get("info", {}).get("upload_time")
                if upload_time_str:
                    publish_time = datetime.fromisoformat(
                        upload_time_str.replace("Z", "+00:00")
                    )
                    return self.check_freshness(package, version, publish_time, ecosystem)

            elif ecosystem == "npm":
                url = f"https://registry.npmjs.org/{package}"
                req = urllib.request.Request(url, headers={"Accept": "application/json"})  # noqa: S310 — URL from configured registry endpoint
                with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 — URL from configured registry endpoint
                    data = json.loads(resp.read().decode())
                time_entry = data.get("time", {}).get(version)
                if time_entry:
                    publish_time = datetime.fromisoformat(
                        time_entry.replace("Z", "+00:00")
                    )
                    return self.check_freshness(package, version, publish_time, ecosystem)

        except (urllib.error.URLError, OSError, json.JSONDecodeError, KeyError):
            pass

        return None

    # ------------------------------------------------------------------
    # Typosquatting
    # ------------------------------------------------------------------

    def check_typosquatting(
        self,
        package: str,
        ecosystem: str = "pypi",
    ) -> SupplyChainFinding | None:
        """Check if package name is suspiciously similar to a popular package."""
        allowlist = self.config.known_packages or set()
        if package in allowlist:
            return None

        popular = KNOWN_POPULAR_PACKAGES.get(ecosystem, set())

        if package in popular:
            return None

        for known in popular:
            sim = _similarity(package, known)
            if sim >= self.config.typosquat_threshold and package != known:
                return SupplyChainFinding(
                    package=package,
                    version="*",
                    severity="critical",
                    rule="typosquat",
                    message=(
                        f"Package '{package}' is suspiciously similar to "
                        f"'{known}' (similarity={sim:.2f}). "
                        f"Possible typosquatting."
                    ),
                )

        return None

    # ------------------------------------------------------------------
    # Directory scan
    # ------------------------------------------------------------------

    def scan_directory(self, directory: str) -> list[SupplyChainFinding]:
        """Scan a directory recursively for dependency manifests.

        Walks ``directory`` and every subdirectory, picking up
        ``requirements*.txt``, ``package.json``, ``pyproject.toml``, and
        ``Cargo.toml``. Subdirectories named in
        ``SupplyChainConfig.scan_exclude_dirs`` (``node_modules``,
        ``.venv``, ``dist``, ``build``, ``target``, etc.) are skipped
        so vendored dependencies and build output don't drown the
        repository's own manifests in noise.
        """
        findings: list[SupplyChainFinding] = []
        root = Path(directory)
        excluded = self.config.scan_exclude_dirs

        for path in self._iter_manifest_files(root, excluded):
            name = path.name
            if name.startswith("requirements") and name.endswith(".txt"):
                findings.extend(self.check_requirements(str(path)))
            elif name == "package.json":
                findings.extend(self.check_package_json(str(path)))
            elif name == "pyproject.toml":
                findings.extend(self.check_pyproject(str(path)))
            elif name == "Cargo.toml":
                findings.extend(self.check_cargo_toml(str(path)))

        return findings

    @staticmethod
    def _iter_manifest_files(
        root: Path, excluded: "frozenset[str]"
    ) -> "list[Path]":
        """Walk ``root`` recursively, yielding manifest files outside
        any excluded directory.

        Uses os.walk so we can prune subtrees in-place — rglob would
        descend into node_modules and .venv before the filter could
        reject the matches.
        """
        results: list[Path] = []
        manifest_names = {"package.json", "pyproject.toml", "Cargo.toml"}
        for dirpath, dirnames, filenames in os.walk(root):
            # Prune excluded subdirectories so the walk doesn't descend
            # into them — purely a noise/perf measure for monorepos.
            dirnames[:] = [d for d in dirnames if d not in excluded]
            for filename in filenames:
                if (
                    filename in manifest_names
                    or (filename.startswith("requirements") and filename.endswith(".txt"))
                ):
                    results.append(Path(dirpath) / filename)
        return results

    # ------------------------------------------------------------------
    # Lockfile drift
    # ------------------------------------------------------------------

    def scan_lockfile_drift(
        self,
        manifest_path: str,
        lock_path: str,
    ) -> list[SupplyChainFinding]:
        """Check if lockfile is in sync with manifest.

        Compares package names in the manifest against those in the
        lockfile and flags any that are missing from the lock.
        """
        findings: list[SupplyChainFinding] = []
        manifest = Path(manifest_path)
        lock = Path(lock_path)

        if not lock.exists():
            findings.append(SupplyChainFinding(
                package="*",
                version="*",
                severity="high",
                rule="missing-lockfile",
                message=f"Lockfile '{lock_path}' does not exist.",
            ))
            return findings

        lock_text = lock.read_text(encoding="utf-8").lower()

        if manifest.name == "package.json":
            data = json.loads(manifest.read_text(encoding="utf-8"))
            for section in ("dependencies", "devDependencies"):
                for pkg in data.get(section, {}):
                    if pkg.lower() not in lock_text:
                        findings.append(SupplyChainFinding(
                            package=pkg,
                            version="*",
                            severity="medium",
                            rule="lockfile-drift",
                            message=(
                                f"Package '{pkg}' in manifest but not found "
                                f"in lockfile."
                            ),
                        ))
        else:
            # requirements.txt style
            text = manifest.read_text(encoding="utf-8")
            for line in text.splitlines():
                parsed = _parse_requirements_line(line)
                if parsed:
                    name, _ = parsed
                    if name.lower() not in lock_text:
                        findings.append(SupplyChainFinding(
                            package=name,
                            version="*",
                            severity="medium",
                            rule="lockfile-drift",
                            message=(
                                f"Package '{name}' in manifest but not found "
                                f"in lockfile."
                            ),
                        ))

        return findings
