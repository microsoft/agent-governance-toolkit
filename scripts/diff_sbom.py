#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Diff two SPDX-JSON SBOMs and render a markdown summary.

Reads a base SBOM (target branch) and a head SBOM (PR), computes the set of
added, removed, and version-bumped packages, and writes a human-readable
markdown report grouped by ecosystem.

Designed for use in the PR-time SBOM diff workflow. Pure stdlib so it can run
in any GitHub-hosted runner without extra installs.

Usage:
    python scripts/diff_sbom.py --base base.spdx.json --head head.spdx.json \
        --output diff.md [--max-added 500]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

# Hard caps to prevent DoS via a flood of new/changed deps. `added` is the
# primary attack surface (transitive creep on a fork PR) but `removed` and
# `bumped` are also bounded so a degenerate diff cannot bust GitHub's 65 KB
# comment cap or run the renderer for minutes.
DEFAULT_MAX_ADDED = 500
DEFAULT_MAX_REMOVED = 500
DEFAULT_MAX_BUMPED = 500

# Hidden marker used by the workflow to find & update the existing PR comment.
COMMENT_MARKER = "<!-- sbom-diff-bot -->"

# Recognised purl ecosystems; anything else falls into "other".
_KNOWN_ECOSYSTEMS = {
    "npm",
    "pypi",
    "cargo",
    "nuget",
    "golang",
    "maven",
    "gem",
    "composer",
    "deb",
    "rpm",
    "apk",
    "github",
    "generic",
}

# Matches a purl: pkg:<type>/<namespace>?/<name>@<version>?...
# Anchored, no backtracking traps; rejects names with shell/HTML metacharacters
# beyond what real purls contain.
_PURL_RE = re.compile(
    r"^pkg:(?P<type>[A-Za-z0-9.+-]+)/"
    r"(?P<path>[^@?#]+)"
    r"(?:@(?P<version>[^?#]+))?"
    r"(?:[?#].*)?$"
)


@dataclass(frozen=True)
class Package:
    """A normalised package coordinate parsed from an SBOM entry."""

    ecosystem: str
    name: str
    version: str


def _sanitize_cell(value: str) -> str:
    """Make a string safe to embed inside a markdown table cell.

    Hostile package names could otherwise inject pipes, backticks, HTML,
    control characters, or @-mentions / #-references into the rendered PR
    comment (log-injection / notification-spam style). Strip CR/LF/control
    chars, escape pipes and backticks, HTML-encode angle brackets, neutralize
    GitHub auto-link triggers (@ and #), and cap length.
    """
    if value is None:
        return "(empty)"
    # Drop CR, LF, NUL, and other C0 control chars (keep tab as space).
    cleaned = "".join(
        " " if ch in ("\t",) else ch
        for ch in value
        if ord(ch) >= 32 and ch not in ("\r", "\n")
    )
    # Escape markdown-significant characters that break tables.
    cleaned = cleaned.replace("\\", "\\\\").replace("|", "\\|").replace("`", "\\`")
    # Strip HTML tag openers so a name like `<script>` cannot break out.
    cleaned = cleaned.replace("<", "&lt;").replace(">", "&gt;")
    # Defuse GitHub auto-links: bot comments would otherwise notify any
    # @user/@org or link to #1234 if a hostile package name embeds them.
    # NOTE: replace `#` BEFORE `@`. Replacing `@` first emits `&#64;`, whose
    # `#` would then be clobbered by the subsequent `#` -> `&#35;` pass.
    cleaned = cleaned.replace("#", "&#35;").replace("@", "&#64;")
    # Length cap protects the comment from giant single fields.
    if len(cleaned) > 200:
        cleaned = cleaned[:197] + "..."
    return cleaned.strip() or "(empty)"


def _parse_purl(purl: str) -> tuple[str, str, str] | None:
    """Return (ecosystem, name, version) from a purl string, or None."""
    if not isinstance(purl, str):
        return None
    match = _PURL_RE.match(purl.strip())
    if not match:
        return None
    eco = match.group("type").lower()
    path = match.group("path")
    version = match.group("version") or ""
    # The last path segment is the package name; preceding segments are the
    # namespace (e.g. @scope for npm, group for maven).
    parts = path.split("/")
    name = parts[-1]
    if len(parts) > 1:
        namespace = "/".join(parts[:-1])
        name = f"{namespace}/{name}"
    if eco not in _KNOWN_ECOSYSTEMS:
        eco = "other"
    return eco, name, version


def _extract_packages(sbom: dict) -> set[Package]:
    """Return the set of packages described by an SPDX-JSON document.

    Falls back to the SPDX `name` / `versionInfo` fields when a package has no
    purl externalRef. Packages that look like SBOM self-references (the root
    document describing itself) are skipped.
    """
    if not isinstance(sbom, dict):
        raise ValueError("SBOM root must be a JSON object")
    packages_raw = sbom.get("packages")
    if packages_raw is None:
        return set()
    if not isinstance(packages_raw, list):
        raise ValueError("'packages' must be a list")

    document_name = sbom.get("name") if isinstance(sbom.get("name"), str) else None
    out: set[Package] = set()
    for entry in packages_raw:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        version = entry.get("versionInfo") or ""
        if not isinstance(name, str) or not name:
            continue
        if not isinstance(version, str):
            version = ""

        # Try purl first for accurate ecosystem identification.
        ecosystem = "other"
        parsed_from_purl = False
        for ref in entry.get("externalRefs", []) or []:
            if not isinstance(ref, dict):
                continue
            if ref.get("referenceType") != "purl":
                continue
            locator = ref.get("referenceLocator", "")
            parsed = _parse_purl(locator)
            if parsed is None:
                continue
            ecosystem, name, purl_version = parsed
            if purl_version:
                version = purl_version
            parsed_from_purl = True
            break

        # Skip the synthetic "root" package that SPDX tools emit to represent
        # the scanned repository itself. We only suppress when ALL of these hold:
        #   1. No PURL was parsed (real dependencies always carry a PURL).
        #   2. The SBOM document has a non-empty name.
        #   3. The package name exactly equals the document name.
        # This avoids accidentally hiding a legitimate dependency that happens
        # to share a name with the document, while still filtering the noise
        # that would otherwise show up as a phantom "added" entry on every PR.
        if not parsed_from_purl and document_name and name == document_name:
            continue

        out.add(Package(ecosystem=ecosystem, name=name, version=version))
    return out


def _index_by_key(packages: Iterable[Package]) -> dict[tuple[str, str], set[str]]:
    """Map (ecosystem, name) -> set of versions seen."""
    idx: dict[tuple[str, str], set[str]] = {}
    for pkg in packages:
        idx.setdefault((pkg.ecosystem, pkg.name), set()).add(pkg.version)
    return idx


@dataclass
class DiffResult:
    """Computed diff between two SBOMs."""

    added: list[Package]
    removed: list[Package]
    bumped: list[tuple[Package, Package]]  # (old, new) sharing ecosystem+name
    truncated_added: int = 0  # entries dropped due to max_added cap
    truncated_removed: int = 0
    truncated_bumped: int = 0

    @property
    def is_empty(self) -> bool:
        return not (self.added or self.removed or self.bumped)


def diff_sboms(
    base: set[Package],
    head: set[Package],
    max_added: int = DEFAULT_MAX_ADDED,
    max_removed: int = DEFAULT_MAX_REMOVED,
    max_bumped: int = DEFAULT_MAX_BUMPED,
) -> DiffResult:
    """Compute the added / removed / bumped diff between two package sets."""
    if max_added < 0 or max_removed < 0 or max_bumped < 0:
        raise ValueError("caps must be non-negative")
    base_idx = _index_by_key(base)
    head_idx = _index_by_key(head)

    added: list[Package] = []
    removed: list[Package] = []
    bumped: list[tuple[Package, Package]] = []

    for key, head_versions in head_idx.items():
        base_versions = base_idx.get(key)
        if base_versions is None:
            for v in sorted(head_versions):
                added.append(Package(key[0], key[1], v))
            continue
        # Same package present on both sides: any version delta is a bump.
        new_versions = head_versions - base_versions
        old_versions = base_versions - head_versions
        if new_versions and old_versions:
            old_pkg = Package(key[0], key[1], sorted(old_versions)[0])
            new_pkg = Package(key[0], key[1], sorted(new_versions)[0])
            bumped.append((old_pkg, new_pkg))

    for key, base_versions in base_idx.items():
        if key not in head_idx:
            for v in sorted(base_versions):
                removed.append(Package(key[0], key[1], v))

    added.sort(key=lambda p: (p.ecosystem, p.name, p.version))
    removed.sort(key=lambda p: (p.ecosystem, p.name, p.version))
    bumped.sort(key=lambda pair: (pair[0].ecosystem, pair[0].name))

    truncated_added = max(0, len(added) - max_added)
    truncated_removed = max(0, len(removed) - max_removed)
    truncated_bumped = max(0, len(bumped) - max_bumped)
    added = added[:max_added]
    removed = removed[:max_removed]
    bumped = bumped[:max_bumped]

    return DiffResult(
        added=added,
        removed=removed,
        bumped=bumped,
        truncated_added=truncated_added,
        truncated_removed=truncated_removed,
        truncated_bumped=truncated_bumped,
    )


def _group_by_ecosystem(pkgs: Iterable[Package]) -> dict[str, list[Package]]:
    grouped: dict[str, list[Package]] = {}
    for pkg in pkgs:
        grouped.setdefault(pkg.ecosystem, []).append(pkg)
    return grouped


def render_markdown(diff: DiffResult, base_ref: str, head_ref: str) -> str:
    """Render a diff as a markdown comment body."""
    safe_base = _sanitize_cell(base_ref or "base")
    safe_head = _sanitize_cell(head_ref or "head")

    lines: list[str] = [
        COMMENT_MARKER,
        "## 📦 Dependency diff (SBOM)",
        "",
        f"Comparing **{safe_base}** → **{safe_head}**.",
        "",
    ]

    if diff.is_empty:
        lines.append("✅ No dependency changes detected.")
        lines.append("")
        return "\n".join(lines)

    totals = (
        f"**Summary:** ➕ {len(diff.added)} added"
        + (f" *(+{diff.truncated_added} more truncated)*" if diff.truncated_added else "")
        + f" · ➖ {len(diff.removed)} removed · 🔄 {len(diff.bumped)} bumped"
    )
    lines.append(totals)
    lines.append("")

    if diff.added:
        lines.append("### ➕ Added")
        lines.append("")
        for eco, pkgs in sorted(_group_by_ecosystem(diff.added).items()):
            lines.append(f"#### `{_sanitize_cell(eco)}` ({len(pkgs)})")
            lines.append("")
            lines.append("| Package | Version |")
            lines.append("|---------|---------|")
            for p in pkgs:
                lines.append(f"| {_sanitize_cell(p.name)} | {_sanitize_cell(p.version)} |")
            lines.append("")
        if diff.truncated_added:
            lines.append(
                f"> ⚠️ Truncated {diff.truncated_added} additional 'added' entries "
                f"(cap = {len(diff.added)}). Inspect the workflow artifact for the full list."
            )
            lines.append("")

    if diff.removed:
        lines.append("### ➖ Removed")
        lines.append("")
        for eco, pkgs in sorted(_group_by_ecosystem(diff.removed).items()):
            lines.append(f"#### `{_sanitize_cell(eco)}` ({len(pkgs)})")
            lines.append("")
            lines.append("| Package | Version |")
            lines.append("|---------|---------|")
            for p in pkgs:
                lines.append(f"| {_sanitize_cell(p.name)} | {_sanitize_cell(p.version)} |")
            lines.append("")
        if diff.truncated_removed:
            lines.append(
                f"> ⚠️ Truncated {diff.truncated_removed} additional 'removed' entries "
                f"(cap = {len(diff.removed)}). Inspect the workflow artifact for the full list."
            )
            lines.append("")

    if diff.bumped:
        lines.append("### 🔄 Bumped")
        lines.append("")
        grouped_bumps: dict[str, list[tuple[Package, Package]]] = {}
        for old, new in diff.bumped:
            grouped_bumps.setdefault(old.ecosystem, []).append((old, new))
        for eco, pairs in sorted(grouped_bumps.items()):
            lines.append(f"#### `{_sanitize_cell(eco)}` ({len(pairs)})")
            lines.append("")
            lines.append("| Package | From | To |")
            lines.append("|---------|------|----|")
            for old, new in pairs:
                lines.append(
                    f"| {_sanitize_cell(old.name)} "
                    f"| {_sanitize_cell(old.version)} "
                    f"| {_sanitize_cell(new.version)} |"
                )
            lines.append("")
        if diff.truncated_bumped:
            lines.append(
                f"> ⚠️ Truncated {diff.truncated_bumped} additional 'bumped' entries "
                f"(cap = {len(diff.bumped)}). Inspect the workflow artifact for the full list."
            )
            lines.append("")

    lines.append("")
    return "\n".join(lines)


# Hard ceiling on the on-disk SBOM size, in bytes, before we even attempt to
# parse JSON. The trusted workflow downloads this artifact from an untrusted
# producer; oversized blobs must fail fast rather than balloon Python memory.
# 64 MiB is well above any realistic SBOM for this repo.
DEFAULT_MAX_SBOM_BYTES = 64 * 1024 * 1024


def _load_sbom(path: Path, max_bytes: int = DEFAULT_MAX_SBOM_BYTES) -> dict:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ValueError(f"Failed to stat SBOM at {path}: {exc}") from exc
    if size > max_bytes:
        raise ValueError(
            f"SBOM at {path} is {size} bytes, exceeds cap of {max_bytes} bytes"
        )
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Failed to read SBOM at {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"SBOM at {path} must be a JSON object")
    return data


def run(
    base_path: Path,
    head_path: Path,
    output_path: Path,
    base_ref: str,
    head_ref: str,
    max_added: int = DEFAULT_MAX_ADDED,
    max_removed: int = DEFAULT_MAX_REMOVED,
    max_bumped: int = DEFAULT_MAX_BUMPED,
    max_sbom_bytes: int = DEFAULT_MAX_SBOM_BYTES,
) -> DiffResult:
    """End-to-end: load both SBOMs, diff, write markdown to output_path."""
    base_sbom = _load_sbom(base_path, max_bytes=max_sbom_bytes)
    head_sbom = _load_sbom(head_path, max_bytes=max_sbom_bytes)
    base_pkgs = _extract_packages(base_sbom)
    head_pkgs = _extract_packages(head_sbom)
    diff = diff_sboms(
        base_pkgs,
        head_pkgs,
        max_added=max_added,
        max_removed=max_removed,
        max_bumped=max_bumped,
    )
    markdown = render_markdown(diff, base_ref=base_ref, head_ref=head_ref)
    output_path.write_text(markdown, encoding="utf-8")
    return diff


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Diff two SPDX-JSON SBOMs into a markdown report.")
    p.add_argument("--base", required=True, type=Path, help="Path to base SBOM (SPDX-JSON).")
    p.add_argument("--head", required=True, type=Path, help="Path to head SBOM (SPDX-JSON).")
    p.add_argument("--output", required=True, type=Path, help="Path to write markdown report.")
    p.add_argument("--base-ref", default="base", help="Human label for the base ref.")
    p.add_argument("--head-ref", default="head", help="Human label for the head ref.")
    p.add_argument(
        "--max-added",
        type=int,
        default=DEFAULT_MAX_ADDED,
        help=f"Cap on rendered 'added' entries (default: {DEFAULT_MAX_ADDED}).",
    )
    p.add_argument(
        "--max-removed",
        type=int,
        default=DEFAULT_MAX_REMOVED,
        help=f"Cap on rendered 'removed' entries (default: {DEFAULT_MAX_REMOVED}).",
    )
    p.add_argument(
        "--max-bumped",
        type=int,
        default=DEFAULT_MAX_BUMPED,
        help=f"Cap on rendered 'bumped' entries (default: {DEFAULT_MAX_BUMPED}).",
    )
    p.add_argument(
        "--max-sbom-bytes",
        type=int,
        default=DEFAULT_MAX_SBOM_BYTES,
        help=f"Reject SBOMs larger than this (default: {DEFAULT_MAX_SBOM_BYTES} bytes).",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        diff = run(
            base_path=args.base,
            head_path=args.head,
            output_path=args.output,
            base_ref=args.base_ref,
            head_ref=args.head_ref,
            max_added=args.max_added,
            max_removed=args.max_removed,
            max_bumped=args.max_bumped,
            max_sbom_bytes=args.max_sbom_bytes,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    summary = (
        f"sbom-diff: +{len(diff.added)} added "
        f"(truncated {diff.truncated_added}), "
        f"-{len(diff.removed)} removed "
        f"(truncated {diff.truncated_removed}), "
        f"~{len(diff.bumped)} bumped "
        f"(truncated {diff.truncated_bumped})"
    )
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
