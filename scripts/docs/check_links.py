#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Validate relative markdown links across the docs tree.

Scans every Markdown file under the given roots (default: ``docs/`` and
top-level ``*.md`` files) and reports broken relative links. External
links (``http://``, ``https://``, ``mailto:``) and pure in-page anchors
are not network-validated; only filesystem-resolvable targets are
checked. Heading anchors inside the target Markdown file are verified
when present.

Usage::

    python scripts/docs/check_links.py
    python scripts/docs/check_links.py docs/security/threat-model.md
    python scripts/docs/check_links.py --root . --json

Exit codes:
    0 - no broken links
    1 - broken links detected
    2 - usage / invocation error
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable
from urllib.parse import unquote, urlparse

# ---------------------------------------------------------------------------
# Markdown parsing
# ---------------------------------------------------------------------------

# Inline link:  [text](target "optional title")
# Skips images by ensuring no preceding '!'. The optional title is dropped.
# The character class in the text group deliberately excludes '\' so the
# only branch that can consume a backslash is the explicit '\\.' escape.
# This removes the alternation ambiguity that triggers CodeQL py/redos
# (exponential backtracking on pathological input).
_INLINE_LINK_RE = re.compile(
    r"(?<!\!)\[(?P<text>(?:[^\[\]\\]|\\.)*?)\]\((?P<target>[^)\s]+)(?:\s+\"[^\"]*\")?\)"
)

# Reference-style link definition:  [label]: target "optional title"
_REF_DEF_RE = re.compile(
    r"^\s{0,3}\[(?P<label>[^\]]+)\]:\s*<?(?P<target>\S+?)>?(?:\s+\"[^\"]*\")?\s*$",
    re.MULTILINE,
)

# Reference-style link use:  [text][label]   or shortcut  [label][]
_REF_USE_RE = re.compile(r"(?<!\!)\[(?P<text>[^\[\]]+)\]\[(?P<label>[^\]]*)\]")

# Fenced code block fence (``` or ~~~), with optional language
_FENCE_RE = re.compile(r"^(?P<fence>`{3,}|~{3,})")


def _strip_code_blocks(text: str) -> str:
    """Return ``text`` with fenced code block contents replaced by blanks.

    Keeps line numbering stable so downstream line reporting matches the
    original file. Inline code spans (single backticks) are left alone —
    markdown parsers do treat ``[x](y)`` inside them as literal, but the
    cost of mis-flagging an inline code example is low and the parsing
    cost of doing it correctly is high.
    """
    out: list[str] = []
    in_fence = False
    fence_marker = ""
    for line in text.splitlines():
        m = _FENCE_RE.match(line.lstrip())
        if m:
            marker = m.group("fence")[0]  # ` or ~
            if not in_fence:
                in_fence = True
                fence_marker = marker
                out.append("")
                continue
            if in_fence and line.lstrip().startswith(fence_marker * 3):
                in_fence = False
                fence_marker = ""
                out.append("")
                continue
        out.append("" if in_fence else line)
    return "\n".join(out)


def _slugify_heading(text: str) -> str:
    """Approximate GitHub/MkDocs heading-to-anchor slugification.

    Lower-cases, strips Markdown formatting, replaces spaces with hyphens,
    drops characters other than letters, digits, hyphen, underscore.
    """
    # Strip inline markdown emphasis/code markers
    text = re.sub(r"[`*_~]", "", text)
    # Strip link wrappers but keep the link text
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = text.strip().lower()
    text = re.sub(r"\s+", "-", text)
    text = re.sub(r"[^\w\-]", "", text)
    return text


def _extract_anchors(markdown: str) -> set[str]:
    """Return the set of anchor slugs defined by headings in ``markdown``."""
    anchors: set[str] = set()
    stripped = _strip_code_blocks(markdown)
    for line in stripped.splitlines():
        m = re.match(r"^(#{1,6})\s+(.+?)\s*#*\s*$", line)
        if m:
            anchors.add(_slugify_heading(m.group(2)))
    # Also accept explicit HTML anchors like <a id="foo"></a> or <a name="foo">
    for m in re.finditer(r"<a\s+(?:id|name)=\"([^\"]+)\"", markdown):
        anchors.add(m.group(1).lower())
    return anchors


def _line_of(text: str, offset: int) -> int:
    """1-indexed line number for a character offset in ``text``."""
    return text.count("\n", 0, offset) + 1


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Link:
    source: Path
    line: int
    target: str  # raw target as written


@dataclass
class Finding:
    source: Path
    line: int
    target: str
    reason: str

    def format(self, root: Path) -> str:
        try:
            rel = self.source.relative_to(root)
        except ValueError:
            rel = self.source
        return f"{rel}:{self.line}: broken link '{self.target}' — {self.reason}"


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    baselined: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    links_checked: int = 0

    @property
    def ok(self) -> bool:
        return not self.findings


def _baseline_key(f: Finding, root: Path) -> str:
    """Stable identifier for a finding used by the baseline file.

    Format: ``<relative-source-path>\t<target>``. Line numbers are
    intentionally excluded so that minor edits above a link do not
    invalidate the baseline entry.
    """
    try:
        rel = f.source.relative_to(root).as_posix()
    except ValueError:
        rel = f.source.as_posix()
    return f"{rel}\t{f.target}"


def load_baseline(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    out: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.add(line)
    return out


def write_baseline(path: Path, findings: Iterable[Finding], root: Path) -> int:
    header = (
        "# Broken-link baseline for scripts/docs/check_links.py\n"
        "# Generated; do not edit by hand except to remove entries\n"
        "# as the underlying links are fixed. Format: <source>\\t<target>\n"
    )
    keys = sorted({_baseline_key(f, root) for f in findings})
    path.write_text(header + "\n".join(keys) + ("\n" if keys else ""), encoding="utf-8")
    return len(keys)


# ---------------------------------------------------------------------------
# Link extraction and validation
# ---------------------------------------------------------------------------


def extract_links(path: Path, text: str) -> list[Link]:
    """Return all inline and reference-style relative links in ``text``."""
    cleaned = _strip_code_blocks(text)
    links: list[Link] = []

    # Collect reference definitions (label -> target). Definitions are
    # only validated via the corresponding use site so we do not double
    # count when both the definition and the use resolve to the same
    # broken target.
    ref_defs: dict[str, tuple[str, int]] = {}
    for m in _REF_DEF_RE.finditer(cleaned):
        label = m.group("label").strip().lower()
        target = m.group("target").strip()
        line = _line_of(cleaned, m.start())
        ref_defs[label] = (target, line)

    # Inline links
    for m in _INLINE_LINK_RE.finditer(cleaned):
        target = m.group("target").strip()
        if not target:
            continue
        links.append(Link(source=path, line=_line_of(cleaned, m.start()), target=target))

    # Reference uses — resolve label to definition target
    for m in _REF_USE_RE.finditer(cleaned):
        label = (m.group("label") or m.group("text")).strip().lower()
        if label in ref_defs:
            target, _ = ref_defs[label]
            links.append(
                Link(source=path, line=_line_of(cleaned, m.start()), target=target)
            )
    return links


def _is_external(target: str) -> bool:
    parsed = urlparse(target)
    if parsed.scheme in {"http", "https", "mailto", "tel", "ftp", "ftps"}:
        return True
    # MkDocs / GitHub will treat scheme-relative URLs as external
    if target.startswith("//"):
        return True
    return False


def validate_link(
    link: Link,
    *,
    root: Path,
    anchor_cache: dict[Path, set[str]],
    require_directory_index: bool = False,
) -> Finding | None:
    target = link.target
    if not target or target.startswith("#"):
        # Pure in-page anchor — validate against the source file's own anchors
        if target.startswith("#"):
            anchor = unquote(target[1:]).lower()
            if not anchor:
                return None
            anchors = _get_anchors(link.source, anchor_cache)
            if anchor not in anchors:
                return Finding(
                    link.source, link.line, target,
                    f"anchor '#{anchor}' not found in source file",
                )
        return None

    if _is_external(target):
        return None

    # Strip query string, then split anchor
    target_no_query = target.split("?", 1)[0]
    path_part, _, anchor = target_no_query.partition("#")
    path_part = unquote(path_part)
    anchor = unquote(anchor).lower()

    if not path_part:
        return None  # already handled '#anchor' above

    # Leading-slash paths in Markdown rendered on GitHub or by MkDocs
    # resolve against the repository / site root, not the OS filesystem
    # root. Treat them that way.
    if path_part.startswith("/"):
        candidate = (root / path_part.lstrip("/")).resolve()
    else:
        candidate = (link.source.parent / path_part).resolve()

    # Reject targets that escape the repository root. Without this a
    # link like ``../../../etc/hosts`` could pass CI on any runner
    # where the target file happens to exist.
    try:
        candidate.relative_to(root)
    except ValueError:
        return Finding(
            link.source, link.line, target,
            "target resolves outside the repository root",
        )

    # Directory targets: GitHub renders them as a folder view, so we
    # accept them as long as the directory exists. MkDocs-style pages
    # that require an index.md can opt in via ``require_directory_index``.
    if candidate.is_dir():
        index = candidate / "index.md"
        if index.is_file():
            candidate = index
        elif require_directory_index:
            return Finding(
                link.source, link.line, target,
                f"directory has no index.md: {_safe_rel(candidate, root)}",
            )
        else:
            return None

    if not candidate.exists():
        return Finding(
            link.source, link.line, target,
            f"file not found: {_safe_rel(candidate, root)}",
        )

    if anchor and candidate.suffix.lower() == ".md":
        anchors = _get_anchors(candidate, anchor_cache)
        if anchor not in anchors:
            return Finding(
                link.source, link.line, target,
                f"anchor '#{anchor}' not found in {_safe_rel(candidate, root)}",
            )
    return None


def _get_anchors(path: Path, cache: dict[Path, set[str]]) -> set[str]:
    if path not in cache:
        try:
            cache[path] = _extract_anchors(path.read_text(encoding="utf-8"))
        except OSError:
            cache[path] = set()
    return cache[path]


def _safe_rel(p: Path, root: Path) -> str:
    try:
        return str(p.relative_to(root))
    except ValueError:
        return str(p)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

DEFAULT_EXCLUDES = (
    ".git",
    "node_modules",
    "site",
    "target",
    "build",
    "dist",
    ".venv",
    "venv",
    "__pycache__",
)


def discover_markdown(root: Path, extra_paths: Iterable[Path] = ()) -> list[Path]:
    """Discover markdown files under ``root/docs`` plus root-level ``*.md``.

    ``extra_paths`` overrides discovery when non-empty.
    """
    extras = [p for p in extra_paths]
    if extras:
        return [p.resolve() for p in extras if p.suffix.lower() == ".md" and p.is_file()]

    found: list[Path] = []
    docs_dir = root / "docs"
    if docs_dir.is_dir():
        for p in docs_dir.rglob("*.md"):
            if any(part in DEFAULT_EXCLUDES for part in p.parts):
                continue
            found.append(p.resolve())
    for p in root.glob("*.md"):
        found.append(p.resolve())
    return sorted(set(found))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check(
    root: Path,
    paths: Iterable[Path] = (),
    *,
    require_directory_index: bool = False,
    baseline: set[str] | None = None,
) -> Report:
    files = discover_markdown(root, paths)
    report = Report()
    anchor_cache: dict[Path, set[str]] = {}
    baseline = baseline or set()
    for f in files:
        try:
            text = f.read_text(encoding="utf-8")
        except OSError as exc:
            report.findings.append(Finding(f, 0, str(f), f"unreadable: {exc}"))
            continue
        report.files_scanned += 1
        for link in extract_links(f, text):
            report.links_checked += 1
            finding = validate_link(
                link,
                root=root,
                anchor_cache=anchor_cache,
                require_directory_index=require_directory_index,
            )
            if finding is None:
                continue
            if _baseline_key(finding, root) in baseline:
                report.baselined.append(finding)
            else:
                report.findings.append(finding)
    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("paths", nargs="*", type=Path, help="Specific markdown files to check (optional).")
    p.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root (default: cwd).")
    p.add_argument("--json", action="store_true", help="Emit machine-readable JSON report.")
    p.add_argument(
        "--require-directory-index",
        action="store_true",
        help="Treat directory targets without an index.md as broken (MkDocs mode).",
    )
    p.add_argument(
        "--baseline",
        type=Path,
        default=Path("scripts/docs/.linkcheck-baseline.txt"),
        help="Allowlist file of pre-existing findings to ignore.",
    )
    p.add_argument(
        "--update-baseline",
        action="store_true",
        help="Rewrite the baseline file from the current findings and exit 0.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    root = args.root.resolve()
    baseline_path: Path = args.baseline
    if not baseline_path.is_absolute():
        baseline_path = root / baseline_path

    if args.update_baseline:
        unfiltered = check(
            root,
            args.paths,
            require_directory_index=args.require_directory_index,
        )
        count = write_baseline(baseline_path, unfiltered.findings, root)
        print(f"Wrote {count} baseline entries to {baseline_path}")
        return 0

    baseline = load_baseline(baseline_path)
    report = check(
        root,
        args.paths,
        require_directory_index=args.require_directory_index,
        baseline=baseline,
    )

    if args.json:
        payload = {
            "files_scanned": report.files_scanned,
            "links_checked": report.links_checked,
            "baselined": len(report.baselined),
            "findings": [
                {
                    "source": _safe_rel(f.source, root),
                    "line": f.line,
                    "target": f.target,
                    "reason": f.reason,
                }
                for f in report.findings
            ],
        }
        print(json.dumps(payload, indent=2))
    else:
        for finding in report.findings:
            print(finding.format(root))
        summary = (
            f"\nScanned {report.files_scanned} file(s), "
            f"{report.links_checked} link(s), "
            f"{len(report.findings)} new broken, "
            f"{len(report.baselined)} baselined."
        )
        print(summary)

    return 0 if report.ok else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
