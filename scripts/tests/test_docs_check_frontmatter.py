#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for scripts/docs/check_frontmatter.py."""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from scripts.docs import check_frontmatter  # noqa: E402


def _write(p: Path, text: str) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


VALID = """\
---
title: Sample Page
last_reviewed: 2026-05-01
owner: docs-team
---

# Sample
"""


def test_valid_frontmatter_produces_no_findings(tmp_path):
    _write(tmp_path / "docs" / "a.md", VALID)
    report = check_frontmatter.check(tmp_path)
    assert report.findings == []


def test_missing_frontmatter_reports_one_finding(tmp_path):
    _write(tmp_path / "docs" / "a.md", "# No frontmatter here\n")
    report = check_frontmatter.check(tmp_path)
    assert len(report.findings) == 1
    assert "missing frontmatter" in report.findings[0].message


def test_missing_individual_keys(tmp_path):
    _write(
        tmp_path / "docs" / "a.md",
        "---\ntitle: Only Title\n---\n\n# x\n",
    )
    report = check_frontmatter.check(tmp_path)
    msgs = [f.message for f in report.findings]
    assert "missing required key: last_reviewed" in msgs
    assert "missing required key: owner" in msgs
    assert "missing required key: title" not in msgs


def test_invalid_last_reviewed_date(tmp_path):
    _write(
        tmp_path / "docs" / "a.md",
        "---\ntitle: x\nlast_reviewed: yesterday\nowner: me\n---\n",
    )
    report = check_frontmatter.check(tmp_path)
    msgs = [f.message for f in report.findings]
    assert any("YYYY-MM-DD" in m for m in msgs)


def test_warn_mode_does_not_fail(tmp_path):
    _write(tmp_path / "docs" / "a.md", "no fm")
    rc = check_frontmatter.main(["--root", str(tmp_path)])
    assert rc == 0


def test_strict_mode_fails_on_findings(tmp_path):
    _write(tmp_path / "docs" / "a.md", "no fm")
    rc = check_frontmatter.main(["--root", str(tmp_path), "--strict"])
    assert rc == 1


def test_strict_mode_passes_when_clean(tmp_path):
    _write(tmp_path / "docs" / "a.md", VALID)
    rc = check_frontmatter.main(["--root", str(tmp_path), "--strict"])
    assert rc == 0


def test_custom_required_keys(tmp_path):
    _write(
        tmp_path / "docs" / "a.md",
        "---\ntitle: x\n---\n",
    )
    report = check_frontmatter.check(tmp_path, required=["title"])
    assert report.findings == []


def test_quoted_values_are_unwrapped(tmp_path):
    _write(
        tmp_path / "docs" / "a.md",
        '---\ntitle: "Quoted"\nlast_reviewed: "2026-01-15"\nowner: \'team\'\n---\n',
    )
    report = check_frontmatter.check(tmp_path, strict=True)
    assert report.findings == []


def test_severity_reflects_strict_flag(tmp_path):
    _write(tmp_path / "docs" / "a.md", "no fm")
    warn = check_frontmatter.check(tmp_path)
    strict = check_frontmatter.check(tmp_path, strict=True)
    assert warn.findings[0].severity == "warn"
    assert strict.findings[0].severity == "error"


def test_excluded_directories_are_skipped(tmp_path):
    _write(tmp_path / "docs" / "overrides" / "skin.md", "no fm")
    _write(tmp_path / "docs" / "i18n" / "es" / "a.md", "no fm")
    _write(tmp_path / "docs" / "real.md", VALID)
    report = check_frontmatter.check(tmp_path)
    assert report.files_scanned == 1
    assert report.findings == []


def test_explicit_paths_take_priority(tmp_path):
    _write(tmp_path / "docs" / "bad.md", "no fm")
    _write(tmp_path / "docs" / "good.md", VALID)
    report = check_frontmatter.check(tmp_path, paths=[tmp_path / "docs" / "good.md"])
    assert report.files_scanned == 1
    assert report.findings == []


def test_parse_frontmatter_returns_none_when_absent():
    assert check_frontmatter.parse_frontmatter("# nothing\n") is None


def test_parse_frontmatter_ignores_comments_and_blanks():
    parsed = check_frontmatter.parse_frontmatter(
        "---\n# a comment\n\ntitle: x\n---\n"
    )
    assert parsed == {"title": "x"}


def test_parse_frontmatter_tolerates_utf8_bom():
    parsed = check_frontmatter.parse_frontmatter(
        "\ufeff---\ntitle: x\n---\n"
    )
    assert parsed == {"title": "x"}


def test_check_file_with_bom_finds_frontmatter(tmp_path):
    _write(tmp_path / "docs" / "a.md", "\ufeff" + VALID)
    report = check_frontmatter.check(tmp_path, strict=True)
    assert report.findings == []
