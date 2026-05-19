#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for scripts/docs/check_links.py."""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from scripts.docs import check_links  # noqa: E402


def _write(p: Path, text: str) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def test_inline_link_to_existing_file_passes(tmp_path):
    docs = tmp_path / "docs"
    _write(docs / "a.md", "See [b](b.md).")
    _write(docs / "b.md", "# B\n")
    report = check_links.check(tmp_path)
    assert report.ok, [f.format(tmp_path) for f in report.findings]
    assert report.links_checked == 1


def test_inline_link_to_missing_file_fails(tmp_path):
    docs = tmp_path / "docs"
    _write(docs / "a.md", "See [missing](nope.md).")
    report = check_links.check(tmp_path)
    assert not report.ok
    assert "file not found" in report.findings[0].reason


def test_external_links_are_skipped(tmp_path):
    docs = tmp_path / "docs"
    _write(
        docs / "a.md",
        "[ext](https://example.com) [mail](mailto:x@example.com) [scheme](//cdn.example.com/x)",
    )
    report = check_links.check(tmp_path)
    assert report.ok


def test_anchor_in_same_file_validates(tmp_path):
    docs = tmp_path / "docs"
    _write(docs / "a.md", "# Heading One\n\nText\n\n[here](#heading-one)\n[bad](#nope)\n")
    report = check_links.check(tmp_path)
    assert len(report.findings) == 1
    assert "#nope" in report.findings[0].reason


def test_anchor_in_other_file_validates(tmp_path):
    docs = tmp_path / "docs"
    _write(docs / "a.md", "[x](b.md#section-two)\n[y](b.md#missing)\n")
    _write(docs / "b.md", "# Section One\n\n## Section Two\n")
    report = check_links.check(tmp_path)
    assert len(report.findings) == 1
    assert "missing" in report.findings[0].reason


def test_reference_style_links(tmp_path):
    docs = tmp_path / "docs"
    _write(
        docs / "a.md",
        "See [the doc][doc] and [shortcut][].\n\n[doc]: b.md\n[shortcut]: c.md\n",
    )
    _write(docs / "b.md", "ok")
    # c.md missing -> one finding
    report = check_links.check(tmp_path)
    assert len(report.findings) == 1
    assert report.findings[0].target == "c.md"


def test_code_fences_are_ignored(tmp_path):
    docs = tmp_path / "docs"
    _write(
        docs / "a.md",
        "```\n[fake](does-not-exist.md)\n```\n\n[real](b.md)\n",
    )
    _write(docs / "b.md", "ok")
    report = check_links.check(tmp_path)
    assert report.ok, [f.format(tmp_path) for f in report.findings]


def test_images_are_not_treated_as_links(tmp_path):
    docs = tmp_path / "docs"
    _write(docs / "a.md", "![alt](img.png)")
    report = check_links.check(tmp_path)
    assert report.links_checked == 0
    assert report.ok


def test_directory_link_resolves_to_index_md(tmp_path):
    docs = tmp_path / "docs"
    _write(docs / "a.md", "[sec](section/)")
    _write(docs / "section" / "index.md", "# Section")
    report = check_links.check(tmp_path)
    assert report.ok


def test_directory_link_without_index_passes_by_default(tmp_path):
    docs = tmp_path / "docs"
    _write(docs / "a.md", "[sec](section/)")
    (docs / "section").mkdir(parents=True)
    report = check_links.check(tmp_path)
    assert report.ok


def test_directory_link_without_index_fails_in_strict_mode(tmp_path):
    docs = tmp_path / "docs"
    _write(docs / "a.md", "[sec](section/)")
    (docs / "section").mkdir(parents=True)
    report = check_links.check(tmp_path, require_directory_index=True)
    assert not report.ok
    assert "no index.md" in report.findings[0].reason


def test_directory_link_to_nonexistent_directory_fails(tmp_path):
    docs = tmp_path / "docs"
    _write(docs / "a.md", "[sec](missing-dir/)")
    report = check_links.check(tmp_path)
    assert not report.ok
    assert "file not found" in report.findings[0].reason


def test_url_encoded_target(tmp_path):
    docs = tmp_path / "docs"
    _write(docs / "a.md", "[x](My%20Page.md)")
    _write(docs / "My Page.md", "# My Page")
    report = check_links.check(tmp_path)
    assert report.ok


def test_query_string_stripped(tmp_path):
    docs = tmp_path / "docs"
    _write(docs / "a.md", "[x](b.md?v=2#top)")
    _write(docs / "b.md", "# Top")
    report = check_links.check(tmp_path)
    assert report.ok


def test_root_markdown_files_included(tmp_path):
    _write(tmp_path / "README.md", "[x](docs/a.md)")
    _write(tmp_path / "docs" / "a.md", "# A")
    report = check_links.check(tmp_path)
    assert report.ok
    assert report.files_scanned == 2


def test_explicit_paths_override_discovery(tmp_path):
    docs = tmp_path / "docs"
    _write(docs / "a.md", "[missing](nope.md)")
    _write(docs / "b.md", "[ok](a.md)")
    report = check_links.check(tmp_path, [docs / "b.md"])
    assert report.ok
    assert report.files_scanned == 1


def test_root_relative_leading_slash(tmp_path):
    _write(tmp_path / "README.md", "[home](/README.md) [bad](/missing.md)")
    report = check_links.check(tmp_path)
    assert len(report.findings) == 1
    assert report.findings[0].target == "/missing.md"


def test_html_anchor_id_recognised(tmp_path):
    docs = tmp_path / "docs"
    _write(docs / "a.md", "<a id=\"target\"></a>\n\n[x](#target)")
    report = check_links.check(tmp_path)
    assert report.ok


def test_main_exits_nonzero_on_findings(tmp_path, capsys):
    docs = tmp_path / "docs"
    _write(docs / "a.md", "[x](missing.md)")
    rc = check_links.main(["--root", str(tmp_path)])
    captured = capsys.readouterr()
    assert rc == 1
    assert "broken link" in captured.out


def test_main_json_output(tmp_path, capsys):
    import json
    docs = tmp_path / "docs"
    _write(docs / "a.md", "[x](missing.md)")
    rc = check_links.main(["--root", str(tmp_path), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["files_scanned"] == 1
    assert len(payload["findings"]) == 1


def test_baseline_suppresses_existing_findings(tmp_path):
    docs = tmp_path / "docs"
    _write(docs / "a.md", "[x](missing.md) [y](also-missing.md)")
    baseline = {"docs/a.md\tmissing.md"}
    report = check_links.check(tmp_path, baseline=baseline)
    assert len(report.findings) == 1
    assert report.findings[0].target == "also-missing.md"
    assert len(report.baselined) == 1


def test_update_baseline_writes_file_and_exits_zero(tmp_path, capsys):
    docs = tmp_path / "docs"
    _write(docs / "a.md", "[x](missing.md)")
    baseline_path = tmp_path / "baseline.txt"
    rc = check_links.main([
        "--root", str(tmp_path),
        "--baseline", str(baseline_path),
        "--update-baseline",
    ])
    assert rc == 0
    contents = baseline_path.read_text(encoding="utf-8")
    assert "docs/a.md\tmissing.md" in contents


def test_baseline_loaded_from_file(tmp_path):
    docs = tmp_path / "docs"
    _write(docs / "a.md", "[x](missing.md)")
    baseline_path = tmp_path / "b.txt"
    baseline_path.write_text("# header\ndocs/a.md\tmissing.md\n", encoding="utf-8")
    rc = check_links.main([
        "--root", str(tmp_path),
        "--baseline", str(baseline_path),
    ])
    assert rc == 0


def test_baseline_key_uses_posix_separator(tmp_path):
    # Ensure baseline keys are stable across Windows/Linux by using
    # POSIX separators in the source-path portion.
    docs = tmp_path / "docs" / "nested"
    _write(docs / "a.md", "[x](missing.md)")
    report = check_links.check(tmp_path)
    key = check_links._baseline_key(report.findings[0], tmp_path.resolve())
    assert key.split("\t")[0] == "docs/nested/a.md"


def test_inline_link_regex_no_catastrophic_backtracking():
    # Regression for CodeQL py/redos finding. A pathological string of
    # '[' followed by many backslashes used to cause exponential
    # backtracking because both '[^\\[\\]]' and '\\.' could consume a
    # backslash. With the disambiguated class the scan completes in
    # linear time.
    import time
    pathological = "[" + "\\" * 2000
    start = time.perf_counter()
    list(check_links._INLINE_LINK_RE.finditer(pathological))
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, f"regex took {elapsed:.2f}s on pathological input"


def test_target_escaping_repo_root_is_rejected(tmp_path):
    # A link that resolves outside the repo root must always fail,
    # even if the target file happens to exist on the host.
    outside = tmp_path.parent / "outside.md"
    outside.write_text("# outside", encoding="utf-8")
    try:
        docs = tmp_path / "docs"
        _write(docs / "a.md", "[escape](../../outside.md)")
        report = check_links.check(tmp_path)
        assert not report.ok
        assert "outside the repository root" in report.findings[0].reason
    finally:
        outside.unlink(missing_ok=True)
