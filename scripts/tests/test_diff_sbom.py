#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for diff_sbom.py."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from diff_sbom import (  # noqa: E402
    COMMENT_MARKER,
    DEFAULT_MAX_ADDED,
    DEFAULT_MAX_BUMPED,
    DEFAULT_MAX_REMOVED,
    DEFAULT_MAX_SBOM_BYTES,
    Package,
    _extract_packages,
    _parse_purl,
    _sanitize_cell,
    diff_sboms,
    render_markdown,
    run,
)


def _pkg(name: str, version: str, purl_type: str = "npm") -> dict:
    """Helper to build an SPDX-JSON package entry."""
    return {
        "name": name,
        "versionInfo": version,
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:{purl_type}/{name}@{version}",
            }
        ],
    }


def _sbom(packages: list[dict], doc_name: str = "test-sbom") -> dict:
    return {
        "spdxVersion": "SPDX-2.3",
        "name": doc_name,
        "packages": packages,
    }


# ----- _parse_purl ------------------------------------------------------------


def test_parse_purl_npm_simple():
    assert _parse_purl("pkg:npm/left-pad@1.3.0") == ("npm", "left-pad", "1.3.0")


def test_parse_purl_npm_scoped():
    assert _parse_purl("pkg:npm/%40scope/pkg@2.0.0") == ("npm", "%40scope/pkg", "2.0.0")


def test_parse_purl_no_version():
    assert _parse_purl("pkg:pypi/requests") == ("pypi", "requests", "")


def test_parse_purl_unknown_ecosystem_falls_back_to_other():
    eco, name, version = _parse_purl("pkg:weird-thing/foo@1.0")
    assert eco == "other"
    assert name == "foo"
    assert version == "1.0"


def test_parse_purl_rejects_non_string():
    assert _parse_purl(None) is None  # type: ignore[arg-type]
    assert _parse_purl(123) is None  # type: ignore[arg-type]


def test_parse_purl_rejects_garbage():
    assert _parse_purl("not-a-purl") is None
    assert _parse_purl("") is None


# ----- _sanitize_cell ---------------------------------------------------------


def test_sanitize_escapes_pipes_and_backticks():
    out = _sanitize_cell("evil|name`with`pipes")
    assert "|" not in out.replace("\\|", "")
    assert "`" not in out.replace("\\`", "")


def test_sanitize_strips_newlines_and_control_chars():
    out = _sanitize_cell("foo\nbar\r\x00baz")
    assert "\n" not in out
    assert "\r" not in out
    assert "\x00" not in out


def test_sanitize_escapes_html_brackets():
    out = _sanitize_cell("<script>alert(1)</script>")
    assert "<" not in out
    assert ">" not in out
    assert "&lt;" in out
    assert "&gt;" in out


def test_sanitize_caps_length():
    long = "x" * 500
    out = _sanitize_cell(long)
    assert len(out) <= 200
    assert out.endswith("...")


def test_sanitize_handles_empty():
    assert _sanitize_cell("") == "(empty)"
    assert _sanitize_cell(None) == "(empty)"  # type: ignore[arg-type]


def test_sanitize_neutralizes_github_mentions():
    # Hostile package name embedding @user / @org/team / #1234 must NOT survive
    # as something that GitHub will render as a notification-spam link in the
    # bot comment.
    out = _sanitize_cell("@octocat please review #1 cc @org/team")
    assert "@octocat" not in out
    assert "@org/team" not in out
    assert "#1" not in out
    assert "&#64;" in out  # encoded @
    assert "&#35;" in out  # encoded #


# ----- _extract_packages ------------------------------------------------------


def test_extract_packages_simple():
    sbom = _sbom([_pkg("foo", "1.0.0"), _pkg("bar", "2.0.0", "pypi")])
    pkgs = _extract_packages(sbom)
    assert Package("npm", "foo", "1.0.0") in pkgs
    assert Package("pypi", "bar", "2.0.0") in pkgs


def test_extract_packages_skips_document_self_reference():
    sbom = {
        "name": "my-repo",
        "packages": [
            {"name": "my-repo", "versionInfo": ""},  # no purl, matches doc name
            _pkg("real-dep", "1.0.0"),
        ],
    }
    pkgs = _extract_packages(sbom)
    assert Package("npm", "real-dep", "1.0.0") in pkgs
    assert not any(p.name == "my-repo" for p in pkgs)


def test_extract_packages_falls_back_to_versionInfo_without_purl():
    sbom = _sbom([{"name": "no-purl-pkg", "versionInfo": "9.9.9"}])
    pkgs = _extract_packages(sbom)
    # No purl -> ecosystem "other"
    assert Package("other", "no-purl-pkg", "9.9.9") in pkgs


def test_extract_packages_empty():
    assert _extract_packages({"packages": []}) == set()
    assert _extract_packages({}) == set()


def test_extract_packages_rejects_non_dict():
    with pytest.raises(ValueError):
        _extract_packages([])  # type: ignore[arg-type]


def test_extract_packages_rejects_non_list_packages():
    with pytest.raises(ValueError):
        _extract_packages({"packages": "not-a-list"})


def test_extract_packages_ignores_malformed_entries():
    sbom = {
        "packages": [
            "not-a-dict",
            {"versionInfo": "1.0"},  # no name
            {"name": ""},  # empty name
            _pkg("good", "1.0.0"),
        ]
    }
    pkgs = _extract_packages(sbom)
    assert pkgs == {Package("npm", "good", "1.0.0")}


# ----- diff_sboms -------------------------------------------------------------


def test_diff_added_only():
    base: set[Package] = set()
    head = {Package("npm", "foo", "1.0.0")}
    diff = diff_sboms(base, head)
    assert diff.added == [Package("npm", "foo", "1.0.0")]
    assert diff.removed == []
    assert diff.bumped == []
    assert not diff.is_empty


def test_diff_removed_only():
    base = {Package("pypi", "old", "1.0")}
    head: set[Package] = set()
    diff = diff_sboms(base, head)
    assert diff.removed == [Package("pypi", "old", "1.0")]
    assert diff.added == []


def test_diff_bumped_detected():
    base = {Package("npm", "foo", "1.0.0")}
    head = {Package("npm", "foo", "2.0.0")}
    diff = diff_sboms(base, head)
    assert diff.added == []
    assert diff.removed == []
    assert len(diff.bumped) == 1
    old, new = diff.bumped[0]
    assert old.version == "1.0.0"
    assert new.version == "2.0.0"


def test_diff_empty_when_identical():
    pkgs = {Package("npm", "foo", "1.0.0"), Package("pypi", "bar", "2.0.0")}
    diff = diff_sboms(pkgs, pkgs)
    assert diff.is_empty
    assert diff.added == [] and diff.removed == [] and diff.bumped == []


def test_diff_truncation_cap():
    head = {Package("npm", f"dep-{i:04d}", "1.0.0") for i in range(600)}
    diff = diff_sboms(set(), head, max_added=500)
    assert len(diff.added) == 500
    assert diff.truncated_added == 100


def test_diff_truncation_cap_zero():
    head = {Package("npm", "foo", "1.0.0")}
    diff = diff_sboms(set(), head, max_added=0)
    assert diff.added == []
    assert diff.truncated_added == 1


def test_diff_rejects_negative_cap():
    with pytest.raises(ValueError):
        diff_sboms(set(), set(), max_added=-1)
    with pytest.raises(ValueError):
        diff_sboms(set(), set(), max_removed=-1)
    with pytest.raises(ValueError):
        diff_sboms(set(), set(), max_bumped=-1)


def test_diff_truncation_cap_removed():
    base = {Package("npm", f"dep-{i:04d}", "1.0.0") for i in range(600)}
    diff = diff_sboms(base, set(), max_removed=500)
    assert len(diff.removed) == 500
    assert diff.truncated_removed == 100


def test_diff_truncation_cap_bumped():
    base = {Package("npm", f"dep-{i:04d}", "1.0.0") for i in range(600)}
    head = {Package("npm", f"dep-{i:04d}", "2.0.0") for i in range(600)}
    diff = diff_sboms(base, head, max_bumped=500)
    assert len(diff.bumped) == 500
    assert diff.truncated_bumped == 100


def test_diff_distinct_ecosystems_are_separate():
    # Same name in two ecosystems is two distinct packages.
    base = {Package("npm", "foo", "1.0.0")}
    head = {Package("npm", "foo", "1.0.0"), Package("pypi", "foo", "1.0.0")}
    diff = diff_sboms(base, head)
    assert diff.added == [Package("pypi", "foo", "1.0.0")]
    assert diff.removed == []
    assert diff.bumped == []


# ----- render_markdown --------------------------------------------------------


def test_render_includes_marker():
    out = render_markdown(diff_sboms(set(), set()), base_ref="main", head_ref="pr")
    assert COMMENT_MARKER in out
    assert out.splitlines()[0] == COMMENT_MARKER  # must be first line


def test_render_empty_diff_says_no_changes():
    out = render_markdown(diff_sboms(set(), set()), base_ref="main", head_ref="pr")
    assert "No dependency changes" in out


def test_render_groups_by_ecosystem():
    head = {
        Package("npm", "a", "1.0.0"),
        Package("pypi", "b", "2.0.0"),
    }
    out = render_markdown(diff_sboms(set(), head), base_ref="main", head_ref="pr")
    assert "`npm`" in out
    assert "`pypi`" in out
    assert "### ➕ Added" in out


def test_render_sanitizes_hostile_package_name():
    head = {Package("npm", "evil`|<script>", "1.0.0\npwn")}
    out = render_markdown(diff_sboms(set(), head), base_ref="main", head_ref="pr")
    # The raw hostile substrings must not appear unescaped in the output body.
    body_after_header = "\n".join(out.splitlines()[1:])
    assert "<script>" not in body_after_header
    assert "1.0.0\npwn" not in body_after_header


def test_render_sanitizes_hostile_ref_label():
    out = render_markdown(
        diff_sboms(set(), set()),
        base_ref="main\n## fake header",
        head_ref="pr`evil`",
    )
    # Header injection requires `#` at line-start; sanitization strips newlines
    # so the hostile string cannot start a new line.
    for line in out.splitlines():
        assert not line.startswith("## fake header")
    # Backticks in ref label must be escaped so they don't open a code span.
    assert "`evil`" not in out


def test_render_shows_truncation_notice():
    head = {Package("npm", f"dep-{i:04d}", "1.0.0") for i in range(50)}
    diff = diff_sboms(set(), head, max_added=10)
    out = render_markdown(diff, base_ref="main", head_ref="pr")
    assert "Truncated 40" in out


def test_render_shows_truncation_notice_for_removed_and_bumped():
    base = {Package("npm", f"old-{i:04d}", "1.0.0") for i in range(50)}
    head = {Package("npm", f"new-{i:04d}", "1.0.0") for i in range(0)}
    # 50 removed, cap to 10
    diff = diff_sboms(base, head, max_removed=10)
    out = render_markdown(diff, base_ref="main", head_ref="pr")
    assert "Truncated 40 additional 'removed' entries" in out

    base2 = {Package("npm", f"dep-{i:04d}", "1.0.0") for i in range(50)}
    head2 = {Package("npm", f"dep-{i:04d}", "2.0.0") for i in range(50)}
    diff2 = diff_sboms(base2, head2, max_bumped=10)
    out2 = render_markdown(diff2, base_ref="main", head_ref="pr")
    assert "Truncated 40 additional 'bumped' entries" in out2


def test_render_bumped_section_has_from_to():
    base = {Package("npm", "foo", "1.0.0")}
    head = {Package("npm", "foo", "2.0.0")}
    out = render_markdown(diff_sboms(base, head), base_ref="main", head_ref="pr")
    assert "🔄 Bumped" in out
    assert "1.0.0" in out and "2.0.0" in out


# ----- run / end-to-end -------------------------------------------------------


def test_run_writes_output_file(tmp_path: Path):
    base_file = tmp_path / "base.json"
    head_file = tmp_path / "head.json"
    out_file = tmp_path / "out.md"
    base_file.write_text(json.dumps(_sbom([_pkg("foo", "1.0.0")])), encoding="utf-8")
    head_file.write_text(
        json.dumps(_sbom([_pkg("foo", "1.0.0"), _pkg("bar", "2.0.0", "pypi")])),
        encoding="utf-8",
    )
    diff = run(base_file, head_file, out_file, base_ref="main", head_ref="pr")
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert COMMENT_MARKER in content
    assert "bar" in content
    assert len(diff.added) == 1


def test_run_rejects_malformed_json(tmp_path: Path):
    base_file = tmp_path / "base.json"
    head_file = tmp_path / "head.json"
    base_file.write_text("{not json", encoding="utf-8")
    head_file.write_text(json.dumps(_sbom([])), encoding="utf-8")
    with pytest.raises(ValueError, match="Failed to read SBOM"):
        run(base_file, head_file, tmp_path / "out.md", base_ref="m", head_ref="p")


def test_run_rejects_non_object_root(tmp_path: Path):
    base_file = tmp_path / "base.json"
    head_file = tmp_path / "head.json"
    base_file.write_text("[]", encoding="utf-8")
    head_file.write_text(json.dumps(_sbom([])), encoding="utf-8")
    with pytest.raises(ValueError, match="must be a JSON object"):
        run(base_file, head_file, tmp_path / "out.md", base_ref="m", head_ref="p")


def test_run_rejects_oversized_sbom(tmp_path: Path):
    base_file = tmp_path / "base.json"
    head_file = tmp_path / "head.json"
    # Both files valid JSON; base is large enough to exceed a 1 KiB cap.
    base_file.write_text(
        json.dumps({"name": "x", "packages": [], "padding": "P" * 2048}),
        encoding="utf-8",
    )
    head_file.write_text(json.dumps(_sbom([])), encoding="utf-8")
    with pytest.raises(ValueError, match="exceeds cap"):
        run(
            base_file,
            head_file,
            tmp_path / "out.md",
            base_ref="m",
            head_ref="p",
            max_sbom_bytes=1024,
        )


def test_default_cap_value():
    # Sanity check the documented default doesn't drift.
    assert DEFAULT_MAX_ADDED == 500
    assert DEFAULT_MAX_REMOVED == 500
    assert DEFAULT_MAX_BUMPED == 500
    assert DEFAULT_MAX_SBOM_BYTES == 64 * 1024 * 1024
