#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for scripts/docs/check_owasp_badge.py."""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from scripts.docs import check_owasp_badge  # noqa: E402


def _write(p: Path, text: str) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _mapping(partials: set[int], summary: str) -> str:
    rows = "\n".join(
        f"| ASI{i:02d} | Risk {i} | {'⚠️ Partial' if i in partials else '✅ Full'} | component |"
        for i in range(1, 11)
    )
    return (
        "| ASI ID | Risk Title | Coverage | Primary AGT Component |\n"
        "|--------|-----------|----------|----------------------|\n"
        f"{rows}\n"
        "| AGT extension | Agent Traceability | ✅ Full | audit log |\n\n"
        f"**{summary}**\n"
    )


def _badge(value: str) -> str:
    return f"[![OWASP Agentic Top 10](https://img.shields.io/badge/OWASP_Agentic_Top_10-{value}-blue)](x.md)\n"


def _repo(tmp_path: Path, badge: str, partials=frozenset({4, 6, 9}),
          summary="Official ASI coverage: 7/10 Full, 3/10 Partial, 0 Gaps.") -> Path:
    _write(tmp_path / "docs/compliance/owasp-agentic-top10-architecture.md", _mapping(partials, summary))
    _write(tmp_path / "README.md", _badge("7_Full,_3_Partial"))
    _write(tmp_path / "docs/i18n/README.ja.md", _badge(badge))
    return tmp_path


def test_matching_badges_pass(tmp_path):
    assert check_owasp_badge.check(_repo(tmp_path, "7_Full,_3_Partial")) == []


def test_stale_translated_badge_fails(tmp_path):
    errors = check_owasp_badge.check(_repo(tmp_path, "10%2F10_Covered"))
    assert len(errors) == 1
    assert "docs/i18n/README.ja.md" in errors[0]


def test_extension_row_is_not_counted(tmp_path):
    full, partial, gap = check_owasp_badge.coverage(_mapping({4, 6, 9}, ""))
    assert (full, partial, gap) == (7, 3, 0)


def test_summary_line_disagreeing_with_table_fails(tmp_path):
    errors = check_owasp_badge.check(
        _repo(tmp_path, "7_Full,_3_Partial", summary="Official ASI coverage: 10/10 Full, 0/10 Partial, 0 Gaps.")
    )
    assert any("summary line" in e for e in errors)


def test_badge_follows_the_table_when_a_row_changes(tmp_path):
    errors = check_owasp_badge.check(
        _repo(tmp_path, "7_Full,_3_Partial", partials={4, 9},
              summary="Official ASI coverage: 8/10 Full, 2/10 Partial, 0 Gaps.")
    )
    assert len(errors) == 2
    assert all("8_Full,_2_Partial" in e for e in errors)


def test_duplicated_row_fails_closed(tmp_path):
    text = _mapping({4, 6, 9}, "").replace(
        "| ASI10 |", "| ASI04 | Risk 4 | ✅ Full | component |\n| ASI10 |"
    )
    try:
        check_owasp_badge.coverage(text)
    except ValueError as e:
        assert "ASI04" in str(e)
    else:
        raise AssertionError("a duplicated ASI04 row was accepted")
