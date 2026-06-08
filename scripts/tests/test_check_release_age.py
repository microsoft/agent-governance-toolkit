#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for check_release_age.py."""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import _supply_chain_common as common  # noqa: E402
import check_release_age as cra  # noqa: E402


# --------------------------- _resolve_pkgjson_deps ---------------------------

def test_pkgjson_resolves_exact_pins():
    tree = {
        "dependencies": {"axios": "1.14.0"},
        "devDependencies": {"jest": "29.0.0"},
    }
    out = cra._resolve_pkgjson_deps(tree)
    assert out == {"axios": "1.14.0", "jest": "29.0.0"}


def test_pkgjson_skips_ranges_and_specials():
    tree = {
        "dependencies": {
            "axios": "^1.14.0",
            "lodash": "~4.17.21",
            "local": "workspace:*",
            "git-pkg": "git+https://example.com/x.git",
            "url-pkg": "https://example.com/x.tgz",
            "any": "*",
        },
    }
    assert cra._resolve_pkgjson_deps(tree) == {}


def test_pkgjson_handles_scoped_names():
    tree = {"dependencies": {"@scope/pkg": "1.0.0"}}
    assert cra._resolve_pkgjson_deps(tree) == {"@scope/pkg": "1.0.0"}


def test_pkgjson_rejects_unsafe_name_or_version():
    tree = {
        "dependencies": {
            "../traversal": "1.0.0",
            "good": "1.0/2.0",
        },
    }
    assert cra._resolve_pkgjson_deps(tree) == {}


def test_pkgjson_handles_none():
    assert cra._resolve_pkgjson_deps(None) == {}
    assert cra._resolve_pkgjson_deps({}) == {}


# --------------------------- _resolve_cargo_deps (H2 fix) ---------------------------

def test_cargo_resolves_simple_string_form():
    tree = {"dependencies": {"serde": "1.0.228"}}
    assert cra._resolve_cargo_deps(tree) == {"serde": "1.0.228"}


def test_cargo_resolves_inline_table_form():
    tree = {"dependencies": {"tokio": {"version": "1.40.0", "features": ["full"]}}}
    assert cra._resolve_cargo_deps(tree) == {"tokio": "1.40.0"}


def test_cargo_resolves_dotted_table_form():
    """H2 regression: [dependencies.foo]\\nversion=... must parse correctly.

    The old line-regex parser only saw the bare ``version="1.40"`` line and
    associated it with the wrong dep name (or no name). With tomllib we get
    the correct {foo: {version: 1.40}} structure.
    """
    body = (
        "[dependencies]\n"
        'serde = "1.0.228"\n'
        "\n"
        "[dependencies.tokio]\n"
        'version = "1.40.0"\n'
        'features = ["full"]\n'
    )
    import tomllib
    tree = tomllib.loads(body)
    out = cra._resolve_cargo_deps(tree)
    assert out == {"serde": "1.0.228", "tokio": "1.40.0"}


def test_cargo_skips_workspace_inheritance():
    tree = {"dependencies": {"serde": {"workspace": True}}}
    assert cra._resolve_cargo_deps(tree) == {}


def test_cargo_skips_range_specifiers():
    tree = {
        "dependencies": {
            "ranged": "^1.0",
            "tilde": "~1.0",
            "ge": ">=1.0",
        },
    }
    assert cra._resolve_cargo_deps(tree) == {}


def test_cargo_includes_dev_and_build_deps():
    tree = {
        "dev-dependencies": {"pretty_assertions": "1.4.0"},
        "build-dependencies": {"cc": "1.0.83"},
    }
    out = cra._resolve_cargo_deps(tree)
    assert out == {"pretty_assertions": "1.4.0", "cc": "1.0.83"}


# --------------------------- _resolve_pyproject_deps ---------------------------

def test_pyproject_resolves_pep621_exact_pin():
    tree = {"project": {"dependencies": ["requests==2.32.0"]}}
    assert cra._resolve_pyproject_deps(tree) == {"requests": "2.32.0"}


def test_pyproject_resolves_optional_deps():
    tree = {
        "project": {
            "optional-dependencies": {
                "dev": ["pytest==8.0.0", "ruff==0.8.0"],
            },
        },
    }
    out = cra._resolve_pyproject_deps(tree)
    assert out == {"pytest": "8.0.0", "ruff": "0.8.0"}


def test_pyproject_skips_range_specifiers():
    tree = {"project": {"dependencies": ["requests>=2.0", "click~=8.0"]}}
    assert cra._resolve_pyproject_deps(tree) == {}


def test_pyproject_strips_extras():
    tree = {"project": {"dependencies": ["requests[security]==2.32.0"]}}
    assert cra._resolve_pyproject_deps(tree) == {"requests": "2.32.0"}


def test_pyproject_handles_marker():
    tree = {"project": {"dependencies": ["requests==2.32.0 ; python_version>='3.10'"]}}
    assert cra._resolve_pyproject_deps(tree) == {"requests": "2.32.0"}


def test_pyproject_resolves_poetry_dict_form():
    tree = {
        "tool": {
            "poetry": {
                "dependencies": {
                    "requests": "==2.32.0",
                    "ranged": "^1.0",
                    "dict-pin": {"version": "==3.0.0"},
                },
            },
        },
    }
    out = cra._resolve_pyproject_deps(tree)
    assert out == {"requests": "2.32.0", "dict-pin": "3.0.0"}


# --------------------------- requirements.txt line parser ---------------------------

@pytest.mark.parametrize(
    "line,expected",
    [
        ("requests==2.32.0", ("requests", "2.32.0")),
        ("requests==2.32.0  # comment", ("requests", "2.32.0")),
        ("requests==2.32.0 ; python_version>'3.10'", ("requests", "2.32.0")),
        ("requests[security]==2.32.0", ("requests", "2.32.0")),
        ("requests>=2.0", None),
        ("# comment", None),
        ("", None),
        ("-e .", None),
        ("--index-url=https://example.com", None),
        ("ranged==2.0,>=1.0", None),
    ],
)
def test_parse_requirements_added_line(line, expected):
    assert cra._parse_requirements_added_line(line) == expected


# --------------------------- collect_candidates structural diffs ---------------------------

def _mock_changed(paths):
    return patch.object(common, "changed_manifests", return_value=paths)


def _mock_loaders(json_map, toml_map=None, diff_lines=None):
    """Patch load_json_at / load_toml_at / diff_lines_added by (ref, path)."""
    toml_map = toml_map or {}
    diff_lines = diff_lines or []

    def fake_json(ref, path):
        return json_map.get((ref, path))

    def fake_toml(ref, path):
        return toml_map.get((ref, path))

    def fake_diff(_base, paths):
        return [t for t in diff_lines if t[0] in paths]

    return (
        patch.object(common, "load_json_at", side_effect=fake_json),
        patch.object(common, "load_toml_at", side_effect=fake_toml),
        patch.object(common, "diff_lines_added", side_effect=fake_diff),
    )


def test_collect_candidates_pkgjson_new_dep():
    json_map = {
        ("origin/main", "package.json"): {"dependencies": {}},
        ("HEAD", "package.json"): {"dependencies": {"axios": "1.14.0"}},
    }
    with _mock_changed(["package.json"]), \
         _mock_loaders(json_map)[0], _mock_loaders(json_map)[1], _mock_loaders(json_map)[2]:
        out = cra.collect_candidates("origin/main")
    assert out == [("npm", "axios", "1.14.0", "package.json")]


def test_collect_candidates_pkgjson_unchanged_version_skipped():
    json_map = {
        ("origin/main", "package.json"): {"dependencies": {"axios": "1.14.0"}},
        ("HEAD", "package.json"): {"dependencies": {"axios": "1.14.0", "lodash": "4.0.0"}},
    }
    with _mock_changed(["package.json"]), \
         _mock_loaders(json_map)[0], _mock_loaders(json_map)[1], _mock_loaders(json_map)[2]:
        out = cra.collect_candidates("origin/main")
    assert sorted(out) == [("npm", "lodash", "4.0.0", "package.json")]


def test_collect_candidates_pkgjson_version_bump_detected():
    json_map = {
        ("origin/main", "package.json"): {"dependencies": {"axios": "1.14.0"}},
        ("HEAD", "package.json"): {"dependencies": {"axios": "1.15.0"}},
    }
    with _mock_changed(["package.json"]), \
         _mock_loaders(json_map)[0], _mock_loaders(json_map)[1], _mock_loaders(json_map)[2]:
        out = cra.collect_candidates("origin/main")
    assert out == [("npm", "axios", "1.15.0", "package.json")]


def test_collect_candidates_cargo_dotted_table():
    """H2 end-to-end: dotted Cargo tables flow through structural diff."""
    import tomllib
    head_body = "[dependencies.tokio]\nversion = \"1.40.0\"\n"
    toml_map = {
        ("origin/main", "Cargo.toml"): {"dependencies": {}},
        ("HEAD", "Cargo.toml"): tomllib.loads(head_body),
    }
    with _mock_changed(["Cargo.toml"]), \
         _mock_loaders({}, toml_map)[0], _mock_loaders({}, toml_map)[1], _mock_loaders({}, toml_map)[2]:
        out = cra.collect_candidates("origin/main")
    assert out == [("cargo", "tokio", "1.40.0", "Cargo.toml")]


def test_collect_candidates_pyproject_pep621():
    toml_map = {
        ("origin/main", "pyproject.toml"): {"project": {"dependencies": []}},
        ("HEAD", "pyproject.toml"): {"project": {"dependencies": ["requests==2.32.0"]}},
    }
    with _mock_changed(["pyproject.toml"]), \
         _mock_loaders({}, toml_map)[0], _mock_loaders({}, toml_map)[1], _mock_loaders({}, toml_map)[2]:
        out = cra.collect_candidates("origin/main")
    assert out == [("pypi", "requests", "2.32.0", "pyproject.toml")]


def test_collect_candidates_requirements_file():
    """Requirements.txt uses the line-diff path."""
    with _mock_changed(["requirements.txt"]), \
         _mock_loaders({}, {}, [("requirements.txt", "ruff==0.8.0")])[0], \
         _mock_loaders({}, {}, [("requirements.txt", "ruff==0.8.0")])[1], \
         _mock_loaders({}, {}, [("requirements.txt", "ruff==0.8.0")])[2]:
        out = cra.collect_candidates("origin/main")
    assert out == [("pypi", "ruff", "0.8.0", "requirements.txt")]


def test_collect_candidates_dedupes_same_pkg_in_multiple_manifests():
    json_map = {
        ("origin/main", "a/package.json"): {"dependencies": {}},
        ("HEAD", "a/package.json"): {"dependencies": {"axios": "1.14.0"}},
        ("origin/main", "b/package.json"): {"dependencies": {}},
        ("HEAD", "b/package.json"): {"dependencies": {"axios": "1.14.0"}},
    }
    with _mock_changed(["a/package.json", "b/package.json"]), \
         _mock_loaders(json_map)[0], _mock_loaders(json_map)[1], _mock_loaders(json_map)[2]:
        out = cra.collect_candidates("origin/main")
    # Single (npm, axios, 1.14.0) entry; source picks first.
    assert len(out) == 1
    assert out[0][:3] == ("npm", "axios", "1.14.0")


def test_collect_candidates_root_manifest_picked_up():
    """M2 regression: a pyproject.toml at the repo root must be matched."""
    toml_map = {
        ("origin/main", "pyproject.toml"): {"project": {"dependencies": []}},
        ("HEAD", "pyproject.toml"): {"project": {"dependencies": ["click==8.0.0"]}},
    }
    with _mock_changed(["pyproject.toml"]), \
         _mock_loaders({}, toml_map)[0], _mock_loaders({}, toml_map)[1], _mock_loaders({}, toml_map)[2]:
        out = cra.collect_candidates("origin/main")
    assert out == [("pypi", "click", "8.0.0", "pyproject.toml")]


# --------------------------- fetch_release_time URL safety (M5) ---------------------------

def test_fetch_release_time_rejects_unsafe_version():
    """M5: even if some upstream is sloppy, fetch_release_time must refuse."""
    with pytest.raises(LookupError):
        cra.fetch_release_time("pypi", "requests", "1.0/../etc")


def test_fetch_release_time_rejects_unsafe_name():
    with pytest.raises(LookupError):
        cra.fetch_release_time("npm", "../evil", "1.0.0")


# --------------------------- fetch_release_time happy path / failure modes ---------------------------

def _stamp(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


def test_fetch_release_time_pypi_happy():
    body = {"urls": [{"upload_time_iso_8601": _stamp(30)}]}
    with patch.object(common, "fetch_json", return_value=body):
        out = cra.fetch_release_time("pypi", "requests", "2.32.0")
    assert out is not None and out.tzinfo is not None


def test_fetch_release_time_pypi_404_raises():
    with patch.object(common, "fetch_json", side_effect=LookupError("404")):
        with pytest.raises(LookupError):
            cra.fetch_release_time("pypi", "ghost", "0.0.1")


def test_fetch_release_time_pypi_transient_returns_none():
    with patch.object(common, "fetch_json", return_value=None):
        assert cra.fetch_release_time("pypi", "requests", "2.32.0") is None


def test_fetch_release_time_npm_per_version():
    body = {"time": _stamp(20)}
    with patch.object(common, "fetch_json", return_value=body):
        out = cra.fetch_release_time("npm", "axios", "1.14.0")
    assert out is not None


def test_fetch_release_time_cargo():
    body = {"version": {"created_at": _stamp(40)}}
    with patch.object(common, "fetch_json", return_value=body):
        out = cra.fetch_release_time("cargo", "serde", "1.0.228")
    assert out is not None


# --------------------------- main_with_args end-to-end ---------------------------

def test_main_no_candidates_returns_zero():
    with patch.object(cra, "collect_candidates", return_value=[]):
        assert cra.main_with_args(["--base", "origin/main"]) == 0


def test_main_explicit_too_fresh_fails():
    fresh = datetime.now(timezone.utc) - timedelta(days=2)
    with patch.object(cra, "fetch_release_time", return_value=fresh):
        rc = cra.main_with_args([
            "--explicit", "pypi:requests@2.32.0",
            "--min-age-days", "7",
        ])
    assert rc == 1


def test_main_explicit_old_enough_passes():
    old = datetime.now(timezone.utc) - timedelta(days=30)
    with patch.object(cra, "fetch_release_time", return_value=old):
        rc = cra.main_with_args([
            "--explicit", "pypi:requests@2.32.0",
            "--min-age-days", "7",
        ])
    assert rc == 0


def test_main_max_deps_trip_returns_two():
    """G2 + H4: max-deps refusal returns exit 2, not silently truncates."""
    fake_candidates = [("pypi", f"p{i}", "1.0.0", "x.txt") for i in range(60)]
    with patch.object(cra, "collect_candidates", return_value=fake_candidates):
        rc = cra.main_with_args(["--max-deps", "50"])
    assert rc == 2


def test_main_max_deps_zero_disables_cap():
    """``--max-deps 0`` must NOT trip the cap."""
    old = datetime.now(timezone.utc) - timedelta(days=30)
    fake_candidates = [("pypi", f"p{i}", "1.0.0", "x.txt") for i in range(60)]
    with patch.object(cra, "collect_candidates", return_value=fake_candidates), \
         patch.object(cra, "fetch_release_time", return_value=old):
        rc = cra.main_with_args(["--max-deps", "0", "--total-deadline-sec", "0"])
    assert rc == 0


def test_main_allow_list_skips():
    fresh = datetime.now(timezone.utc) - timedelta(days=1)
    with patch.object(cra, "fetch_release_time", return_value=fresh) as fr:
        rc = cra.main_with_args([
            "--explicit", "pypi:requests@2.32.0",
            "--allow", "requests==2.32.0",
        ])
    assert rc == 0
    fr.assert_not_called()


def test_main_unverifiable_changed_dep_is_fail_closed():
    """M4 regression: a transient registry failure on a *changed* dep MUST fail."""
    with patch.object(cra, "fetch_release_time", return_value=None):
        rc = cra.main_with_args([
            "--explicit", "pypi:requests@2.32.0",
        ])
    assert rc == 1


def test_main_404_is_hard_fail():
    """A 404 from the registry — version doesn't exist — is a typosquat signal."""
    with patch.object(cra, "fetch_release_time", side_effect=LookupError("404")):
        rc = cra.main_with_args([
            "--explicit", "pypi:ghost@0.0.1",
        ])
    assert rc == 1


def test_main_no_agt_internal_skip():
    """C3 regression: there is no ``is_internal()`` allow-list short-circuit.

    A freshly-published package whose name matches an AGT-published name must
    still get the cooling-off check. The previous behavior was a free SKIP on
    any name in AGT_PUBLISHED_*, which let a Birsan-style typosquat against an
    unclaimed name bypass detection.
    """
    fresh = datetime.now(timezone.utc) - timedelta(days=2)
    # Use a name that happens to match an AGT package — the old code would
    # skip this. The new code must NOT.
    with patch.object(cra, "fetch_release_time", return_value=fresh):
        rc = cra.main_with_args([
            "--explicit", "pypi:agent-os-kernel@99.99.99",
            "--min-age-days", "7",
        ])
    assert rc == 1


def test_main_bad_explicit_syntax_returns_two():
    rc = cra.main_with_args(["--explicit", "not-valid-syntax"])
    assert rc == 2


def test_main_deadline_unscanned_becomes_finding():
    """H4: when the wall-clock budget expires mid-loop, the rest are reported."""
    old = datetime.now(timezone.utc) - timedelta(days=30)
    cands = [("pypi", f"p{i}", "1.0.0", "x") for i in range(10)]

    # ``--total-deadline-sec 0`` disables the deadline → success.
    with patch.object(cra, "collect_candidates", return_value=cands), \
         patch.object(cra, "fetch_release_time", return_value=old):
        rc = cra.main_with_args(["--max-deps", "0", "--total-deadline-sec", "0"])
    assert rc == 0

    # Force an already-expired deadline by patching Deadline.expired -> True.
    # That drives every iteration through the "DEADLINE-UNSCANNED" finding
    # path which exits 1.
    with patch.object(cra, "collect_candidates", return_value=cands), \
         patch.object(cra, "fetch_release_time", return_value=old), \
         patch.object(common.Deadline, "expired", return_value=True):
        rc = cra.main_with_args(["--max-deps", "0", "--total-deadline-sec", "60"])
    assert rc == 1
