#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for check_install_scripts.py."""

from __future__ import annotations

import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import _supply_chain_common as common  # noqa: E402
import check_install_scripts as cis  # noqa: E402


# --------------------------- _extract_pkgjson_pairs ---------------------------

def test_pkgjson_pairs_exact_pin():
    tree = {
        "dependencies": {"axios": "1.14.0"},
        "devDependencies": {"jest": "29.0.0"},
    }
    assert cis._extract_pkgjson_pairs(tree) == {"axios": "1.14.0", "jest": "29.0.0"}


def test_pkgjson_pairs_skips_ranges_and_specials():
    tree = {
        "dependencies": {
            "axios": "^1.14.0",
            "local": "workspace:*",
            "filepkg": "file:./local",
            "linkpkg": "link:../sib",
            "url": "https://example.com/x.tgz",
            "git": "git+https://example.com/x.git",
            "any": "*",
        },
    }
    assert cis._extract_pkgjson_pairs(tree) == {}


def test_pkgjson_pairs_scoped_names():
    tree = {"dependencies": {"@scope/pkg": "1.0.0"}}
    assert cis._extract_pkgjson_pairs(tree) == {"@scope/pkg": "1.0.0"}


def test_pkgjson_pairs_rejects_unsafe():
    tree = {"dependencies": {"../traversal": "1.0.0", "good": "1.0/2.0"}}
    assert cis._extract_pkgjson_pairs(tree) == {}


def test_pkgjson_pairs_empty():
    assert cis._extract_pkgjson_pairs(None) == {}
    assert cis._extract_pkgjson_pairs({}) == {}


# --------------------------- _unwrap_lockfile_path (C5 fix) ---------------------------

@pytest.mark.parametrize(
    "key,expected",
    [
        ("", None),
        ("node_modules/foo", "foo"),
        ("node_modules/@scope/foo", "@scope/foo"),
        # C5: deeply nested deps must extract the innermost package name.
        ("node_modules/a/node_modules/b", "b"),
        ("node_modules/a/node_modules/@scope/b", "@scope/b"),
        ("node_modules/a/node_modules/b/node_modules/c", "c"),
        # No node_modules prefix → unrecognized.
        ("packages/local", None),
    ],
)
def test_unwrap_lockfile_path(key, expected):
    assert cis._unwrap_lockfile_path(key) == expected


# --------------------------- _extract_lockfile_pairs ---------------------------

def test_lockfile_v3_packages_form():
    tree = {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "root"},
            "node_modules/axios": {"version": "1.14.0", "hasInstallScript": False},
            "node_modules/sus": {"version": "0.1.0", "hasInstallScript": True},
        },
    }
    out = cis._extract_lockfile_pairs(tree)
    assert ("axios", "1.14.0") in out
    assert ("sus", "0.1.0") in out
    assert out[("axios", "1.14.0")] is False
    assert out[("sus", "0.1.0")] is True


def test_lockfile_v3_nested_node_modules_extracted():
    """C5 end-to-end: nested deps must be captured by the lockfile parser."""
    tree = {
        "lockfileVersion": 3,
        "packages": {
            "node_modules/outer": {"version": "1.0.0"},
            "node_modules/outer/node_modules/sus": {
                "version": "0.0.1",
                "hasInstallScript": True,
            },
        },
    }
    out = cis._extract_lockfile_pairs(tree)
    assert ("sus", "0.0.1") in out
    assert out[("sus", "0.0.1")] is True


def test_lockfile_v1_legacy_dependencies_recursive():
    tree = {
        "lockfileVersion": 1,
        "dependencies": {
            "outer": {
                "version": "1.0.0",
                "dependencies": {
                    "inner": {
                        "version": "2.0.0",
                        "dependencies": {
                            "deep": {"version": "3.0.0"},
                        },
                    },
                },
            },
        },
    }
    out = cis._extract_lockfile_pairs(tree)
    assert ("outer", "1.0.0") in out
    assert ("inner", "2.0.0") in out
    assert ("deep", "3.0.0") in out


def test_lockfile_hint_true_not_overwritten_by_false():
    """If the same (name, ver) appears with hint=True somewhere, keep True.

    Defence against a lockfile that lists a package once with hint=False to
    bypass and again with the real hint=True somewhere deeper.
    """
    tree = {
        "lockfileVersion": 3,
        "packages": {
            "node_modules/a/node_modules/sus": {
                "version": "1.0.0",
                "hasInstallScript": True,
            },
            "node_modules/sus": {"version": "1.0.0", "hasInstallScript": False},
        },
    }
    out = cis._extract_lockfile_pairs(tree)
    assert out[("sus", "1.0.0")] is True


def test_lockfile_rejects_unsafe_names():
    tree = {
        "lockfileVersion": 3,
        "packages": {"node_modules/../evil": {"version": "1.0.0"}},
    }
    out = cis._extract_lockfile_pairs(tree)
    assert out == {}


def test_lockfile_none_or_empty():
    assert cis._extract_lockfile_pairs(None) == {}
    assert cis._extract_lockfile_pairs({}) == {}


# --------------------------- collect_candidates ---------------------------

def _mock_changed(paths):
    return patch.object(common, "changed_manifests", return_value=paths)


def _mock_json(json_map):
    def fake_json(ref, path):
        return json_map.get((ref, path))
    return patch.object(common, "load_json_at", side_effect=fake_json)


def test_collect_candidates_new_pkgjson_dep():
    json_map = {
        ("origin/main", "package.json"): {"dependencies": {}},
        ("HEAD", "package.json"): {"dependencies": {"axios": "1.14.0"}},
    }
    with _mock_changed(["package.json"]), _mock_json(json_map):
        out = cis.collect_candidates("origin/main")
    # Hint is None (no lockfile context for package.json adds).
    assert out == [("axios", "1.14.0", None, "package.json")]


def test_collect_candidates_unchanged_dep_skipped():
    json_map = {
        ("origin/main", "package.json"): {"dependencies": {"axios": "1.14.0"}},
        ("HEAD", "package.json"): {"dependencies": {"axios": "1.14.0"}},
    }
    with _mock_changed(["package.json"]), _mock_json(json_map):
        out = cis.collect_candidates("origin/main")
    assert out == []


def test_collect_candidates_combines_pkgjson_and_lockfile():
    json_map = {
        ("origin/main", "package.json"): {"dependencies": {}},
        ("HEAD", "package.json"): {"dependencies": {"axios": "1.14.0"}},
        ("origin/main", "package-lock.json"): {"lockfileVersion": 3, "packages": {}},
        ("HEAD", "package-lock.json"): {
            "lockfileVersion": 3,
            "packages": {
                "node_modules/axios": {"version": "1.14.0", "hasInstallScript": False},
                "node_modules/sus": {"version": "0.1.0", "hasInstallScript": True},
            },
        },
    }
    with _mock_changed(["package.json", "package-lock.json"]), _mock_json(json_map):
        out = cis.collect_candidates("origin/main")
    triples = {(n, v, h) for n, v, h, _ in out}
    # G1: the new lockfile-only dep ``sus`` is now picked up.
    assert ("sus", "0.1.0", True) in triples
    # axios hint comes from lockfile (False).
    assert ("axios", "1.14.0", False) in triples


def test_collect_candidates_dedupes_across_lockfiles():
    json_map = {
        ("origin/main", "a/package-lock.json"): {"lockfileVersion": 3, "packages": {}},
        ("HEAD", "a/package-lock.json"): {
            "lockfileVersion": 3,
            "packages": {"node_modules/x": {"version": "1.0.0"}},
        },
        ("origin/main", "b/package-lock.json"): {"lockfileVersion": 3, "packages": {}},
        ("HEAD", "b/package-lock.json"): {
            "lockfileVersion": 3,
            "packages": {"node_modules/x": {"version": "1.0.0"}},
        },
    }
    with _mock_changed(["a/package-lock.json", "b/package-lock.json"]), _mock_json(json_map):
        out = cis.collect_candidates("origin/main")
    keys = [(n, v) for n, v, _, _ in out]
    # One entry per (name, version) — first source wins.
    assert keys.count(("x", "1.0.0")) == 1


# --------------------------- fetch_install_scripts URL safety (M5) ---------------------------

def test_fetch_install_scripts_rejects_unsafe_name():
    with pytest.raises(LookupError):
        cis.fetch_install_scripts("../evil", "1.0.0")


def test_fetch_install_scripts_rejects_unsafe_version():
    with pytest.raises(LookupError):
        cis.fetch_install_scripts("axios", "1.0/../etc")


# --------------------------- fetch_install_scripts behavior ---------------------------

def test_fetch_install_scripts_returns_dict_when_scripts_present():
    body = {"scripts": {"postinstall": "node setup.js"}}
    with patch.object(common, "fetch_json", return_value=body):
        out = cis.fetch_install_scripts("axios", "1.14.0")
    assert out == {"postinstall": "node setup.js"}


def test_fetch_install_scripts_returns_empty_dict_when_no_scripts():
    with patch.object(common, "fetch_json", return_value={"scripts": {}}):
        assert cis.fetch_install_scripts("axios", "1.14.0") == {}


def test_fetch_install_scripts_returns_empty_dict_when_no_scripts_key():
    """A version with no ``scripts`` key at all has no install scripts."""
    with patch.object(common, "fetch_json", return_value={"name": "axios"}):
        assert cis.fetch_install_scripts("axios", "1.14.0") == {}


def test_fetch_install_scripts_filters_to_install_lifecycle_only():
    body = {
        "scripts": {
            "test": "jest",         # not an install script
            "build": "tsc",         # not an install script
            "postinstall": "node setup.js",
        },
    }
    with patch.object(common, "fetch_json", return_value=body):
        out = cis.fetch_install_scripts("axios", "1.14.0")
    assert "postinstall" in out
    assert "test" not in out
    assert "build" not in out


def test_fetch_install_scripts_404_raises():
    with patch.object(common, "fetch_json", side_effect=LookupError("404")):
        with pytest.raises(LookupError):
            cis.fetch_install_scripts("ghost", "0.0.1")


def test_fetch_install_scripts_transient_returns_none():
    with patch.object(common, "fetch_json", return_value=None):
        assert cis.fetch_install_scripts("axios", "1.14.0") is None


# --------------------------- main_with_args ---------------------------

def test_main_no_candidates_returns_zero():
    with patch.object(cis, "collect_candidates", return_value=[]):
        assert cis.main_with_args(["--base", "origin/main"]) == 0


def test_main_explicit_with_scripts_warns_but_passes():
    """Default behavior: install scripts are warnings, not blockers."""
    with patch.object(cis, "fetch_install_scripts",
                       return_value={"postinstall": "x"}):
        rc = cis.main_with_args(["--explicit", "axios@1.14.0"])
    assert rc == 0


def test_main_explicit_with_scripts_strict_fails():
    """H3: ``--strict`` upgrades the warning to a hard fail."""
    with patch.object(cis, "fetch_install_scripts",
                       return_value={"postinstall": "x"}):
        rc = cis.main_with_args(["--explicit", "axios@1.14.0", "--strict"])
    assert rc == 1


def test_main_explicit_clean_passes():
    with patch.object(cis, "fetch_install_scripts", return_value={}):
        rc = cis.main_with_args(["--explicit", "axios@1.14.0", "--strict"])
    assert rc == 0


def test_main_allowlist_skips_query():
    """A package on the built-in or --allow list is skipped without a fetch."""
    with patch.object(cis, "fetch_install_scripts") as f:
        rc = cis.main_with_args(["--explicit", "axios@1.14.0", "--allow", "axios"])
    assert rc == 0
    f.assert_not_called()


def test_main_lockfile_hint_false_still_queried():
    """C4 regression: hint=False MUST NOT short-circuit the registry call.

    The previous behavior was an outright skip when the lockfile claimed
    ``hasInstallScript: false`` — that lets a tampered lockfile hide a real
    install script. We now always query.
    """
    queried = {"n": 0}

    def fake_fetch(name, version):
        queried["n"] += 1
        return {"postinstall": "x"}  # registry says scripts EXIST

    fake_cands = [("axios", "1.14.0", False, "package-lock.json")]
    with patch.object(cis, "collect_candidates", return_value=fake_cands), \
         patch.object(cis, "fetch_install_scripts", side_effect=fake_fetch):
        rc = cis.main_with_args(["--strict"])
    # Registry WAS queried despite hint=False.
    assert queried["n"] == 1
    # And the lockfile-lied finding produced a hard fail.
    assert rc == 1


def test_main_max_deps_trip():
    fake_cands = [(f"p{i}", "1.0.0", None, "x") for i in range(150)]
    with patch.object(cis, "collect_candidates", return_value=fake_cands):
        rc = cis.main_with_args(["--max-deps", "100"])
    assert rc == 2


def test_main_max_deps_zero_disables():
    fake_cands = [(f"p{i}", "1.0.0", None, "x") for i in range(150)]
    with patch.object(cis, "collect_candidates", return_value=fake_cands), \
         patch.object(cis, "fetch_install_scripts", return_value={}):
        rc = cis.main_with_args(["--max-deps", "0", "--total-deadline-sec", "0"])
    assert rc == 0


def test_main_unverifiable_changed_dep_fail_closed_strict():
    """M4: in --strict mode, a transient registry failure fails the check."""
    with patch.object(cis, "fetch_install_scripts", return_value=None):
        rc = cis.main_with_args(["--explicit", "axios@1.14.0", "--strict"])
    assert rc == 1


def test_main_404_is_hard_fail_strict():
    """In --strict mode (the workflow's mode) a 404 is a hard fail."""
    with patch.object(cis, "fetch_install_scripts", side_effect=LookupError("404")):
        rc = cis.main_with_args(["--explicit", "ghost@0.0.1", "--strict"])
    assert rc == 1


def test_main_404_warns_only_without_strict():
    """Default mode is warn-only — 404 reported but exit 0."""
    with patch.object(cis, "fetch_install_scripts", side_effect=LookupError("404")):
        rc = cis.main_with_args(["--explicit", "ghost@0.0.1"])
    assert rc == 0


def test_main_bad_explicit_syntax_returns_two():
    rc = cis.main_with_args(["--explicit", "no-at-sign"])
    assert rc == 2


def test_main_deadline_unscanned_becomes_finding():
    """H4: pre-expired deadline → DEADLINE-UNSCANNED finding → exit 1."""
    fake_cands = [(f"p{i}", "1.0.0", None, "x") for i in range(5)]
    with patch.object(cis, "collect_candidates", return_value=fake_cands), \
         patch.object(cis, "fetch_install_scripts", return_value={}), \
         patch.object(common.Deadline, "expired", return_value=True):
        rc = cis.main_with_args([
            "--max-deps", "0",
            "--total-deadline-sec", "60",
            "--strict",
        ])
    assert rc == 1
