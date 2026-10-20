#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for _supply_chain_common.py."""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
from io import BytesIO
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import _supply_chain_common as common  # noqa: E402

# --------------------------- is_safe_version / is_safe_name ---------------------------

@pytest.mark.parametrize(
    "v,expected",
    [
        ("1.0.0", True),
        ("1.0.0-rc1", True),
        ("1.0.0+build.1", True),
        ("2024.10.1", True),
        ("0.0.1-alpha.0", True),
        ("v1.2.3", True),
        ("", False),
        (".", False),
        ("..", False),
        ("../etc/passwd", False),
        ("1.0/2.0", False),
        ("1.0 0", False),
        ("1.0\n", False),
        ("1.0\x00", False),
        ("'1.0", False),
        ('1.0"', False),
        ("1.0;rm -rf /", False),
    ],
)
def test_is_safe_version(v, expected):
    assert common.is_safe_version(v) == expected


@pytest.mark.parametrize(
    "n,expected",
    [
        ("axios", True),
        ("@scope/pkg", True),
        ("requests", True),
        ("django-rest-framework", True),
        ("foo_bar", True),
        ("foo.bar", True),
        ("", False),
        (".", False),
        ("../evil", False),
        ("evil;rm", False),
        ("evil pkg", False),
        ("evil\npkg", False),
    ],
)
def test_is_safe_name(n, expected):
    assert common.is_safe_name(n) == expected


@pytest.mark.parametrize("alias,spec,target,version", [
    ("@typescript/native", "npm:typescript@7.0.2", "typescript", "7.0.2"),
    ("typescript", "npm:@typescript/typescript6@6.0.2", "@typescript/typescript6", "6.0.2"),
])
def test_approved_npm_manifest_aliases(alias, spec, target, version):
    assert common.resolve_npm_manifest_pin(alias, spec) == (target, version)


@pytest.mark.parametrize("alias,spec", [
    ("@typescript/native", "npm:evil-typescript@7.0.2"),
    ("@typescript/native", "npm:typescript@^7.0.2"),
    ("@typescript/native", "npm:typescript@latest"),
    ("@typescript/native", "npm:typescript@7.0.2/../evil"),
    ("@typescript/native", "npm:@bad/../../evil@7.0.2"),
    ("@unapproved/native", "npm:typescript@7.0.2"),
    ("typescript", "npm:typescript@6.0.2"),
])
def test_npm_manifest_alias_rejects_unapproved_or_non_exact(alias, spec):
    with pytest.raises(ValueError):
        common.resolve_npm_manifest_pin(alias, spec)


def test_lockfile_alias_resolves_transitive_range_with_canonical_tarball():
    packages = {
        "": {"devDependencies": {"@typescript/native": "npm:typescript@7.0.2"}},
        "node_modules/typescript": {"dependencies": {"@typescript/old": "npm:typescript@^6"}},
    }
    declarations = common.npm_alias_declarations(packages)
    info = {
        "name": "typescript",
        "version": "6.0.3",
        "resolved": "https://registry.npmjs.org/typescript/-/typescript-6.0.3.tgz",
    }
    assert common.resolve_npm_lockfile_name("@typescript/old", info, declarations) == "typescript"


def test_established_jest_transitive_alias_is_approved():
    packages = {
        "node_modules/jest-haste-map": {
            "dependencies": {"@jest/react-is-18": "npm:react-is@^18.3.1"},
        },
    }
    declarations = common.npm_alias_declarations(packages)
    info = {
        "name": "react-is", "version": "18.3.1",
        "resolved": "https://registry.npmjs.org/react-is/-/react-is-18.3.1.tgz",
    }
    assert common.resolve_npm_lockfile_name("@jest/react-is-18", info, declarations) == "react-is"


@pytest.mark.parametrize("parent,alias,spec", [
    ("node_modules/parent", "lodash", "npm:evil@1.0.0"),
    ("node_modules/parent", "@typescript/old", "npm:evil@1.0.0"),
    ("", "@typescript/native", "npm:evil@7.0.2"),
])
def test_lockfile_declarations_reject_unapproved_aliases(parent, alias, spec):
    with pytest.raises(ValueError, match="unapproved npm lockfile alias"):
        common.npm_alias_declarations({parent: {"dependencies": {alias: spec}}})


@pytest.mark.parametrize("info", [
    {"name": "evil", "version": "7.0.2", "resolved": "https://registry.npmjs.org/evil/-/evil-7.0.2.tgz"},
    {"name": "typescript", "version": "7.0.2", "resolved": "https://evil.example.com/typescript.tgz"},
    {"name": "typescript", "version": "7.0.2", "resolved": "https://registry.npmjs.org/typescript/-/typescript-7.0.1.tgz"},
    {"name": ["typescript"], "version": "7.0.2", "resolved": "https://registry.npmjs.org/typescript/-/typescript-7.0.2.tgz"},
    {"version": "7.0.2", "resolved": "https://registry.npmjs.org/typescript/-/typescript-7.0.2.tgz"},
])
def test_lockfile_alias_rejects_false_provenance(info):
    declarations = {"@typescript/native": {("typescript", "7.0.2", True)}}
    with pytest.raises(ValueError):
        common.resolve_npm_lockfile_name("@typescript/native", info, declarations)


def test_lockfile_alias_rejects_malformed_or_ambiguous_declarations():
    with pytest.raises(ValueError):
        common.npm_alias_declarations({"": {"dependencies": {"@typescript/native": "npm:typescript@7.0.2/../x"}}})
    info = {
        "name": "typescript", "version": "7.0.2",
        "resolved": "https://registry.npmjs.org/typescript/-/typescript-7.0.2.tgz",
    }
    with pytest.raises(ValueError):
        common.resolve_npm_lockfile_name(
            "@typescript/native", info, {"@typescript/native": {
                ("typescript", "7.0.2", True), ("evil", "7.0.2", False),
            }}
        )


def test_direct_npm_alias_requires_exact_lockfile_version():
    declarations = common.npm_alias_declarations({
        "": {"devDependencies": {"@typescript/native": "npm:typescript@7.0.2"}},
    })
    with pytest.raises(ValueError):
        common.resolve_npm_lockfile_name("@typescript/native", {
            "name": "typescript", "version": "7.0.1",
            "resolved": "https://registry.npmjs.org/typescript/-/typescript-7.0.1.tgz",
        }, declarations)
    assert common.resolve_npm_lockfile_name("@typescript/native", {
        "name": "typescript", "version": "7.0.1",
        "resolved": "https://registry.npmjs.org/typescript/-/typescript-7.0.1.tgz",
    }, declarations, top_level=False) == "typescript"


# --------------------------- safe_url_path ---------------------------

def test_safe_url_path_simple():
    assert common.safe_url_path("axios", "1.0.0") == "axios/1.0.0"


def test_safe_url_path_scoped_name_percent_encodes_slash():
    # urllib.parse.quote percent-encodes the slash in @scope/pkg.
    # This is the correct form for npm's per-version endpoint.
    out = common.safe_url_path("@scope/pkg")
    assert out == "%40scope%2Fpkg"


def test_safe_url_path_rejects_empty():
    with pytest.raises(ValueError):
        common.safe_url_path("foo", "")


# --------------------------- Deadline ---------------------------

def test_deadline_zero_never_expires():
    d = common.Deadline(budget_seconds=0)
    assert not d.expired()
    time.sleep(0.01)
    assert not d.expired()


def test_deadline_negative_never_expires():
    d = common.Deadline(budget_seconds=-5)
    assert not d.expired()


def test_deadline_tracks_elapsed():
    d = common.Deadline(budget_seconds=10)
    time.sleep(0.05)
    assert d.elapsed_seconds() >= 0.04


def test_deadline_expires_when_exhausted():
    d = common.Deadline(budget_seconds=0.05)
    time.sleep(0.10)
    assert d.expired()


# --------------------------- fetch_json ---------------------------

class _FakeResp:
    def __init__(self, body: bytes):
        self._body = body

    def read(self, n=-1):
        if n is None or n < 0:
            data, self._body = self._body, b""
            return data
        data, self._body = self._body[:n], self._body[n:]
        return data

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_fetch_json_returns_parsed():
    body = json.dumps({"hello": "world"}).encode()
    with patch.object(common.urllib.request, "urlopen", return_value=_FakeResp(body)):
        assert common.fetch_json("https://example.com/x") == {"hello": "world"}


def test_fetch_json_404_raises_lookup():
    err = urllib.error.HTTPError("https://x", 404, "Not Found", {}, BytesIO(b""))
    with patch.object(common.urllib.request, "urlopen", side_effect=err), pytest.raises(LookupError):
        common.fetch_json("https://x/missing")


def test_fetch_json_5xx_returns_none():
    err = urllib.error.HTTPError("https://x", 503, "Service Unavailable", {}, BytesIO(b""))
    with patch.object(common.urllib.request, "urlopen", side_effect=err):
        assert common.fetch_json("https://x/transient") is None


def test_fetch_json_timeout_returns_none():
    with patch.object(common.urllib.request, "urlopen", side_effect=TimeoutError("slow")):
        assert common.fetch_json("https://x/slow") is None


def test_fetch_json_decode_error_returns_none():
    body = b"\xff\xfe not utf-8"
    with patch.object(common.urllib.request, "urlopen", return_value=_FakeResp(body)):
        assert common.fetch_json("https://x/garbage") is None


def test_fetch_json_unparseable_json_returns_none():
    body = b"<html>nope</html>"
    with patch.object(common.urllib.request, "urlopen", return_value=_FakeResp(body)):
        assert common.fetch_json("https://x/html") is None


def test_fetch_json_oversized_returns_none():
    # 6 MB body > MAX_RESPONSE_BYTES (5 MB).
    body = b'{"a":"' + b"x" * (6 * 1024 * 1024) + b'"}'
    with patch.object(common.urllib.request, "urlopen", return_value=_FakeResp(body)):
        assert common.fetch_json("https://x/big") is None


def test_fetch_json_at_size_limit_succeeds():
    # 1 KB body, well under the cap.
    body = json.dumps({"v": "x" * 1024}).encode()
    with patch.object(common.urllib.request, "urlopen", return_value=_FakeResp(body)):
        assert common.fetch_json("https://x/small") is not None


# --------------------------- _basename_glob_match ---------------------------

@pytest.mark.parametrize(
    "name,glob,expected",
    [
        ("requirements.txt", "requirements*.txt", True),
        ("requirements-dev.txt", "requirements*.txt", True),
        ("requirements_test.txt", "requirements*.txt", True),
        ("foo.csproj", "*.csproj", True),
        ("requirements.json", "requirements*.txt", False),
        ("notrequirements.txt", "requirements*.txt", False),
    ],
)
def test_basename_glob_match(name, glob, expected):
    assert common._basename_glob_match(name, glob) == expected


# --------------------------- changed_manifests ---------------------------

def _mock_git_diff_names(paths: list[str]):
    """Patch ``run_git`` so ``git diff --name-only`` returns these paths."""
    return patch.object(common, "run_git", return_value="\n".join(paths))


def test_changed_manifests_matches_root_file():
    """The M2 fix: a manifest at the repo root must be matched."""
    with _mock_git_diff_names(["pyproject.toml", "scripts/x.py"]):
        out = common.changed_manifests("origin/main", ["pyproject.toml"])
    assert out == ["pyproject.toml"]


def test_changed_manifests_matches_nested():
    with _mock_git_diff_names(["a/b/c/pyproject.toml"]):
        out = common.changed_manifests("origin/main", ["pyproject.toml"])
    assert out == ["a/b/c/pyproject.toml"]


def test_changed_manifests_handles_glob_basename():
    with _mock_git_diff_names([
        "requirements.txt",
        "requirements-dev.txt",
        "scripts/requirements.json",
    ]):
        out = common.changed_manifests("origin/main", ["requirements*.txt"])
    assert sorted(out) == ["requirements-dev.txt", "requirements.txt"]


def test_changed_manifests_case_insensitive_basename():
    """Windows-style file naming should match regardless of case."""
    with _mock_git_diff_names(["PACKAGES/x/Package.JSON"]):
        out = common.changed_manifests("origin/main", ["package.json"])
    assert out == ["PACKAGES/x/Package.JSON"]


def test_changed_manifests_empty_basenames_returns_empty():
    with _mock_git_diff_names(["x.txt"]):
        out = common.changed_manifests("origin/main", [])
    assert out == []


def test_changed_manifests_handles_backslash_path():
    """Windows-style backslash paths from CRLF git output normalize correctly."""
    with _mock_git_diff_names([r"packages\foo\package.json"]):
        out = common.changed_manifests("origin/main", ["package.json"])
    assert len(out) == 1


# --------------------------- load_*_at ---------------------------

def _mock_two_git_calls(size_out: str, show_out: str):
    """Sequence run_git outputs: first the size, then the show."""
    return patch.object(common, "run_git", side_effect=[size_out, show_out])


def test_load_file_at_missing_returns_none():
    with patch.object(common, "run_git", return_value=""):
        assert common.load_file_at("HEAD", "missing") is None


def test_load_file_at_oversized_returns_none():
    huge = str(common.MAX_MANIFEST_BYTES + 1)
    with patch.object(common, "run_git", return_value=huge):
        assert common.load_file_at("HEAD", "evil") is None


def test_load_file_at_returns_bytes():
    with _mock_two_git_calls("123", "hello world"):
        out = common.load_file_at("HEAD", "x")
    assert out == b"hello world"


def test_load_json_at_parses():
    body = '{"foo": 1}'
    with _mock_two_git_calls(str(len(body)), body):
        out = common.load_json_at("HEAD", "x.json")
    assert out == {"foo": 1}


def test_load_json_at_invalid_returns_none():
    with _mock_two_git_calls("5", "{not}"):
        out = common.load_json_at("HEAD", "x.json")
    assert out is None


def test_load_toml_at_parses_multiline_table():
    """The H2 case: tomllib correctly handles [dependencies.foo] table form."""
    body = '[dependencies.serde]\nversion = "1.0.228"\nfeatures = ["derive"]\n'
    with _mock_two_git_calls(str(len(body)), body):
        out = common.load_toml_at("HEAD", "Cargo.toml")
    assert out is not None
    assert out["dependencies"]["serde"]["version"] == "1.0.228"


def test_load_toml_at_invalid_returns_none():
    with _mock_two_git_calls("10", "not valid ="):
        out = common.load_toml_at("HEAD", "x.toml")
    assert out is None


# --------------------------- diff_lines_added (H1 hardening) ---------------------------

def test_diff_lines_added_basic():
    diff = (
        "diff --git a/req.txt b/req.txt\n"
        "--- a/req.txt\n"
        "+++ b/req.txt\n"
        "@@ -0,0 +1 @@\n"
        "+requests==2.32.0\n"
    )
    with patch.object(common, "run_git", return_value=diff):
        out = common.diff_lines_added("origin/main", ["req.txt"])
    assert out == [("req.txt", "requests==2.32.0")]


def test_diff_lines_added_rejects_double_plus_injection():
    """H1 attack: a content line beginning with '++ b/' must NOT become a file header.

    The attacker tries to redirect added-line attribution to a different file by
    smuggling '+++ b/safe' inside a content line of an unrelated file (e.g., a
    multiline docstring being edited in the same PR).
    """
    diff = (
        "diff --git a/real.txt b/real.txt\n"
        "--- a/real.txt\n"
        "+++ b/real.txt\n"
        "@@ -0,0 +1,2 @@\n"
        "+evil==1.0.0\n"
        # Now a content line that LOOKS like a file header but is not preceded
        # by ``---``. A naive parser would re-attribute the next added line.
        "++ b/safe.txt\n"
        "+++ b/safe.txt\n"
        "+ANOTHER==1.0\n"
    )
    with patch.object(common, "run_git", return_value=diff):
        out = common.diff_lines_added("origin/main", ["real.txt"])
    # Either the entries stay attributed to real.txt, or the injected header is
    # rejected and the second added line is dropped. In neither case may
    # "safe.txt" appear in the output.
    for path, _ in out:
        assert path != "safe.txt", (
            f"H1 INJECTION SUCCEEDED: added line was re-attributed to {path}"
        )


def test_diff_lines_added_skips_dev_null():
    """Removed file (+++ /dev/null) must not become a current_file."""
    diff = (
        "diff --git a/old.txt b/old.txt\n"
        "--- a/old.txt\n"
        "+++ /dev/null\n"
        "@@ -1 +0,0 @@\n"
        "-removed line\n"
    )
    with patch.object(common, "run_git", return_value=diff):
        out = common.diff_lines_added("origin/main", ["old.txt"])
    assert out == []


def test_diff_lines_added_empty_paths_returns_empty():
    out = common.diff_lines_added("origin/main", [])
    assert out == []


def test_diff_lines_added_no_diff_returns_empty():
    with patch.object(common, "run_git", return_value=""):
        out = common.diff_lines_added("origin/main", ["x.txt"])
    assert out == []


def test_diff_lines_added_multiple_files():
    diff = (
        "diff --git a/r1.txt b/r1.txt\n"
        "--- a/r1.txt\n"
        "+++ b/r1.txt\n"
        "@@ -0,0 +1 @@\n"
        "+foo==1.0\n"
        "diff --git a/r2.txt b/r2.txt\n"
        "--- a/r2.txt\n"
        "+++ b/r2.txt\n"
        "@@ -0,0 +1 @@\n"
        "+bar==2.0\n"
    )
    with patch.object(common, "run_git", return_value=diff):
        out = common.diff_lines_added("origin/main", ["r1.txt", "r2.txt"])
    assert sorted(out) == [("r1.txt", "foo==1.0"), ("r2.txt", "bar==2.0")]


# --------------------------- run_git ---------------------------

def test_run_git_failure_returns_empty():
    """A non-zero git exit must return "" so callers can't confuse with success."""

    class _FakeResult:
        returncode = 128
        stdout = "shouldn't be returned"
        stderr = ""

    with patch.object(common.subprocess, "run", return_value=_FakeResult()):
        assert common.run_git(["status"]) == ""


def test_run_git_oserror_returns_empty():
    with patch.object(common.subprocess, "run", side_effect=OSError("git not found")):
        assert common.run_git(["status"]) == ""
