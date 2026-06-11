#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for ``scripts/check_dependency_scorecard.py``."""

from __future__ import annotations

import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SCRIPTS))

import check_dependency_scorecard as cds  # noqa: E402


# ---------- Fakes ------------------------------------------------------------


class FakeGit:
    """Stand-in for the git runner used by diff helpers."""

    def __init__(self, blobs: dict[tuple[str, str], str], changed: list[str]):
        # blobs: {(ref, path): contents}
        self.blobs = blobs
        self.changed = changed

    def __call__(self, args: list[str]) -> str:
        if args[:2] == ["diff", "--name-only"]:
            return "\n".join(self.changed) + ("\n" if self.changed else "")
        if args[0] == "show":
            spec = args[1]
            ref, _, path = spec.partition(":")
            if (ref, path) in self.blobs:
                return self.blobs[(ref, path)]
            raise RuntimeError(f"missing blob: {spec}")
        raise AssertionError(f"unexpected git args: {args}")


class FakeHttp:
    """Stand-in for the urllib opener; URL → (status, body bytes)."""

    def __init__(self, mapping: dict[str, tuple[int, bytes]]):
        self.mapping = mapping
        self.calls: list[str] = []

    def __call__(self, url: str) -> tuple[int, bytes]:
        self.calls.append(url)
        if url in self.mapping:
            return self.mapping[url]
        return 404, b""


def _json_body(obj: Any) -> bytes:
    return json.dumps(obj).encode("utf-8")


# ---------- Manifest parsing -------------------------------------------------


def test_parse_npm_picks_up_deps_and_devdeps():
    text = json.dumps(
        {"dependencies": {"axios": "1.0.0"}, "devDependencies": {"jest": "29.0.0"}}
    )
    assert cds.parse_npm_direct_deps(text) == {"axios", "jest"}


def test_parse_npm_ignores_unknown_sections_and_invalid_names():
    text = json.dumps(
        {
            "dependencies": {"good-pkg": "1.0.0", "BAD NAME!!": "1.0.0"},
            "peerDependencies": {"react": "18.0.0"},
        }
    )
    parsed = cds.parse_npm_direct_deps(text)
    assert parsed == {"good-pkg"}


def test_parse_npm_returns_empty_on_invalid_json():
    assert cds.parse_npm_direct_deps("{not json") == set()


def test_parse_pyproject_includes_optional_groups():
    text = (
        '[project]\n'
        'name = "x"\n'
        'dependencies = ["requests>=2.0", "click; python_version>=\'3.8\'"]\n'
        '[project.optional-dependencies]\n'
        'dev = ["pytest>=7.0", "ruff"]\n'
    )
    assert cds.parse_pyproject_direct_deps(text) == {"requests", "click", "pytest", "ruff"}


def test_parse_pyproject_strips_extras_and_markers():
    text = (
        '[project]\n'
        'name = "x"\n'
        'dependencies = ["fastapi[all] >= 0.100", "uvicorn[standard]==0.23"]\n'
    )
    assert cds.parse_pyproject_direct_deps(text) == {"fastapi", "uvicorn"}


def test_parse_cargo_collects_both_sections():
    text = (
        '[dependencies]\nserde = "1.0"\ntokio = { version = "1", features = ["full"] }\n'
        '[dev-dependencies]\nmockall = "0.11"\n'
    )
    assert cds.parse_cargo_direct_deps(text) == {"serde", "tokio", "mockall"}


def test_parse_cargo_ignores_invalid_toml():
    assert cds.parse_cargo_direct_deps("[deps\n=invalid") == set()


# ---------- Diff computation -------------------------------------------------


def test_compute_new_deps_flags_only_added_names():
    base_pkg = json.dumps({"dependencies": {"axios": "1.0.0"}})
    head_pkg = json.dumps(
        {"dependencies": {"axios": "1.1.0", "lodash": "4.17.21"}}
    )
    git = FakeGit(
        blobs={
            ("origin/main", "package.json"): base_pkg,
            ("HEAD", "package.json"): head_pkg,
        },
        changed=["package.json"],
    )
    deps = cds.compute_new_deps("origin/main", "HEAD", runner=git)
    assert [(d.ecosystem, d.name) for d in deps] == [("npm", "lodash")]


def test_compute_new_deps_ignores_pure_version_bumps():
    base = json.dumps({"dependencies": {"axios": "1.0.0"}})
    head = json.dumps({"dependencies": {"axios": "1.9.9"}})
    git = FakeGit(
        blobs={("origin/main", "package.json"): base, ("HEAD", "package.json"): head},
        changed=["package.json"],
    )
    assert cds.compute_new_deps("origin/main", "HEAD", runner=git) == []


def test_compute_new_deps_handles_new_manifest_file():
    head = json.dumps({"dependencies": {"axios": "1.0.0"}})
    git = FakeGit(
        blobs={("HEAD", "subpkg/package.json"): head},
        changed=["subpkg/package.json"],
    )
    deps = cds.compute_new_deps("origin/main", "HEAD", runner=git)
    assert [(d.ecosystem, d.name) for d in deps] == [("npm", "axios")]


def test_compute_new_deps_skips_lockfiles_and_unrelated_paths():
    git = FakeGit(blobs={}, changed=["README.md", "package-lock.json", "src/main.py"])
    assert cds.compute_new_deps("base", "head", runner=git) == []


def test_compute_new_deps_dedupes_across_manifests():
    text = json.dumps({"dependencies": {"shared": "1.0"}})
    git = FakeGit(
        blobs={
            ("HEAD", "a/package.json"): text,
            ("HEAD", "b/package.json"): text,
        },
        changed=["a/package.json", "b/package.json"],
    )
    deps = cds.compute_new_deps("base", "HEAD", runner=git)
    assert len(deps) == 1
    assert deps[0].name == "shared"


def test_compute_new_deps_handles_multiple_ecosystems():
    git = FakeGit(
        blobs={
            ("HEAD", "package.json"): json.dumps({"dependencies": {"axios": "1.0"}}),
            ("HEAD", "pyproject.toml"): '[project]\nname="x"\ndependencies=["requests"]\n',
            ("HEAD", "Cargo.toml"): '[dependencies]\nserde = "1.0"\n',
        },
        changed=["package.json", "pyproject.toml", "Cargo.toml"],
    )
    deps = cds.compute_new_deps("base", "HEAD", runner=git)
    names = sorted((d.ecosystem, d.name) for d in deps)
    assert names == [("cargo", "serde"), ("npm", "axios"), ("pypi", "requests")]


# ---------- GitHub URL canonicalization (the SSRF gate) ----------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("https://github.com/foo/bar", "https://github.com/foo/bar"),
        ("https://github.com/foo/bar/", "https://github.com/foo/bar"),
        ("https://github.com/foo/bar.git", "https://github.com/foo/bar"),
        ("git+https://github.com/foo/bar.git", "https://github.com/foo/bar"),
        ("git://github.com/foo/bar.git", "https://github.com/foo/bar"),
        ("git@github.com:foo/bar.git", "https://github.com/foo/bar"),
        ("http://github.com/foo/bar", "https://github.com/foo/bar"),
    ],
)
def test_canonicalize_accepts_known_github_forms(raw, expected):
    assert cds._canonicalize_github_url(raw) == expected


@pytest.mark.parametrize(
    "raw,expected",
    [
        # SSH owner regex must accept the same chars as GITHUB_REPO_RE so
        # that a git@ URL doesn't silently drop where an https URL would
        # canonicalize. Repo segment continues to accept dot/dash/underscore.
        (
            "git@github.com:my-org/my.repo.git",
            "https://github.com/my-org/my.repo",
        ),
        (
            "git@github.com:my-org/my_repo",
            "https://github.com/my-org/my_repo",
        ),
        (
            "git@github.com:org123/repo-name.git",
            "https://github.com/org123/repo-name",
        ),
    ],
)
def test_canonicalize_ssh_owner_regex_matches_github_repo_re(raw, expected):
    """Regression for review feedback: SSH owner regex must not be narrower
    than the canonical GITHUB_REPO_RE."""
    assert cds._canonicalize_github_url(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "https://gitlab.com/foo/bar",
        "https://example.com/foo/bar",
        "https://github.com/foo/bar/../../evil",
        "https://github.com/foo",  # too few segments
        "https://github.com/",
        "https://github.com/../bar",
        "https://github.com/./bar",
        "https://github.com.evil.com/foo/bar",
        "javascript:alert(1)",
        "file:///etc/passwd",
        "https://github.com:8080/foo/bar",
    ],
)
def test_canonicalize_rejects_non_github_or_malicious(raw):
    assert cds._canonicalize_github_url(raw) is None


def test_query_scorecard_refuses_unvalidated_url():
    with pytest.raises(ValueError, match="refusing un-validated"):
        cds.query_scorecard("https://evil.com/x/y", opener=FakeHttp({}))


def test_query_scorecard_builds_correct_api_url():
    http = FakeHttp(
        {
            "https://api.securityscorecards.dev/projects/github.com/foo/bar": (
                200, _json_body({"score": 7.5})
            )
        }
    )
    status, payload = cds.query_scorecard("https://github.com/foo/bar", opener=http)
    assert status == 200
    assert payload == {"score": 7.5}
    assert http.calls == [
        "https://api.securityscorecards.dev/projects/github.com/foo/bar"
    ]


# ---------- Registry resolution ---------------------------------------------


def test_resolve_npm_extracts_repo_from_object():
    http = FakeHttp(
        {
            "https://registry.npmjs.org/axios": (
                200,
                _json_body(
                    {"repository": {"type": "git", "url": "git+https://github.com/axios/axios.git"}}
                ),
            )
        }
    )
    dep = cds.NewDep(ecosystem="npm", name="axios", file="package.json")
    assert cds.resolve_repo_url(dep, opener=http) == "https://github.com/axios/axios"


def test_resolve_npm_extracts_repo_from_string_form():
    http = FakeHttp(
        {
            "https://registry.npmjs.org/lodash": (
                200,
                _json_body({"repository": "github:lodash/lodash"}),  # shorthand → no match
            )
        }
    )
    dep = cds.NewDep(ecosystem="npm", name="lodash", file="package.json")
    # "github:lodash/lodash" should NOT canonicalize — not a github.com URL.
    assert cds.resolve_repo_url(dep, opener=http) is None


def test_resolve_pypi_prefers_source_url_then_falls_back():
    http = FakeHttp(
        {
            "https://pypi.org/pypi/requests/json": (
                200,
                _json_body(
                    {
                        "info": {
                            "project_urls": {
                                "Homepage": "https://requests.readthedocs.io",
                                "Source": "https://github.com/psf/requests",
                            }
                        }
                    }
                ),
            )
        }
    )
    dep = cds.NewDep(ecosystem="pypi", name="requests", file="pyproject.toml")
    assert cds.resolve_repo_url(dep, opener=http) == "https://github.com/psf/requests"


def test_resolve_cargo_uses_crate_repository_field():
    http = FakeHttp(
        {
            "https://crates.io/api/v1/crates/serde": (
                200,
                _json_body({"crate": {"repository": "https://github.com/serde-rs/serde"}}),
            )
        }
    )
    dep = cds.NewDep(ecosystem="cargo", name="serde", file="Cargo.toml")
    assert cds.resolve_repo_url(dep, opener=http) == "https://github.com/serde-rs/serde"


def test_resolve_rejects_invalid_package_names():
    http = FakeHttp({})
    dep = cds.NewDep(ecosystem="npm", name="../etc/passwd", file="package.json")
    assert cds.resolve_repo_url(dep, opener=http) is None
    assert http.calls == []  # never even hit the network


def test_resolve_returns_none_when_registry_returns_404():
    http = FakeHttp({})  # everything 404
    dep = cds.NewDep(ecosystem="npm", name="nonexistent", file="package.json")
    assert cds.resolve_repo_url(dep, opener=http) is None


# ---------- score_deps orchestration ----------------------------------------


def _opener_for(
    *,
    registry_payloads: dict[str, dict[str, Any]],
    scorecards: dict[str, tuple[int, dict[str, Any] | None]],
) -> FakeHttp:
    mapping: dict[str, tuple[int, bytes]] = {}
    for url, payload in registry_payloads.items():
        mapping[url] = (200, _json_body(payload))
    for repo_url, (status, payload) in scorecards.items():
        api = f"https://api.securityscorecards.dev/projects/github.com/{repo_url}"
        body = _json_body(payload) if payload is not None else b""
        mapping[api] = (status, body)
    return FakeHttp(mapping)


def test_score_deps_flags_below_threshold():
    http = _opener_for(
        registry_payloads={
            "https://registry.npmjs.org/sketchy": {
                "repository": {"url": "https://github.com/anon/sketchy"}
            }
        },
        scorecards={
            "anon/sketchy": (
                200,
                {"score": 3.2, "checks": [{"name": "Maintained", "score": 0}]},
            )
        },
    )
    dep = cds.NewDep(ecosystem="npm", name="sketchy", file="package.json")
    results = cds.score_deps([dep], min_score=5.0, opener=http)
    assert len(results) == 1
    assert results[0].status == "below"
    assert results[0].score == 3.2
    assert results[0].repo_url == "https://github.com/anon/sketchy"


def test_score_deps_high_score_passes_silently():
    http = _opener_for(
        registry_payloads={
            "https://registry.npmjs.org/safe": {
                "repository": {"url": "https://github.com/org/safe.git"}
            }
        },
        scorecards={"org/safe": (200, {"score": 8.7})},
    )
    dep = cds.NewDep(ecosystem="npm", name="safe", file="package.json")
    results = cds.score_deps([dep], min_score=5.0, opener=http)
    assert results[0].status == "above"
    assert results[0].score == 8.7


def test_score_deps_marks_untracked_on_404_from_scorecard():
    http = _opener_for(
        registry_payloads={
            "https://registry.npmjs.org/obscure": {
                "repository": {"url": "https://github.com/x/obscure"}
            }
        },
        scorecards={"x/obscure": (404, None)},
    )
    dep = cds.NewDep(ecosystem="npm", name="obscure", file="package.json")
    results = cds.score_deps([dep], min_score=5.0, opener=http)
    assert results[0].status == "untracked"


def test_score_deps_marks_no_repo_when_resolution_fails():
    # Registry returns metadata without a repository field.
    http = _opener_for(
        registry_payloads={"https://registry.npmjs.org/orphan": {}},
        scorecards={},
    )
    dep = cds.NewDep(ecosystem="npm", name="orphan", file="package.json")
    results = cds.score_deps([dep], min_score=5.0, opener=http)
    assert results[0].status == "no-repo"


def test_score_deps_handles_non_github_repo_url():
    http = _opener_for(
        registry_payloads={
            "https://registry.npmjs.org/gl-pkg": {
                "repository": {"url": "https://gitlab.com/group/proj"}
            }
        },
        scorecards={},
    )
    dep = cds.NewDep(ecosystem="npm", name="gl-pkg", file="package.json")
    results = cds.score_deps([dep], min_score=5.0, opener=http)
    assert results[0].status == "no-repo"
    assert results[0].repo_url is None


def test_score_deps_swallows_per_dep_errors():
    def boom(url: str) -> tuple[int, bytes]:
        raise RuntimeError("network down")

    dep = cds.NewDep(ecosystem="npm", name="anything", file="package.json")
    results = cds.score_deps([dep], min_score=5.0, opener=boom)
    assert results[0].status == "error"
    assert "network down" in results[0].message


def test_score_deps_treats_missing_score_field_as_untracked():
    http = _opener_for(
        registry_payloads={
            "https://registry.npmjs.org/weird": {
                "repository": {"url": "https://github.com/x/weird"}
            }
        },
        scorecards={"x/weird": (200, {"checks": []})},  # no "score" key
    )
    dep = cds.NewDep(ecosystem="npm", name="weird", file="package.json")
    results = cds.score_deps([dep], min_score=5.0, opener=http)
    assert results[0].status == "untracked"


def test_score_deps_min_score_threshold_is_inclusive():
    http = _opener_for(
        registry_payloads={
            "https://registry.npmjs.org/edge": {
                "repository": {"url": "https://github.com/o/edge"}
            }
        },
        scorecards={"o/edge": (200, {"score": 5.0})},
    )
    dep = cds.NewDep(ecosystem="npm", name="edge", file="package.json")
    results = cds.score_deps([dep], min_score=5.0, opener=http)
    # 5.0 is NOT below 5.0; should pass.
    assert results[0].status == "above"


# ---------- Reporting --------------------------------------------------------


def test_format_report_empty_when_no_deps():
    assert "No new direct dependencies" in cds.format_report([], 5.0)


def test_format_report_renders_table():
    r = cds.ScoreResult(
        dep=cds.NewDep("npm", "axios", "package.json"),
        repo_url="https://github.com/axios/axios",
        score=8.1,
        status="above",
        message="score 8.1",
    )
    report = cds.format_report([r], 5.0)
    assert "| npm | `axios` |" in report
    assert "8.1" in report


def test_emit_annotations_warns_on_below_score():
    r = cds.ScoreResult(
        dep=cds.NewDep("npm", "bad", "package.json"),
        repo_url="https://github.com/o/bad",
        score=2.1,
        status="below",
        message="score 2.1 below threshold 5.0",
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        cds.emit_annotations([r])
    out = buf.getvalue()
    assert "::warning" in out
    assert "bad" in out


def test_emit_annotations_notices_for_untracked():
    r = cds.ScoreResult(
        dep=cds.NewDep("pypi", "tiny", "pyproject.toml"),
        status="untracked",
        message="not tracked",
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        cds.emit_annotations([r])
    assert "::notice" in buf.getvalue()


def test_emit_annotations_notices_for_no_repo():
    """Cover the no-repo branch: dep with no discoverable GitHub URL."""
    r = cds.ScoreResult(
        dep=cds.NewDep("npm", "private-pkg", "package.json"),
        status="no-repo",
        message="no GitHub source URL",
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        cds.emit_annotations([r])
    out = buf.getvalue()
    assert "::notice" in out
    assert "private-pkg" in out
    assert "no discoverable GitHub source URL" in out


def test_emit_annotations_notices_on_error():
    """Cover the error branch: registry/Scorecard call failed transiently."""
    r = cds.ScoreResult(
        dep=cds.NewDep("cargo", "flaky-crate", "Cargo.toml"),
        status="error",
        message="HTTP 502 from crates.io",
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        cds.emit_annotations([r])
    out = buf.getvalue()
    assert "::notice" in out
    assert "flaky-crate" in out
    assert "HTTP 502" in out


def test_emit_annotations_silent_on_pass():
    """Passing scores must not emit any annotation (warn-only by default)."""
    r = cds.ScoreResult(
        dep=cds.NewDep("npm", "good-pkg", "package.json"),
        status="pass",
        score=8.5,
        repo_url="https://github.com/good/pkg",
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        cds.emit_annotations([r])
    assert buf.getvalue() == ""


# ---------- main / CLI -------------------------------------------------------


def test_main_overflow_exits_2(monkeypatch):
    deps = [
        cds.NewDep("npm", f"p{i}", "package.json") for i in range(60)
    ]
    monkeypatch.setattr(cds, "compute_new_deps", lambda *a, **k: deps)
    rc = cds.main(["--max-deps", "50"])
    assert rc == cds.EXIT_OVERFLOW


def test_main_strict_exits_1_on_low_score(monkeypatch):
    dep = cds.NewDep("npm", "bad", "package.json")
    monkeypatch.setattr(cds, "compute_new_deps", lambda *a, **k: [dep])

    def fake_score(deps, min_score, opener=None, skip_patterns=None):
        return [
            cds.ScoreResult(
                dep=dep, repo_url="https://github.com/o/bad",
                score=1.0, status="below", message="low",
            )
        ]

    monkeypatch.setattr(cds, "score_deps", fake_score)
    rc = cds.main(["--strict", "--min-score", "5.0"])
    assert rc == cds.EXIT_STRICT_FAIL


def test_main_default_is_warn_only(monkeypatch):
    dep = cds.NewDep("npm", "bad", "package.json")
    monkeypatch.setattr(cds, "compute_new_deps", lambda *a, **k: [dep])
    monkeypatch.setattr(
        cds, "score_deps",
        lambda deps, min_score, opener=None, skip_patterns=None: [
            cds.ScoreResult(dep=dep, status="below", score=1.0, message="low")
        ],
    )
    rc = cds.main([])
    assert rc == cds.EXIT_OK


def test_main_usage_error_on_bad_min_score():
    rc = cds.main(["--min-score", "99"])
    assert rc == cds.EXIT_USAGE


def test_main_usage_error_on_bad_max_deps():
    rc = cds.main(["--max-deps", "0"])
    assert rc == cds.EXIT_USAGE


def test_main_returns_usage_on_git_failure(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("git boom")

    monkeypatch.setattr(cds, "compute_new_deps", boom)
    rc = cds.main([])
    assert rc == cds.EXIT_USAGE


def test_main_succeeds_with_no_new_deps(monkeypatch):
    monkeypatch.setattr(cds, "compute_new_deps", lambda *a, **k: [])
    rc = cds.main([])
    assert rc == cds.EXIT_OK


def test_min_score_override_changes_threshold(monkeypatch):
    dep = cds.NewDep("npm", "mid", "package.json")
    monkeypatch.setattr(cds, "compute_new_deps", lambda *a, **k: [dep])
    captured: dict[str, float] = {}

    def fake_score(deps, min_score, opener=None, skip_patterns=None):
        captured["min_score"] = min_score
        return [cds.ScoreResult(dep=dep, status="above", score=7.0, message="ok")]

    monkeypatch.setattr(cds, "score_deps", fake_score)
    rc = cds.main(["--min-score", "7.5"])
    assert rc == cds.EXIT_OK
    assert captured["min_score"] == 7.5


# ---------- Post-redteam coverage --------------------------------------------


def test_npm_includes_optional_dependencies():
    text = json.dumps(
        {
            "dependencies": {"a": "1"},
            "devDependencies": {"b": "1"},
            "optionalDependencies": {"c": "1"},
            "peerDependencies": {"d": "1"},  # excluded by design
        }
    )
    assert cds.parse_npm_direct_deps(text) == {"a", "b", "c"}


def test_pyproject_includes_build_system_requires():
    text = (
        '[build-system]\n'
        'requires = ["setuptools>=68", "wheel"]\n'
        '[project]\nname = "x"\ndependencies = ["requests"]\n'
    )
    parsed = cds.parse_pyproject_direct_deps(text)
    assert {"setuptools", "wheel", "requests"} <= parsed


def test_pyproject_includes_pep735_dependency_groups():
    text = (
        '[project]\nname = "x"\n'
        '[dependency-groups]\n'
        'dev = ["pytest", "ruff"]\n'
        'docs = ["mkdocs"]\n'
    )
    assert cds.parse_pyproject_direct_deps(text) == {"pytest", "ruff", "mkdocs"}


def test_pyproject_includes_poetry_sections():
    text = (
        '[tool.poetry]\nname = "x"\n'
        '[tool.poetry.dependencies]\n'
        'python = "^3.11"\n'
        'httpx = "^0.27"\n'
        '[tool.poetry.group.dev.dependencies]\n'
        'pytest = "^8.0"\n'
    )
    parsed = cds.parse_pyproject_direct_deps(text)
    assert "httpx" in parsed
    assert "pytest" in parsed
    assert "python" not in parsed  # the language marker, not a package


def test_cargo_includes_build_dependencies_and_target_tables():
    text = (
        '[dependencies]\nserde = "1"\n'
        '[build-dependencies]\ncc = "1"\n'
        '[target."cfg(unix)".dependencies]\nlibc = "0.2"\n'
        '[target."cfg(windows)".build-dependencies]\nwinres = "0.1"\n'
    )
    parsed = cds.parse_cargo_direct_deps(text)
    assert parsed == {"serde", "cc", "libc", "winres"}


def test_no_redirect_handler_rejects_all_redirects():
    handler = cds._NoRedirectHandler()
    # urllib's contract: returning None tells urlopen NOT to follow the redirect.
    assert handler.redirect_request(None, None, 302, "Found", {}, "https://evil/") is None
    assert handler.redirect_request(None, None, 301, "Moved", {}, "https://x/") is None


def test_skip_pattern_short_circuits_before_network():
    http = FakeHttp({})  # any registry call would 404; we want NO call at all
    dep = cds.NewDep("npm", "@internal/secret", "package.json")
    pattern = [__import__("re").compile(r"^@internal/")]
    results = cds.score_deps([dep], min_score=5.0, opener=http, skip_patterns=pattern)
    assert results[0].status == "skipped"
    assert "--skip-pattern" in results[0].message
    assert http.calls == []  # never queried public registry


def test_skip_pattern_does_not_match_unrelated_names():
    http = _opener_for(
        registry_payloads={
            "https://registry.npmjs.org/public-pkg": {
                "repository": {"url": "https://github.com/o/public-pkg"}
            }
        },
        scorecards={"o/public-pkg": (200, {"score": 8.0})},
    )
    dep = cds.NewDep("npm", "public-pkg", "package.json")
    pattern = [__import__("re").compile(r"^@internal/")]
    results = cds.score_deps([dep], min_score=5.0, opener=http, skip_patterns=pattern)
    assert results[0].status == "above"


def test_main_rejects_invalid_skip_pattern_regex():
    rc = cds.main(["--skip-pattern", "[unclosed"])
    assert rc == cds.EXIT_USAGE
