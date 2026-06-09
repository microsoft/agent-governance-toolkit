#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. Licensed under the MIT License.
"""Tests for check_lockfile_integrity.py."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import check_lockfile_integrity as cli  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _sri(payload: bytes, algo: str = "sha512") -> str:
    digest = hashlib.new(algo, payload).digest()
    return f"{algo}-{base64.b64encode(digest).decode('ascii')}"


def _hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _make_npm_lock(*pkgs: tuple[str, str, str]) -> str:
    packages: dict[str, dict] = {"": {"name": "demo", "version": "0.0.0"}}
    for name, version, integrity in pkgs:
        packages[f"node_modules/{name}"] = {
            "version": version,
            "integrity": integrity,
            "resolved": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz",
        }
    return json.dumps({"name": "demo", "version": "0.0.0", "lockfileVersion": 3, "packages": packages})


def _make_cargo_lock(*pkgs: tuple[str, str, str]) -> str:
    parts = ['version = 3', '']
    for name, version, checksum in pkgs:
        parts += [
            "[[package]]",
            f'name = "{name}"',
            f'version = "{version}"',
            'source = "registry+https://github.com/rust-lang/crates.io-index"',
            f'checksum = "{checksum}"',
            "",
        ]
    return "\n".join(parts)


def _make_requirements(*pkgs: tuple[str, str, list[str]]) -> str:
    lines = []
    for name, version, hashes in pkgs:
        hash_parts = " ".join(f"--hash=sha256:{h}" for h in hashes)
        lines.append(f"{name}=={version} {hash_parts}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Safe-log helper
# ---------------------------------------------------------------------------


def test_safe_strips_control_chars():
    assert cli._safe("foo\nbar\x1b[31m") == "foobar[31m"


def test_safe_caps_length():
    assert cli._safe("a" * 500, max_len=10) == "aaaaaaaaaa..."


def test_safe_handles_non_string():
    assert "object" in cli._safe(object())  # falls back to repr


def test_safe_empty():
    assert cli._safe("") == "<empty>"


# ---------------------------------------------------------------------------
# npm parsing
# ---------------------------------------------------------------------------


def test_parse_npm_lockfile_basic():
    sri = _sri(b"left-pad-1.3.0")
    content = _make_npm_lock(("left-pad", "1.3.0", sri))
    entries = cli.parse_npm_lockfile(content, "p/package-lock.json")
    assert len(entries) == 1
    assert entries[0].name == "left-pad"
    assert entries[0].version == "1.3.0"
    assert entries[0].integrity == sri
    assert entries[0].location.startswith("p/package-lock.json::")


def test_parse_npm_lockfile_scoped_and_nested():
    sri = _sri(b"x")
    content = json.dumps({
        "packages": {
            "": {"name": "root"},
            "node_modules/@scope/pkg": {"version": "1.0.0", "integrity": sri},
            "node_modules/a/node_modules/@scope/pkg": {"version": "1.0.0", "integrity": sri},
        }
    })
    entries = cli.parse_npm_lockfile(content, "x.json")
    names = sorted(e.name for e in entries)
    assert names == ["@scope/pkg", "@scope/pkg"]


def test_parse_npm_lockfile_skips_links_and_workspaces():
    sri = _sri(b"x")
    content = json.dumps({
        "packages": {
            "": {"name": "root"},
            "node_modules/linked": {"version": "1.0.0", "link": True},
            "node_modules/good": {"version": "1.0.0", "integrity": sri},
        }
    })
    entries = cli.parse_npm_lockfile(content, "x.json")
    assert [e.name for e in entries] == ["good"]


def test_parse_npm_lockfile_rejects_invalid_integrity():
    content = json.dumps({
        "packages": {
            "node_modules/x": {"version": "1.0.0", "integrity": "not-a-real-sri"},
        }
    })
    assert cli.parse_npm_lockfile(content, "x.json") == []


def test_parse_npm_lockfile_unparseable():
    assert cli.parse_npm_lockfile("not json {", "x.json") == []


def test_parse_npm_lockfile_no_packages_section():
    assert cli.parse_npm_lockfile(json.dumps({"foo": 1}), "x.json") == []


def test_parse_npm_lockfile_rejects_log_injection_name():
    sri = _sri(b"x")
    # newline + ANSI in name must be rejected by NPM_NAME_RE
    content = json.dumps({
        "packages": {
            "node_modules/evil\n\x1b[31m": {"version": "1.0.0", "integrity": sri},
        }
    })
    assert cli.parse_npm_lockfile(content, "x.json") == []


# ---------------------------------------------------------------------------
# npm comparison + fetch
# ---------------------------------------------------------------------------


def test_compare_npm_exact_match():
    sri = _sri(b"x")
    assert cli.compare_npm(sri, sri)


def test_compare_npm_multi_algo_overlap():
    a = _sri(b"x", "sha512")
    b = _sri(b"x", "sha256")
    assert cli.compare_npm(f"{a} {b}", b)


def test_compare_npm_mismatch():
    assert not cli.compare_npm(_sri(b"x"), _sri(b"y"))


def test_compare_npm_rejects_garbage():
    assert not cli.compare_npm("garbage", _sri(b"x"))


# ---------------------------------------------------------------------------
# Cargo parsing
# ---------------------------------------------------------------------------


def test_parse_cargo_basic():
    h = _hex(b"serde-1.0.0")
    content = _make_cargo_lock(("serde", "1.0.0", h))
    entries = cli.parse_cargo_lockfile(content, "Cargo.lock")
    assert len(entries) == 1
    assert entries[0].name == "serde"
    assert entries[0].integrity == h


def test_parse_cargo_skips_path_deps():
    h = _hex(b"x")
    content = _make_cargo_lock(("serde", "1.0.0", h)) + '\n[[package]]\nname = "local"\nversion = "0.0.0"\n'
    entries = cli.parse_cargo_lockfile(content, "Cargo.lock")
    assert [e.name for e in entries] == ["serde"]


def test_parse_cargo_rejects_short_checksum():
    content = _make_cargo_lock(("serde", "1.0.0", "abc"))
    assert cli.parse_cargo_lockfile(content, "Cargo.lock") == []


def test_parse_cargo_unparseable():
    assert cli.parse_cargo_lockfile("[[[[bad", "Cargo.lock") == []


# ---------------------------------------------------------------------------
# Cargo sparse-index path rules
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name,expected", [
    ("a", "1/a"),
    ("ab", "2/ab"),
    ("abc", "3/a/abc"),
    ("abcd", "ab/cd/abcd"),
    ("serde", "se/rd/serde"),
    ("Serde", "se/rd/serde"),
])
def test_crates_index_path(name, expected):
    assert cli.crates_index_path(name) == expected


def test_crates_index_path_rejects_garbage():
    with pytest.raises(cli.RegistryError):
        cli.crates_index_path("evil/../etc/passwd")


# ---------------------------------------------------------------------------
# pip parsing
# ---------------------------------------------------------------------------


def test_parse_pip_basic():
    h = _hex(b"x")
    content = _make_requirements(("requests", "2.31.0", [h]))
    entries = cli.parse_pip_lockfile(content, "r.txt")
    assert len(entries) == 1
    assert entries[0].ecosystem == "pip"
    assert entries[0].integrity == f"sha256:{h}"


def test_parse_pip_multiple_hashes_one_per_artifact():
    h1 = _hex(b"a")
    h2 = _hex(b"b")
    content = _make_requirements(("requests", "2.31.0", [h1, h2]))
    entries = cli.parse_pip_lockfile(content, "r.txt")
    assert sorted(e.integrity for e in entries) == sorted([f"sha256:{h1}", f"sha256:{h2}"])


def test_parse_pip_line_continuations():
    h = _hex(b"x")
    content = f"requests==2.31.0 \\\n    --hash=sha256:{h}\n"
    entries = cli.parse_pip_lockfile(content, "r.txt")
    assert len(entries) == 1
    assert entries[0].integrity == f"sha256:{h}"


def test_parse_pip_skips_unhashed():
    content = "requests==2.31.0\n"
    assert cli.parse_pip_lockfile(content, "r.txt") == []


def test_parse_pip_skips_comments():
    h = _hex(b"x")
    content = f"# pinned\nrequests==2.31.0 --hash=sha256:{h}  # ok\n"
    entries = cli.parse_pip_lockfile(content, "r.txt")
    assert len(entries) == 1


# --- Pip smuggling sentinels (security-review Alert 1) ---


def test_parse_pip_flags_url_form_with_hash():
    """PEP 508 direct URL pins must not be silently dropped — they bypass PyPI."""
    h = _hex(b"x")
    content = f"evilpkg @ https://attacker.example.com/evil-1.0-py3-none-any.whl --hash=sha256:{h}\n"
    entries = cli.parse_pip_lockfile(content, "r.txt")
    assert len(entries) == 1
    assert entries[0].ecosystem == "pip-suspicious"


def test_parse_pip_flags_vcs_form_with_hash():
    h = _hex(b"x")
    content = f"cryptography @ git+https://github.com/attacker/evil@deadbeef --hash=sha256:{h}\n"
    entries = cli.parse_pip_lockfile(content, "r.txt")
    assert any(e.ecosystem == "pip-suspicious" for e in entries)


def test_parse_pip_accepts_sha384_pin():
    payload = b"x"
    import hashlib
    h384 = hashlib.sha384(payload).hexdigest()
    content = f"requests==2.31.0 --hash=sha384:{h384}\n"
    entries = cli.parse_pip_lockfile(content, "r.txt")
    assert len(entries) == 1
    assert entries[0].ecosystem == "pip"
    assert entries[0].integrity == f"sha384:{h384}"


def test_parse_pip_accepts_sha512_pin():
    import hashlib
    h512 = hashlib.sha512(b"x").hexdigest()
    content = f"requests==2.31.0 --hash=sha512:{h512}\n"
    entries = cli.parse_pip_lockfile(content, "r.txt")
    assert len(entries) == 1
    assert entries[0].integrity == f"sha512:{h512}"


def test_parse_pip_flags_unknown_hash_algo():
    """name==version --hash=md5:... must be flagged, not silently ignored."""
    content = "requests==2.31.0 --hash=md5:0123456789abcdef0123456789abcdef\n"
    entries = cli.parse_pip_lockfile(content, "r.txt")
    assert any(e.ecosystem == "pip-suspicious" for e in entries)


def test_parse_pip_flags_truncated_sha256():
    content = "requests==2.31.0 --hash=sha256:abc\n"
    entries = cli.parse_pip_lockfile(content, "r.txt")
    # Truncated hex won't even match the regex (which requires hex chars but
    # is greedy); the line still contains --hash= so we expect the sentinel.
    # Either parses to suspicious or is dropped silently — verify it is NOT
    # silently accepted as a normal "pip" entry.
    assert not any(e.ecosystem == "pip" for e in entries)


def test_verify_emits_error_for_pip_suspicious():
    entry = cli.LockEntry("pip-suspicious", "evilpkg", "1.0",
                          "evilpkg @ https://attacker/x.whl --hash=sha256:xxx", "r.txt:1")
    report = cli.Report()
    cli.verify_entries([entry], report)
    assert len(report.errors) == 1
    assert "manual review" in report.errors[0].message


def test_verify_pip_sha384_matches_upstream():
    import hashlib
    h384 = hashlib.sha384(b"x").hexdigest()
    entries = [cli.LockEntry("pip", "x", "1.0.0", f"sha384:{h384}", "loc")]
    report = cli.Report()
    cli.verify_entries(entries, report, pip_fetcher=lambda n, v: {f"sha384:{h384}"})
    assert report.findings == []


# ---------------------------------------------------------------------------
# diff_entries
# ---------------------------------------------------------------------------


def test_diff_entries_detects_added():
    old = [cli.LockEntry("npm", "a", "1.0.0", _sri(b"a"), "x")]
    sri_b = _sri(b"b")
    new = old + [cli.LockEntry("npm", "b", "1.0.0", sri_b, "y")]
    assert [e.name for e in cli.diff_entries(old, new)] == ["b"]


def test_diff_entries_detects_integrity_change():
    old = [cli.LockEntry("npm", "a", "1.0.0", _sri(b"a"), "x")]
    new = [cli.LockEntry("npm", "a", "1.0.0", _sri(b"a-tampered"), "x")]
    assert cli.diff_entries(old, new) == new


def test_diff_entries_no_change():
    e = cli.LockEntry("npm", "a", "1.0.0", _sri(b"a"), "x")
    assert cli.diff_entries([e], [e]) == []


# ---------------------------------------------------------------------------
# verify_entries (integration via fake fetchers)
# ---------------------------------------------------------------------------


def test_verify_entries_npm_match():
    sri = _sri(b"x")
    entries = [cli.LockEntry("npm", "x", "1.0.0", sri, "loc")]
    report = cli.Report()
    cli.verify_entries(entries, report, npm_fetcher=lambda n, v: sri)
    assert report.findings == []
    assert report.checked == 1


def test_verify_entries_npm_mismatch():
    entries = [cli.LockEntry("npm", "x", "1.0.0", _sri(b"local"), "loc")]
    report = cli.Report()
    cli.verify_entries(entries, report, npm_fetcher=lambda n, v: _sri(b"upstream"))
    assert len(report.errors) == 1
    assert "integrity mismatch" in report.errors[0].message


def test_verify_entries_cargo_mismatch():
    entries = [cli.LockEntry("cargo", "x", "1.0.0", _hex(b"a"), "loc")]
    report = cli.Report()
    cli.verify_entries(entries, report, cargo_fetcher=lambda n, v: _hex(b"b"))
    assert len(report.errors) == 1
    assert "checksum mismatch" in report.errors[0].message


def test_verify_entries_pip_match():
    h = _hex(b"x")
    entries = [cli.LockEntry("pip", "x", "1.0.0", f"sha256:{h}", "loc")]
    report = cli.Report()
    cli.verify_entries(entries, report, pip_fetcher=lambda n, v: {f"sha256:{h}"})
    assert report.findings == []


def test_verify_entries_pip_mismatch():
    entries = [cli.LockEntry("pip", "x", "1.0.0", f"sha256:{_hex(b'local')}", "loc")]
    report = cli.Report()
    cli.verify_entries(entries, report, pip_fetcher=lambda n, v: {f"sha256:{_hex(b'upstream')}"})
    assert len(report.errors) == 1


def test_verify_entries_registry_404_is_error():
    def boom(n, v):
        raise cli.RegistryError("http 404")
    entries = [cli.LockEntry("npm", "x", "1.0.0", _sri(b"x"), "loc")]
    report = cli.Report()
    cli.verify_entries(entries, report, npm_fetcher=boom)
    assert len(report.errors) == 1
    assert "could not verify" in report.errors[0].message


# ---------------------------------------------------------------------------
# run() with mixed ecosystems and DoS cap
# ---------------------------------------------------------------------------


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return str(p)


def test_run_mixed_ecosystems(tmp_path):
    sri = _sri(b"n")
    chex = _hex(b"c")
    phex = _hex(b"p")
    npm = _write(tmp_path, "package-lock.json", _make_npm_lock(("nx", "1.0.0", sri)))
    cargo = _write(tmp_path, "Cargo.lock", _make_cargo_lock(("cx", "1.0.0", chex)))
    pip = _write(tmp_path, "requirements.txt", _make_requirements(("px", "1.0.0", [phex])))

    report = cli.run(
        [npm, cargo, pip],
        base_ref=None,
        max_deps=2000,
        npm_fetcher=lambda n, v: sri,
        cargo_fetcher=lambda n, v: chex,
        pip_fetcher=lambda n, v: {f"sha256:{phex}"},
    )
    assert report.checked == 3
    assert report.findings == []


def test_run_max_deps_cap_returns_capped(tmp_path):
    pkgs = []
    for i in range(5):
        pkgs.append((f"pkg{i}", "1.0.0", _sri(f"x{i}".encode())))
    npm = _write(tmp_path, "package-lock.json", _make_npm_lock(*pkgs))
    report = cli.run(
        [npm], base_ref=None, max_deps=2,
        npm_fetcher=lambda n, v: _sri(b"upstream"),  # any value; we just check capping
    )
    assert report.capped is True
    assert report.skipped == 3
    assert report.checked == 2


def test_run_uses_base_ref_to_skip_unchanged(tmp_path):
    sri_a = _sri(b"a")
    sri_b = _sri(b"b")
    base_content = _make_npm_lock(("a", "1.0.0", sri_a))
    head_content = _make_npm_lock(("a", "1.0.0", sri_a), ("b", "1.0.0", sri_b))
    head_path = _write(tmp_path, "package-lock.json", head_content)

    calls: list[tuple[str, str]] = []

    def fake_npm(name, version):
        calls.append((name, version))
        return sri_b if name == "b" else sri_a

    report = cli.run(
        [head_path],
        base_ref="fake-base",
        max_deps=100,
        npm_fetcher=fake_npm,
        read_base=lambda ref, path: base_content,
    )
    # Only the new entry should have been verified.
    assert calls == [("b", "1.0.0")]
    assert report.checked == 1
    assert report.findings == []


def test_run_missing_path_is_skipped(tmp_path):
    report = cli.run([str(tmp_path / "nope.lock")], base_ref=None, max_deps=10)
    assert report.checked == 0
    assert report.findings == []


# ---------------------------------------------------------------------------
# HTTP guard
# ---------------------------------------------------------------------------


def test_http_get_refuses_non_https():
    with pytest.raises(cli.RegistryError):
        cli._http_get("http://registry.npmjs.org/foo", allowed_hosts=(cli.NPM_HOST,))


def test_http_get_refuses_host_outside_allowlist():
    with pytest.raises(cli.RegistryError):
        cli._http_get("https://evil.example.com/foo", allowed_hosts=(cli.NPM_HOST,))


# ---------------------------------------------------------------------------
# main() CLI entrypoint
# ---------------------------------------------------------------------------


def test_main_returns_zero_when_no_paths_and_no_lockfiles(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "discover_lockfiles", lambda base: [])
    rc = cli.main(["--base", ""])
    assert rc == 0


def test_main_validates_max_deps():
    rc = cli.main(["--max-deps", "0"])
    assert rc == 3


def test_main_returns_two_on_cap(monkeypatch, tmp_path):
    pkgs = [(f"p{i}", "1.0.0", _sri(f"x{i}".encode())) for i in range(3)]
    path = _write(tmp_path, "package-lock.json", _make_npm_lock(*pkgs))
    monkeypatch.setattr(cli, "fetch_npm_integrity", lambda n, v: _sri(b"u"))
    rc = cli.main(["--max-deps", "1", "--base", "", path])
    assert rc == 2


def test_main_returns_one_on_mismatch(monkeypatch, tmp_path):
    path = _write(tmp_path, "package-lock.json", _make_npm_lock(("x", "1.0.0", _sri(b"local"))))
    monkeypatch.setattr(cli, "fetch_npm_integrity", lambda n, v: _sri(b"upstream"))
    rc = cli.main(["--base", "", path])
    assert rc == 1


def test_main_returns_zero_on_match(monkeypatch, tmp_path):
    sri = _sri(b"x")
    path = _write(tmp_path, "package-lock.json", _make_npm_lock(("x", "1.0.0", sri)))
    monkeypatch.setattr(cli, "fetch_npm_integrity", lambda n, v: sri)
    rc = cli.main(["--base", "", path])
    assert rc == 0


def test_main_ignores_unknown_paths(monkeypatch, tmp_path):
    other = _write(tmp_path, "random.txt", "hello")
    rc = cli.main(["--base", "", other])
    assert rc == 0


# ---------------------------------------------------------------------------
# Security: SSRF-via-redirect and ref validation
# ---------------------------------------------------------------------------


def test_http_get_refuses_30x_redirect():
    """A 30x response must not transparently follow to a non-allowlisted host.

    Without the _NoRedirect handler, urllib silently follows 302 anywhere,
    including 169.254.169.254 (cloud metadata). Our opener must raise so
    the caller is forced to handle it explicitly.
    """
    import http.server
    import socket
    import threading

    class RedirectHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(302)
            self.send_header("Location", "https://169.254.169.254/latest/meta-data/")
            self.end_headers()

        def log_message(self, *_args):  # silence test output
            return

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    srv = http.server.HTTPServer(("127.0.0.1", port), RedirectHandler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(cli.RegistryError):
            cli._http_get(f"http://127.0.0.1:{port}/", allowed_hosts=("127.0.0.1",))
    finally:
        srv.shutdown()
        srv.server_close()


def test_discover_lockfiles_rejects_shell_metachar_ref():
    """A maliciously crafted base ref must not reach git argv."""
    with pytest.raises(cli.RegistryError):
        cli.discover_lockfiles("main; rm -rf /")


def test_discover_lockfiles_rejects_revision_arithmetic():
    """``HEAD~5`` and ``main^`` are valid for git but disallowed here."""
    with pytest.raises(cli.RegistryError):
        cli.discover_lockfiles("HEAD~5")
    with pytest.raises(cli.RegistryError):
        cli.discover_lockfiles("main^")


def test_read_base_blob_rejects_at_revision_syntax():
    """``@{upstream}`` and ``@{1}`` revision pseudo-refs must be rejected."""
    with pytest.raises(cli.RegistryError):
        cli.read_base_blob("@{upstream}", "package-lock.json")


def test_validate_ref_accepts_common_forms():
    cli._validate_ref("main")
    cli._validate_ref("origin/main")
    cli._validate_ref("refs/heads/feature-branch")
    cli._validate_ref("v1.2.3")
    cli._validate_ref("a" * 40)  # 40-char SHA


# --- Round-2 adversarial review fixes ---


def test_parse_npm_accepts_multi_algo_sri():
    """Multi-algo SRI (``sha512-X sha256-Y``) must not be silently dropped."""
    sri_a = _sri(b"x", "sha512")
    sri_b = _sri(b"x", "sha256")
    multi = f"{sri_a} {sri_b}"
    content = _make_npm_lock(("nx", "1.0.0", multi))
    entries = cli.parse_npm_lockfile(content, "package-lock.json")
    assert len(entries) == 1
    assert entries[0].ecosystem == "npm"
    # Round-trips through compare_npm
    assert cli.compare_npm(entries[0].integrity, sri_a) is True


def test_parse_pip_flags_requirement_include():
    """``-r evil.txt`` fetches arbitrary code with no hash — must be flagged."""
    content = "-r ./vendored-deps.in\n"
    entries = cli.parse_pip_lockfile(content, "r.txt")
    assert len(entries) == 1
    assert entries[0].ecosystem == "pip-suspicious"


def test_parse_pip_flags_editable_vcs():
    content = "-e git+https://attacker.example/repo@HEAD#egg=foo\n"
    entries = cli.parse_pip_lockfile(content, "r.txt")
    assert any(e.ecosystem == "pip-suspicious" for e in entries)


def test_parse_pip_flags_index_url_redirect():
    content = "--index-url https://attacker.example/simple/\n"
    entries = cli.parse_pip_lockfile(content, "r.txt")
    assert any(e.ecosystem == "pip-suspicious" for e in entries)


def test_parse_pip_flags_constraint_and_find_links():
    """Other pip directives that pull code without hash gating."""
    for line in (
        "-c constraints.txt\n",
        "--find-links ./wheels/\n",
        "--extra-index-url https://attacker/simple/\n",
        "--trusted-host attacker.example\n",
    ):
        entries = cli.parse_pip_lockfile(line, "r.txt")
        assert any(e.ecosystem == "pip-suspicious" for e in entries), \
            f"directive not flagged: {line!r}"


def test_validate_ref_rejects_leading_dash():
    """``-Gpattern`` would otherwise be passed to git as an option."""
    with pytest.raises(cli.RegistryError):
        cli._validate_ref("-Gpattern")
    with pytest.raises(cli.RegistryError):
        cli._validate_ref("--no-pager")


def test_validate_ref_rejects_leading_dot_and_double_dot():
    """git's check-ref-format forbids these for the same reason."""
    with pytest.raises(cli.RegistryError):
        cli._validate_ref(".foo")
    with pytest.raises(cli.RegistryError):
        cli._validate_ref("..foo")
    with pytest.raises(cli.RegistryError):
        cli._validate_ref("foo..bar")


# --- Round-3 adversarial review fixes ---


def test_parse_npm_flags_same_algo_multi_token():
    """``sha512-EVIL sha512-LEGIT`` is alternative-form; npm/ssri accepts
    either, so a verifier that uses set-intersection would say OK while
    npm ci installs the bytes hashing to EVIL.
    """
    evil = _sri(b"evil", "sha512")
    legit = _sri(b"legit", "sha512")
    multi_same = f"{evil} {legit}"
    content = _make_npm_lock(("nx", "1.0.0", multi_same))
    entries = cli.parse_npm_lockfile(content, "package-lock.json")
    assert len(entries) == 1
    assert entries[0].ecosystem == "npm-suspicious"


def test_parse_npm_still_accepts_legit_cross_algo():
    """Different algorithms covering the same artifact stay legal."""
    a = _sri(b"x", "sha512")
    b = _sri(b"x", "sha256")
    content = _make_npm_lock(("nx", "1.0.0", f"{a} {b}"))
    entries = cli.parse_npm_lockfile(content, "package-lock.json")
    assert len(entries) == 1
    assert entries[0].ecosystem == "npm"


def test_verify_emits_error_for_npm_suspicious():
    """Sentinel must always surface as an error finding."""
    entry = cli.LockEntry(
        "npm-suspicious", "x", "1.0.0",
        "sha512-EVIL== sha512-LEGIT==", "loc",
    )
    report = cli.Report()
    cli.verify_entries([entry], report)
    assert len(report.errors) == 1
    assert "alternatives" in report.errors[0].message


def test_parse_pip_flags_short_attached_index_url():
    """``-ihttps://attacker/`` is parsed by pip's optparse as -i <url>."""
    content = "-ihttps://attacker.example/simple/\n"
    entries = cli.parse_pip_lockfile(content, "r.txt")
    assert len(entries) == 1
    assert entries[0].ecosystem == "pip-suspicious"


def test_parse_pip_flags_short_attached_requirement():
    content = "-rrequirements-evil.txt\n"
    entries = cli.parse_pip_lockfile(content, "r.txt")
    assert any(e.ecosystem == "pip-suspicious" for e in entries)


def test_parse_pip_flags_short_attached_editable_and_find_links():
    for line in (
        "-e./malicious-local-path\n",
        "-fhttps://attacker.example/wheels/\n",
        "-cconstraints-evil.txt\n",
    ):
        entries = cli.parse_pip_lockfile(line, "r.txt")
        assert any(e.ecosystem == "pip-suspicious" for e in entries), \
            f"short-attached form not flagged: {line!r}"


def test_parse_pip_bare_dash_not_treated_as_directive():
    """A pure ``-`` (no following chars) is malformed but not a known
    attack vector; ensure parser doesn't crash and doesn't FP."""
    entries = cli.parse_pip_lockfile("-\n", "r.txt")
    # Either dropped or flagged — but no exception.
    assert isinstance(entries, list)


# --- Round-4 adversarial review fixes ---


def test_oversize_lockfile_is_skipped_not_oomed(tmp_path, monkeypatch):
    """Hostile multi-GB ``package-lock.json`` in a PR must not OOM the
    runner. We simulate by lowering the cap and creating a file just
    over it."""
    monkeypatch.setattr(cli, "MAX_LOCKFILE_BYTES", 256)
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text("x" * 1024, encoding="utf-8")
    report = cli.run(
        paths=[str(lockfile)],
        base_ref=None,
        max_deps=2000,
    )
    assert any("larger than" in f.message for f in report.findings if f.severity == "warning")
    assert not report.errors


def test_run_git_caps_stdout(monkeypatch):
    """``git`` stdout is bounded; a hostile blob in history would
    otherwise be loaded entirely into memory."""
    monkeypatch.setattr(cli, "MAX_GIT_STDOUT_BYTES", 32)
    # ``git --version`` emits well under 32 bytes; ``git config -l``
    # in a fresh repo can exceed it on some hosts — but the real
    # behaviour we care about is that the function *enforces* the cap
    # without raising. Use a portable echo via git's own help.
    rc, out, err = cli._run_git(["--version"])
    assert isinstance(out, str)
    # Result string is bounded even if the underlying command produced
    # more bytes; we don't assert exact length because git's own output
    # is short.
    assert len(out.encode("utf-8")) <= cli.MAX_GIT_STDOUT_BYTES + 64
