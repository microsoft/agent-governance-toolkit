# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""RE2 compatibility unit tests for :mod:`agt.policies._re2`.

These guard the fail-open class the OPA-less runtime bridge path is exposed to:
``fnmatch.translate`` emits atomic groups ``(?>...)`` on CPython >= 3.12 that
Go RE2 rejects, and validation must never silently succeed when OPA is absent.
"""

from __future__ import annotations

import builtins

import pytest

from agt.policies import _re2


def _no_opa(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ACS_OPA_PATH", raising=False)
    monkeypatch.setattr(_re2.shutil, "which", lambda _name: None)


def _no_google_re2(monkeypatch: pytest.MonkeyPatch) -> None:
    real_import = builtins.__import__

    def guarded(name, *args, **kwargs):
        if name == "re2":
            raise ImportError("blocked for test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded)


@pytest.mark.parametrize("pattern", ["*secret*", "a*b*c", "*a*b*c*d*e*", "***x***"])
def test_glob_to_re2_never_emits_atomic_groups(
    pattern: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Multi-wildcard globs must translate to RE2-safe output (no ``(?>``)."""
    _no_opa(monkeypatch)
    translated = _re2.glob_to_re2(pattern)
    assert "(?>" not in translated
    assert translated.endswith(r"\z")


def test_glob_to_re2_uses_re2_end_anchor(monkeypatch: pytest.MonkeyPatch) -> None:
    _no_opa(monkeypatch)
    translated = _re2.glob_to_re2("*.exe")
    assert r"\Z" not in translated
    assert translated.endswith(r"\z")


@pytest.mark.parametrize("pattern", ["[](?x)]", "[]a]", "[^]]", "[]]", "[!]x]"])
def test_glob_to_re2_handles_literal_bracket_in_class(
    pattern: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A ']' as the first class member must not confuse the compile-tier scan.

    In a regex class '[]...]' the leading ']' is a literal, so text after it is
    still inside the class; mis-tracking it made the scanner read a following
    '(?x)' as an inline flag and falsely reject a valid glob.
    """
    _no_opa(monkeypatch)
    _no_google_re2(monkeypatch)
    translated = _re2.glob_to_re2(pattern)
    assert "(?>" not in translated


@pytest.mark.parametrize(
    "pattern",
    [
        "(?>abc)def",       # atomic group
        "(?=foo)bar",       # lookahead
        "a(?!b)",           # negative lookahead
        "(?<=x)y",          # lookbehind
        "(?<!x)y",          # negative lookbehind
        r"(a)\1",           # backreference
        r"(?P<n>x)(?P=n)",  # named backreference
        "a++",              # possessive quantifier
        "password.*+",      # possessive quantifier mid-pattern
        "(unclosed",        # plain-malformed
        r"a\Kb",            # PCRE \K
        r"foo\Z",           # \Z anchor (RE2 uses \z)
        "(?#comment)abc",   # inline comment (parser discards it)
        "(?x)a b",          # Python-only verbose flag
        r"\u0061bc",        # Python-only \u escape
        r"a\U00000061b",    # Python-only \U escape
        r"\N{DEGREE SIGN}",  # Python-only named escape
    ],
)
def test_validate_re2_rejects_pcre_only_without_opa_or_re2(
    pattern: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The compile tier must reject PCRE-only/malformed input, not fail open."""
    _no_opa(monkeypatch)
    _no_google_re2(monkeypatch)
    with pytest.raises(ValueError, match="Go RE2"):
        _re2.validate_re2(pattern, require_opa=False)


@pytest.mark.parametrize(
    "pattern",
    [
        r"(?s:(?:.*?secret).*)\z",  # glob_to_re2 output (uses \z)
        "(abc)+d.*",
        "[a-z]+@[a-z]+",
        "foo|bar",
        "a+?",                      # lazy quantifier (valid RE2)
        "[*+]+",                    # literal * / + in a class (not a quantifier)
        r"\bword\b",                # word boundaries
        r"\d{2,5}",
        "(?i)abc",                  # RE2-supported inline flag
        "(?P<name>x)",              # named group
        r"a\\Z",                    # escaped backslash then literal Z (valid)
        r"[\\Z]",                   # backslash / Z as class members (valid)
    ],
)
def test_validate_re2_accepts_valid_re2_without_opa_or_re2(
    pattern: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Valid RE2 must not be false-rejected by the compile tier."""
    _no_opa(monkeypatch)
    _no_google_re2(monkeypatch)
    _re2.validate_re2(pattern, require_opa=False)


def test_validate_re2_requires_opa_when_asked(monkeypatch: pytest.MonkeyPatch) -> None:
    """require_opa fails closed when no authoritative validator is present."""
    _no_opa(monkeypatch)
    _no_google_re2(monkeypatch)
    with pytest.raises(ValueError, match="authoritative RE2 validator"):
        _re2.validate_re2(r"(?s:secret)\z", require_opa=True)
