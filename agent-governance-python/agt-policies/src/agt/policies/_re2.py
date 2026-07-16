# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Go RE2 compatibility helpers for policy-authored patterns.

Policy patterns are evaluated by OPA's Go ``regexp`` engine (RE2), which
implements a strict subset of PCRE. Two failure modes motivate this module:

* CPython's :func:`fnmatch.translate` wraps ``*``/``?`` runs in atomic groups
  ``(?>...)`` on Python >= 3.12. RE2 rejects atomic groups, so an unvalidated
  glob compiles to an invalid RE2 pattern and ``regex.match`` evaluates to
  *undefined* at policy time, silently failing open (the deny never fires).
* A v4 ``REGEX`` blocked pattern may use PCRE-only constructs (lookaround,
  backreferences, atomic groups) that RE2 does not implement.

:func:`glob_to_re2` therefore emits RE2-safe output by construction and
:func:`validate_re2` never silently succeeds: it validates with OPA when
available, else the optional ``google-re2`` binding, else a pure-Python
heuristic that rejects the PCRE-only constructs RE2 cannot compile. An invalid
pattern is thus rejected at author/migration time instead of failing open at
policy-evaluation time.
"""

from __future__ import annotations

import fnmatch
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

try:  # Python 3.11+
    from re import _constants as _sre_constants
    from re import _parser as _sre_parser
except ImportError:  # pragma: no cover — Python < 3.11
    import sre_constants as _sre_constants  # type: ignore[no-redef]
    import sre_parse as _sre_parser  # type: ignore[no-redef]

# Parse-tree opcodes for PCRE constructs Go RE2 does not implement. Detecting
# them on the parsed tree (rather than by text probing) is context-aware, so a
# literal '*'/'+' inside a character class or a backslash-digit octal escape is
# not mistaken for a possessive quantifier or a backreference.
_RE2_UNSUPPORTED_OPS: dict[Any, str] = {}
for _name, _desc in (
    ("GROUPREF", "backreferences"),
    ("GROUPREF_EXISTS", "conditional '(?(id)...)' groups"),
    ("ASSERT", "lookahead/lookbehind assertions"),
    ("ASSERT_NOT", "negative lookahead/lookbehind assertions"),
    ("ATOMIC_GROUP", "atomic groups '(?>...)'"),
    ("POSSESSIVE_REPEAT", "possessive quantifiers"),
):
    _op = getattr(_sre_constants, _name, None)
    if _op is not None:
        _RE2_UNSUPPORTED_OPS[_op] = _desc


def glob_to_re2(pattern: str, *, require_opa: bool = False) -> str:
    """Translate a Python glob to an anchored, RE2-safe regex string."""
    translated = fnmatch.translate(pattern)
    # fnmatch (CPython >= 3.12) wraps '*'/'?' runs in atomic groups '(?>...)'
    # solely to bound backtracking. RE2 rejects atomic groups, and de-atomising
    # does not change the matched language for these glob-derived expressions.
    translated = translated.replace("(?>", "(?:")
    if translated.endswith(r"\Z"):
        translated = translated[:-2] + r"\z"
    validate_re2(translated, require_opa=require_opa)
    return translated


def validate_re2(pattern: str, *, require_opa: bool = False) -> None:
    """Validate *pattern* against Go RE2 semantics, never succeeding silently.

    Preference order: OPA's authoritative Go RE2 engine, then the optional
    ``google-re2`` binding (also authoritative). When neither is available and
    ``require_opa`` is set, the pattern is rejected outright — the security
    -critical bridge and migrator use this so a pattern is never emitted without
    an authoritative RE2 check (fail closed, never fail open). When neither is
    available and ``require_opa`` is not set, a pure-Python best-effort check
    runs: it *compiles* the pattern (rejecting anything Python cannot parse) and
    walks the parse tree to reject the PCRE constructs RE2 does not implement.

    The pure-Python tier is a best-effort last resort for non-authoritative
    callers (e.g. validating :func:`glob_to_re2` output, which is RE2-safe by
    construction). It is exact for malformed input, backreferences, lookaround,
    atomic groups, possessive quantifiers, ``\\u``/``\\U``/``\\N{}`` escapes,
    the ``\\Z`` anchor, ``(?#...)`` comments, and Python-only inline flags.
    Because Python's accepted language is not identical to RE2's, it cannot be
    exhaustively sound for arbitrary hand-written regex (e.g. it accepts an
    over-large ``{0,100000}`` bound RE2 rejects, and rejects RE2-only ``\\p{...}``
    that RE2 accepts); security-critical callers must therefore pass
    ``require_opa=True`` and host OPA or the ``google-re2`` binding.
    """
    opa = _opa_path()
    if opa is not None:
        _validate_with_opa(opa, pattern)
        return
    if _validate_with_google_re2(pattern):
        return
    if require_opa:
        raise ValueError(
            "an authoritative RE2 validator (OPA on PATH or the google-re2 "
            "package) is required to validate REGEX/GLOB patterns safely"
        )
    _validate_re2_by_compiling(pattern)


def _scan_hidden_re2_incompatibilities(pattern: str) -> str | None:
    """Detect RE2-incompatible constructs Python's parser resolves away.

    The parse-tree walk cannot see these because ``re`` normalises them while
    parsing: ``\\u``/``\\U``/``\\N{}`` escapes (RE2 spells code points
    ``\\x{...}``), the ``\\Z`` anchor (RE2 uses ``\\z``), ``(?#...)`` comments,
    and Python-only inline flags (``a``/``L``/``u``/``x``; RE2 accepts only
    ``i``/``m``/``s``/``U``). The scan is escape- and character-class-aware, so
    an escaped ``\\\\Z`` literal or a ``[\\\\Z]`` class member is not flagged.
    """
    i, n = 0, len(pattern)
    in_class = False
    while i < n:
        c = pattern[i]
        if c == "\\":
            if i + 1 < n:
                nxt = pattern[i + 1]
                if nxt in "uUN":
                    return f"the Python-only escape '\\{nxt}' (RE2 uses '\\x{{...}}')"
                if nxt == "Z" and not in_class:
                    return "the '\\Z' anchor (RE2 uses '\\z')"
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
            i += 1
            continue
        if c == "[":
            in_class = True
            i += 1
            # In a regex character class a leading '^' negates, and a ']'
            # immediately after '[' or '[^' is a literal member, not the close
            # (e.g. '[]]' or '[^]]'). Consume them so the close-detection below
            # does not end the class early and mis-read later text.
            if i < n and pattern[i] == "^":
                i += 1
            if i < n and pattern[i] == "]":
                i += 1
            continue
        if c == "(" and pattern.startswith("(?", i):
            marker = pattern[i + 2 : i + 3]
            if marker == "#":
                return "inline comments '(?#...)'"
            if marker and marker not in "P:=!<>":
                flags = ""
                j = i + 2
                while j < n and pattern[j] not in ":)":
                    flags += pattern[j]
                    j += 1
                for flag in flags:
                    if flag not in "imsU-":
                        return f"the Python-only inline flag group '(?{flags})'"
        i += 1
    return None


def _validate_re2_by_compiling(pattern: str) -> None:
    """Reject patterns Python cannot parse or that use RE2-unsupported ops."""
    # Catch constructs the parse below cannot see because Python normalises them
    # away (escapes, comments, Python-only inline flags, the '\\Z' anchor).
    hidden = _scan_hidden_re2_incompatibilities(pattern)
    if hidden is not None:
        raise ValueError(f"pattern is not valid Go RE2 syntax: uses {hidden}")
    # RE2 spells end-of-text ``\z``, which Python's parser rejects as a bad
    # escape. Normalise ``\z`` -> ``\Z`` (same meaning) so Python can parse an
    # otherwise-valid RE2 pattern — including the output of :func:`glob_to_re2`.
    probe = pattern.replace(r"\z", r"\Z")
    try:
        tree = _sre_parser.parse(probe)
    except Exception as exc:  # noqa: BLE001 — any parse failure means invalid RE2
        raise ValueError(f"pattern is not valid Go RE2 syntax: {exc}") from exc

    found: list[str] = []

    def _walk(seq: Any) -> None:
        for op, arg in seq:
            description = _RE2_UNSUPPORTED_OPS.get(op)
            if description is not None:
                found.append(description)
            stack = [arg]
            while stack:
                item = stack.pop()
                if isinstance(item, _sre_parser.SubPattern):
                    _walk(item)
                elif isinstance(item, (list, tuple)):
                    stack.extend(item)

    _walk(tree)
    if found:
        raise ValueError(
            "pattern is not valid Go RE2 syntax: uses " + ", ".join(sorted(set(found)))
        )


def _validate_with_google_re2(pattern: str) -> bool:
    """Compile *pattern* with the optional ``google-re2`` binding.

    Returns ``True`` when the binding is installed and the pattern compiled,
    ``False`` when the binding is unavailable (so the caller falls back to the
    heuristic). Raises :class:`ValueError` when the binding is present and
    rejects the pattern.
    """
    try:
        import re2 as _google_re2
    except ImportError:
        return False
    try:
        _google_re2.compile(pattern)
    except Exception as exc:  # noqa: BLE001 — any compile failure means invalid RE2
        raise ValueError(f"pattern is not valid Go RE2 syntax: {exc}") from exc
    return True


def _validate_with_opa(opa: Path, pattern: str) -> None:
    """Validate one pattern with OPA's Go RE2 engine (authoritative)."""
    try:
        proc = subprocess.run(
            [
                str(opa),
                "eval",
                "--format=json",
                "--stdin-input",
                "regex.is_valid(input.pattern)",
            ],
            input=json.dumps({"pattern": pattern}),
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"OPA regex validation failed: {exc}") from exc
    if proc.returncode != 0:
        detail = proc.stderr.strip() or "OPA regex validation failed"
        raise ValueError(detail)
    try:
        payload = json.loads(proc.stdout)
        valid = payload["result"][0]["expressions"][0]["value"]
    except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
        raise ValueError("OPA returned an invalid regex validation response") from exc
    if valid is not True:
        raise ValueError("pattern is not valid Go RE2 syntax")


def _opa_path() -> Path | None:
    configured = os.environ.get("ACS_OPA_PATH")
    if configured:
        path = Path(configured).expanduser()
        if path.is_file():
            return path
        raise ValueError(f"ACS_OPA_PATH does not name a file: {path}")
    discovered = shutil.which("opa")
    return Path(discovered) if discovered else None


__all__ = ["glob_to_re2", "validate_re2"]
