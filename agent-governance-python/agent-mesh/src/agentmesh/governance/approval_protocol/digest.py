# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""RFC 8785 JSON Canonicalization Scheme (JCS) and SHA-256 action digests.

ADR-0030 binds every approval to the *exact* action under review by hashing a
canonical serialization of the request. The same digest must be reproducible at
the execution boundary, so the serialization has to be deterministic regardless
of mapping insertion order or insignificant whitespace.

This module vendors a focused subset of RFC 8785 (no third-party dependency):

* objects emit keys sorted by UTF-16 code unit (RFC 8785 sort order);
* no insignificant whitespace (``,`` / ``:`` separators only);
* strings use minimal JSON escaping with non-ASCII kept as literal UTF-8
  (CPython's ``json.dumps(..., ensure_ascii=False)`` matches JCS string
  escaping: short escapes for ``\\b \\t \\n \\f \\r`` and lowercase ``\\uXXXX``
  for the remaining control characters);
* integers serialize with no decimal point; finite floats use CPython's
  shortest round-trip ``repr`` with integer-valued floats normalized to
  integers; ``NaN``/``Infinity`` are rejected.

Byte-for-byte parity with non-Python JCS implementations across all float
magnitudes (full ECMAScript ``Number`` formatting) is tracked as cross-SDK
parity work (ADR-0030 step 6). Within the Python governance surface the
serialization is internally consistent, which is exactly what the action-digest
binding requires: a digest computed here always reproduces here.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

__all__ = ["canonicalize", "sha256_jcs", "DIGEST_PREFIX"]

#: Prefix carried by every digest string emitted by the protocol, e.g.
#: ``"sha256:9f86d0..."``. Records store and compare the prefixed form.
DIGEST_PREFIX = "sha256:"


def _format_number(value: int | float) -> str:
    # ``bool`` is a subclass of ``int``; callers screen it out before here.
    if isinstance(value, int):
        return str(value)
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError("JCS cannot serialize NaN or Infinity")
    if value.is_integer():
        return str(int(value))
    return repr(value)


def _utf16_units(key: str) -> bytes:
    # Ordering by big-endian UTF-16 bytes is equivalent to ordering by UTF-16
    # code units, which is what RFC 8785 mandates for object member sorting.
    return key.encode("utf-16-be")


def _emit(value: Any, out: list[str]) -> None:
    if value is None:
        out.append("null")
    elif isinstance(value, bool):
        out.append("true" if value else "false")
    elif isinstance(value, (int, float)):
        out.append(_format_number(value))
    elif isinstance(value, str):
        out.append(json.dumps(value, ensure_ascii=False))
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for index, item in enumerate(value):
            if index:
                out.append(",")
            _emit(item, out)
        out.append("]")
    elif isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise TypeError(
                    f"JCS object keys must be strings, got {type(key).__name__}"
                )
        out.append("{")
        for index, key in enumerate(sorted(value, key=_utf16_units)):
            if index:
                out.append(",")
            out.append(json.dumps(key, ensure_ascii=False))
            out.append(":")
            _emit(value[key], out)
        out.append("}")
    else:
        raise TypeError(f"value of type {type(value).__name__} is not JCS-serializable")


def canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 encoding of ``value``.

    Raises ``TypeError`` for non-JSON values (so a tool parameter the protocol
    cannot canonicalize fails loudly rather than producing an unstable digest)
    and ``ValueError`` for ``NaN``/``Infinity``.
    """
    parts: list[str] = []
    _emit(value, parts)
    return "".join(parts).encode("utf-8")


def sha256_jcs(value: Any) -> str:
    """Return ``"sha256:<lowercase-hex>"`` over the JCS encoding of ``value``."""
    return DIGEST_PREFIX + hashlib.sha256(canonicalize(value)).hexdigest()
