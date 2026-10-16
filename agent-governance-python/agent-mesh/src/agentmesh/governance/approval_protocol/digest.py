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
* integers serialize with no decimal point; finite floats serialize as
  ECMAScript ``Number::toString`` does (RFC 8785 section 3.2.2.3): the
  shortest round-trip digits, plain notation for decimal exponents from -6
  through 21 and ``e+N`` / ``e-N`` notation outside it, so ``1e-06`` becomes
  ``0.000001``, ``1e-07`` becomes ``1e-7`` and ``1e21`` becomes ``1e+21``;
  ``-0.0`` serializes as ``0``; ``NaN``/``Infinity`` are rejected.

Python ``int`` values serialize exactly. An integer outside the IEEE 754
double's exact range (above 2**53 in magnitude) therefore has no counterpart
in a JCS implementation that parses numbers as doubles, so callers that need
cross-SDK digests should keep integers within that range.
"""

from __future__ import annotations

import hashlib
import json
import math
from decimal import Decimal
from typing import Any

__all__ = ["canonicalize", "sha256_jcs", "DIGEST_PREFIX"]

#: Prefix carried by every digest string emitted by the protocol, e.g.
#: ``"sha256:9f86d0..."``. Records store and compare the prefixed form.
DIGEST_PREFIX = "sha256:"


def _format_number(value: int | float) -> str:
    # ``bool`` is a subclass of ``int``; callers screen it out before here.
    if isinstance(value, int):
        return str(value)
    if not math.isfinite(value):
        raise ValueError("JCS cannot serialize NaN or Infinity")
    return _format_double(value)


def _format_double(value: float) -> str:
    """Serialize a finite double as ECMAScript ``Number::toString`` does."""
    if value == 0:
        return "0"
    if value < 0:
        return "-" + _format_double(-value)
    # ``repr`` yields the shortest digit string that round-trips, which is the
    # digit string ECMAScript selects; only the layout differs.
    sign, digit_tuple, exponent = Decimal(repr(value)).as_tuple()
    digits = "".join(map(str, digit_tuple)).rstrip("0")
    exponent += len(digit_tuple) - len(digits)
    k = len(digits)
    n = exponent + k  # value == 0.<digits> * 10**n
    if k <= n <= 21:
        return digits + "0" * (n - k)
    if 0 < n <= 21:
        return digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + digits
    e = n - 1
    mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
    return f"{mantissa}e{'+' if e >= 0 else '-'}{abs(e)}"


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
