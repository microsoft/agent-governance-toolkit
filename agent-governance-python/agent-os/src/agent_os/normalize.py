# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Content normalization (canonicalization) for prompt-injection defense.

Python port of ``agentmesh::normalize`` (see
``agent-governance-rust/agentmesh/src/normalize.rs``) — the two implementations
apply the same transforms, in the same order, under the same false-positive
guards, so canonicalization decisions agree across SDKs.

This module strengthens and **surfaces** de-obfuscation as a shared
pre-detection control: it produces a canonical view of untrusted text **and a
record of which transforms fired**, so every text-based control — the regex
detector, classifier/LLM annotators, policy/IFC decisions, and human review —
can consume the same un-disguised content.

Design goals:

* **Deterministic & idempotent**: ``normalize(normalize(x).text).text ==
  normalize(x).text``.

  One exception, always announced: when nesting is deeper than
  ``max_decode_depth`` the result is tagged
  :attr:`Transform.DECODE_DEPTH_CAPPED`, and re-normalizing that output peels
  the next layers. Idempotency holds for every result *not* carrying that tag,
  so a caller that needs the invariant should treat the tag as "not yet
  canonical" rather than re-normalizing blindly. The cap exists to bound work on
  adversarial input; the tag is what makes the incompleteness visible to policy
  instead of silent. This is a property of the depth cap itself and applies on
  any input that reaches it.
* **Benign-safe**: every aggressive transform fires only under a guard, so
  legitimate inputs (percentages, ``&amp;``, real base64, code, structured
  data) pass through unchanged. Decoders additionally require a printable-
  ratio / English-benefit acceptance test.
* **Stdlib-only** — no new dependencies.

The transform vocabulary is a closed enum (:class:`Transform`) so the audit /
telemetry surface stays a fixed, reviewable set rather than free-form strings.
"""

from __future__ import annotations

import base64 as _b64
import enum
from dataclasses import dataclass
from typing import Optional


class Transform(str, enum.Enum):
    """A transform that a normalization pass may apply. Surfaced to callers so
    they can see (and audit) what was un-disguised."""

    #: Fullwidth / ideographic-space fold to ASCII.
    WIDTH_FOLD = "width_fold"
    #: Stripped zero-width, soft-hyphen, control, AND bidi override/isolate
    #: characters (the "Trojan Source" class).
    STRIP_INVISIBLE = "strip_invisible"
    #: Lowercased.
    LOWERCASE = "lowercase"
    #: Collapsed runs of whitespace to single spaces.
    WHITESPACE_COLLAPSE = "whitespace_collapse"
    #: Folded unambiguous homoglyphs (Cyrillic/Greek look-alikes) to Latin.
    CONFUSABLES = "confusables"
    #: De-substituted leetspeak (``1gn0r3`` -> ``ignore``) under a token guard.
    LEET = "leet"
    #: Collapsed letter-spacing (``i g n o r e`` -> ``ignore``).
    SPACING_COLLAPSE = "spacing_collapse"
    #: Decoded rot13.
    ROT13 = "rot13"
    #: Decoded base64.
    BASE64 = "base64"
    #: Decoded hex.
    HEX = "hex"
    #: Decoded percent / URL-encoding.
    PERCENT = "percent"
    #: Decoded ``\\uXXXX`` / ``\\xNN`` escapes.
    UNICODE_ESCAPE = "unicode_escape"
    #: Decoded HTML entities (``&#NN;``, ``&#xNN;``, named).
    HTML_ENTITY = "html_entity"
    #: A decode was attempted but failed the acceptance guard (kept original).
    DECODE_REJECTED = "decode_rejected"
    #: Nesting hit the configured decode-depth cap.
    DECODE_DEPTH_CAPPED = "decode_depth_capped"
    #: Output hit the configured expansion cap and was truncated.
    OUTPUT_CAPPED = "output_capped"


@dataclass(frozen=True)
class Normalized:
    """Result of a normalization pass."""

    #: The canonical text.
    text: str
    #: Which transforms fired (closed vocabulary, de-duplicated).
    transforms: frozenset[Transform]


@dataclass
class NormalizeConfig:
    """Configuration. Defaults are the values measured false-positive-safe on
    the research corpus (see the upstream RFC)."""

    #: Maximum nested decode layers (e.g. ``base64(percent(x))`` = 2).
    max_decode_depth: int = 2
    #: Reject/truncate output that expands beyond this multiple of the input.
    max_output_ratio: int = 4
    #: A decode is accepted only if its result is at least this fraction
    #: printable. The single most important benign-safety guard.
    printable_min_ratio: float = 0.90
    #: Run the decode layers (independent of the char-level transforms).
    enable_decoders: bool = True


def normalize(text: str, config: Optional[NormalizeConfig] = None) -> Normalized:
    """Normalize untrusted text; ``config`` defaults to :class:`NormalizeConfig`.

    Mirrors ``agentmesh::normalize::normalize_with`` — same transform order,
    same guards, same tags.
    """
    cfg = config or NormalizeConfig()
    tags: set[Transform] = set()
    # output bound is in UTF-8 bytes, matching the Rust implementation
    max_len = max(len(text.encode("utf-8")) * cfg.max_output_ratio, 64)

    # 1. strip invisible / bidi / control characters
    s, stripped = _strip_invisible(text)
    if stripped:
        tags.add(Transform.STRIP_INVISIBLE)

    # 2. width fold (fullwidth -> ASCII)
    folded = "".join(_fold_width_char(ch) for ch in s)
    if folded != s:
        tags.add(Transform.WIDTH_FOLD)
    s = folded

    # 3. decode layers FIRST (each guarded) — peel encodings before the
    #    character-level de-obfuscators, which assume already-decoded text
    #    (otherwise leet/spacing would mangle an encoded blob, e.g. the `7` in
    #    `%67`).
    if cfg.enable_decoders:
        s = _decode_layers(s, cfg, tags)

    # 4. confusable / homoglyph fold
    s, changed = _fold_confusables(s)
    if changed:
        tags.add(Transform.CONFUSABLES)

    # 5. letter-spacing collapse
    s, changed = _collapse_spacing(s)
    if changed:
        tags.add(Transform.SPACING_COLLAPSE)

    # 6. leetspeak de-substitution (token-guarded)
    s, changed = _desubstitute_leet(s)
    if changed:
        tags.add(Transform.LEET)

    # 7. lowercase + whitespace canonicalization
    lowered = s.lower()
    if lowered != s:
        tags.add(Transform.LOWERCASE)
    s = lowered
    s, changed = _collapse_whitespace(s)
    if changed:
        tags.add(Transform.WHITESPACE_COLLAPSE)

    # 8. enforce output bound
    if len(s.encode("utf-8")) > max_len:
        s = _truncate_utf8(s, max_len)
        tags.add(Transform.OUTPUT_CAPPED)

    return Normalized(text=s, transforms=frozenset(tags))


# -----------------------------------------------------------------------------
# char-level transforms
# -----------------------------------------------------------------------------


def _strip_invisible(text: str) -> tuple[str, bool]:
    """Strip zero-width, soft-hyphen, non-whitespace control, AND the
    bidirectional override/embedding/isolate ranges (Trojan Source)."""
    out = []
    changed = False
    for ch in text:
        if _is_invisible(ch):
            changed = True
            continue
        out.append(ch)
    return "".join(out), changed


def _is_invisible(ch: str) -> bool:
    cp = ord(ch)
    if (
        0x200B <= cp <= 0x200F  # zero-width space/joiners, LRM, RLM
        or 0x202A <= cp <= 0x202E  # bidi embedding/override: LRE RLE PDF LRO RLO
        or 0x2060 <= cp <= 0x206F  # word-joiner, invisible operators, bidi isolates
        or cp == 0x00AD  # soft hyphen
        or cp == 0x180E  # mongolian vowel separator
        or cp == 0xFEFF  # BOM / zero-width no-break space
    ):
        return True
    return _is_control(ch) and not ch.isspace()


def _is_control(ch: str) -> bool:
    cp = ord(ch)
    return cp < 0x20 or 0x7F <= cp <= 0x9F


def _fold_width_char(ch: str) -> str:
    cp = ord(ch)
    if cp == 0x3000:
        return " "
    if 0xFF01 <= cp <= 0xFF5E:
        return chr(cp - 0xFEE0)
    return ch


#: Unambiguous Cyrillic/Greek homoglyphs -> Latin (same closed set as Rust).
_CONFUSABLES = {
    # Cyrillic -> Latin
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "Х": "X",
    "І": "I", "і": "i", "Ј": "J", "ј": "j", "һ": "h", "ԁ": "d",
    # Greek -> Latin
    "ο": "o", "α": "a", "ε": "e", "ρ": "p", "υ": "u",
    "Ο": "O", "Α": "A", "Ε": "E", "Β": "B", "Μ": "M",
    "κ": "k", "ι": "i", "ν": "v", "τ": "t",
}


def _fold_confusables(s: str) -> tuple[str, bool]:
    out = []
    changed = False
    for ch in s:
        latin = _CONFUSABLES.get(ch)
        if latin is not None:
            changed = True
            out.append(latin)
        else:
            out.append(ch)
    return "".join(out), changed


def _collapse_spacing(s: str) -> tuple[str, bool]:
    """Collapse runs of >= 4 single-character alphanumeric tokens
    (letter-spacing), per line, conservatively (rare in benign prose)."""
    changed = False
    out_lines = []
    for line in s.split("\n"):
        tokens = line.split(" ")
        out: list[str] = []
        i = 0
        while i < len(tokens):
            j = i
            while j < len(tokens) and _is_single_alnum(tokens[j]):
                j += 1
            if j - i >= 4:
                out.append("".join(tokens[i:j]))
                changed = True
                i = j
            else:
                out.append(tokens[i])
                i += 1
        out_lines.append(" ".join(out))
    return "\n".join(out_lines), changed


def _is_single_alnum(tok: str) -> bool:
    return len(tok) == 1 and tok.isalnum()


def _desubstitute_leet(s: str) -> tuple[str, bool]:
    """De-substitute leetspeak inside a token, under a strict guard that keeps
    numbers, hashes, and codes intact: the token must have >= 2 alphabetic chars
    and >= 1 leet char, AND the de-leeted result must be ENTIRELY alphabetic
    with length >= 3. A token like ``a1b2c3`` (non-leet digits remain) or
    ``2024`` is left untouched. This guard is what preserves the measured zero
    false-positives."""
    changed = False
    out = []
    for tok in s.split(" "):
        sub = _deleet_token(tok)
        if sub is not None:
            changed = True
            out.append(sub)
        else:
            out.append(tok)
    return " ".join(out), changed


_LEET = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}


def _deleet_token(tok: str) -> Optional[str]:
    if not any(c in _LEET for c in tok):
        return None
    if sum(1 for c in tok if c.isalpha()) < 2:
        return None
    sub = "".join(_LEET.get(c, c) for c in tok)
    if len(sub) >= 3 and sub.isalpha():
        return sub
    return None


def _collapse_whitespace(s: str) -> tuple[str, bool]:
    out = " ".join(s.split())
    return out, out != s


# -----------------------------------------------------------------------------
# decode layers
# -----------------------------------------------------------------------------


def _decode_layers(s: str, cfg: NormalizeConfig, tags: set[Transform]) -> str:
    for depth in range(cfg.max_decode_depth):
        decoded = _try_decode_once(s, cfg)
        if decoded is None:
            # record a rejection only if a decodable-looking blob was present
            if depth == 0 and _looks_encoded(s):
                tags.add(Transform.DECODE_REJECTED)
            return s
        s, tag = decoded
        tags.add(tag)
    if _try_decode_once(s, cfg) is not None:
        tags.add(Transform.DECODE_DEPTH_CAPPED)
    return s


def _try_decode_once(s: str, cfg: NormalizeConfig) -> Optional[tuple[str, Transform]]:
    """Attempt exactly one decode layer. Returns the decoded text + which
    scheme, or ``None`` if nothing decoded under the acceptance guard."""
    trimmed = s.strip()

    # rot13: alphabetic-heavy prose; length-preserving, so require an English benefit.
    alpha = sum(1 for c in trimmed if c.isalpha())
    if alpha >= 16 and alpha / max(len(trimmed), 1) > 0.6:
        dec = _rot13(trimmed)
        if _english_score(dec) > _english_score(trimmed) + 1:
            return dec, Transform.ROT13

    # percent / URL-encoding: require >= 4 %XX groups, then printable + benefit.
    if _count_percent(trimmed) >= 4:
        dec = _percent_decode(trimmed)
        if (
            dec is not None
            and _printable_ratio(dec) >= cfg.printable_min_ratio
            and _has_decode_benefit(trimmed, dec)
        ):
            return dec, Transform.PERCENT

    # \uXXXX / \xNN escapes: require >= 2 groups, printable + benefit.
    if _count_unicode_escapes(trimmed) >= 2:
        dec = _unicode_unescape(trimmed)
        if (
            dec != trimmed
            and _printable_ratio(dec) >= cfg.printable_min_ratio
            and _has_decode_benefit(trimmed, dec)
        ):
            return dec, Transform.UNICODE_ESCAPE

    # HTML entities: require >= 2 entities, printable + benefit.
    if _count_html_entities(trimmed) >= 2:
        dec = _html_unescape(trimmed)
        if (
            dec != trimmed
            and _printable_ratio(dec) >= cfg.printable_min_ratio
            and _has_decode_benefit(trimmed, dec)
        ):
            return dec, Transform.HTML_ENTITY

    # base64 / hex: only on a CONTIGUOUS blob (no whitespace) so ordinary prose
    # is never treated as a payload. Acceptance = printable ratio only, so nested
    # encodings unwrap.
    if trimmed and not any(c.isspace() for c in trimmed) and len(trimmed) >= 16:
        if _is_base64(trimmed) and len(trimmed) % 4 == 0:
            try:
                dec = _b64.b64decode(trimmed, validate=True).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                dec = None
            if dec is not None and _printable_ratio(dec) >= cfg.printable_min_ratio:
                return dec, Transform.BASE64
        hexs = trimmed
        if hexs.startswith(("0x", "0X")):
            hexs = hexs[2:]
        if _is_hex(hexs) and len(hexs) % 2 == 0:
            try:
                dec = bytes.fromhex(hexs).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                dec = None
            if dec is not None and _printable_ratio(dec) >= cfg.printable_min_ratio:
                return dec, Transform.HEX

    return None


def _has_decode_benefit(before: str, after: str) -> bool:
    """Return True if decoding ``before`` into ``after`` made progress.

    The percent, escape and entity layers are ambiguous: their markers occur in
    benign text (``50% off``, ``&amp;``, a Windows path), so a decode has to
    justify itself. An English-marker gain is the justification when the payload
    is plain prose.

    It is not the only one. When the inner text is *itself* an encoded blob, both
    sides score zero English markers and a gain can never be shown -- so
    ``percent(base64(payload))`` was left verbatim while the reverse nesting,
    ``base64(percent(payload))``, unwrapped fully. The base64/hex layer below
    already accepts on the printable ratio alone precisely "so nested encodings
    unwrap"; an outer layer that reveals a blob that layer would take is the same
    kind of progress, and gets the same treatment.

    This cannot loosen the guard into benign text: revealing a decodable blob is
    strictly narrower than revealing arbitrary printable text -- a contiguous,
    non-whitespace, >= 16 char run of base64 or hex alphabet whose length the
    base64/hex layer will actually accept.

    Note what this does *not* promise. The revealed blob is one the base64/hex
    layer will *attempt*; that layer still applies its own printable-ratio test
    and may reject the result, in which case this outer decode has already been
    accepted and the text stays decoded one layer. That is the intended
    trade-off -- an ambiguous layer wrapping a decodable blob is evidence of
    obfuscation whether or not the inner payload turns out to be printable --
    but it is a weaker guarantee than "the blob then decodes cleanly".
    """
    if _english_score(after) > _english_score(before):
        return True
    # No English gain: accept only if the decode exposed something the base64/hex
    # layer will unwrap on the next pass. Without this, a decode whose output is
    # another encoding can never show a benefit and the nesting survives.
    return _decode_attemptable(after) and not _decode_attemptable(before)


def _decode_attemptable(s: str) -> bool:
    """Return True if the base64/hex layer of :func:`_try_decode_once` would try ``s``.

    Deliberately stricter than :func:`_looks_encoded`, which omits the length
    congruences and so calls a 19-char base64-alphabet run "encoded" even though
    the base64 layer requires ``len % 4 == 0`` and the hex layer ``len % 2 == 0``
    and neither would touch it. :func:`_has_decode_benefit` needs the real
    criteria: accepting an ambiguous outer decode because it revealed a blob is
    only justified if that blob is one the next pass can act on.

    :func:`_looks_encoded` keeps its looser definition, which is right for the
    ``DECODE_REJECTED`` tag -- there the question is whether the input *looked*
    like a payload worth reporting, not whether a decoder would run.
    """
    t = s.strip()
    if not t or any(c.isspace() for c in t) or len(t) < 16:
        return False
    if _is_base64(t) and len(t) % 4 == 0:
        return True
    hexs = t[2:] if t.startswith(("0x", "0X")) else t
    return _is_hex(hexs) and len(hexs) % 2 == 0


def _looks_encoded(s: str) -> bool:
    t = s.strip()
    return (
        bool(t)
        and not any(c.isspace() for c in t)
        and len(t) >= 16
        and (_is_base64(t) or _is_hex(t))
    )


# -----------------------------------------------------------------------------
# decode primitives (stdlib only)
# -----------------------------------------------------------------------------


def _rot13(s: str) -> str:
    out = []
    for c in s:
        if "a" <= c <= "z":
            out.append(chr((ord(c) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= c <= "Z":
            out.append(chr((ord(c) - ord("A") + 13) % 26 + ord("A")))
        else:
            out.append(c)
    return "".join(out)


_HEX_DIGITS = set("0123456789abcdefABCDEF")


def _is_hex_digit_byte(b: int) -> bool:
    return chr(b) in _HEX_DIGITS


def _count_percent(s: str) -> int:
    b = s.encode("utf-8")
    n = 0
    i = 0
    while i + 2 < len(b):
        if b[i] == ord("%") and _is_hex_digit_byte(b[i + 1]) and _is_hex_digit_byte(b[i + 2]):
            n += 1
            i += 3
        else:
            i += 1
    return n


def _percent_decode(s: str) -> Optional[str]:
    b = s.encode("utf-8")
    out = bytearray()
    i = 0
    while i < len(b):
        if b[i] == ord("%") and i + 2 < len(b) and _is_hex_digit_byte(b[i + 1]) and _is_hex_digit_byte(b[i + 2]):
            out.append(int(chr(b[i + 1]) + chr(b[i + 2]), 16))
            i += 3
            continue
        out.append(b[i])
        i += 1
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _count_unicode_escapes(s: str) -> int:
    n = 0
    i = 0
    while i + 1 < len(s):
        if s[i] == "\\" and s[i + 1] in ("u", "x"):
            n += 1
            i += 2
        else:
            i += 1
    return n


def _unicode_unescape(s: str) -> str:
    out = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            kind = s[i + 1]
            if kind == "u" and i + 5 < len(s):
                digits = s[i + 2 : i + 6]
                if all(c in _HEX_DIGITS for c in digits):
                    cp = int(digits, 16)
                    if not 0xD800 <= cp <= 0xDFFF:
                        out.append(chr(cp))
                        i += 6
                        continue
            elif kind == "x" and i + 3 < len(s):
                digits = s[i + 2 : i + 4]
                if all(c in _HEX_DIGITS for c in digits):
                    out.append(chr(int(digits, 16)))
                    i += 4
                    continue
        out.append(s[i])
        i += 1
    return "".join(out)


def _count_html_entities(s: str) -> int:
    n = 0
    i = 0
    while i < len(s):
        if s[i] == "&":
            rel = s.find(";", i) - i
            if 1 <= rel <= 10:
                n += 1
                i += rel + 1
                continue
        i += 1
    return n


def _html_unescape(s: str) -> str:
    out = []
    i = 0
    while i < len(s):
        if s[i] == "&":
            end = s.find(";", i)
            if end != -1:
                ch = _decode_entity(s[i + 1 : end])
                if ch is not None:
                    out.append(ch)
                    i = end + 1
                    continue
        out.append(s[i])
        i += 1
    return "".join(out)


_NAMED_ENTITIES = {
    "amp": "&", "lt": "<", "gt": ">", "quot": '"',
    "apos": "'", "nbsp": " ", "sol": "/", "colon": ":",
}


def _decode_entity(ent: str) -> Optional[str]:
    if ent.startswith("#"):
        num = ent[1:]
        if num[:1] in ("x", "X"):
            digits = num[1:]
            if not digits or any(c not in _HEX_DIGITS for c in digits):
                return None
            cp = int(digits, 16)
        else:
            if not num.isdigit():
                return None
            cp = int(num)
        # reject surrogates and out-of-range, matching Rust's char::from_u32
        if cp > 0x10FFFF or 0xD800 <= cp <= 0xDFFF:
            return None
        return chr(cp)
    return _NAMED_ENTITIES.get(ent)


_B64_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")


def _is_base64(s: str) -> bool:
    return all(c in _B64_ALPHABET for c in s) and any(c.isalpha() for c in s)


def _is_hex(s: str) -> bool:
    return bool(s) and all(c in "0123456789abcdefABCDEF" for c in s)


# -----------------------------------------------------------------------------
# acceptance-guard helpers
# -----------------------------------------------------------------------------


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    printable = sum(1 for c in s if not _is_control(c) or c.isspace())
    return printable / len(s)


#: A generic "is this more English-like" signal. NOT derived from attack labels:
#: ordinary high-frequency words plus a few imperative stems. Used only to gate
#: length-preserving / ambiguous decodes so benign text is not mangled.
_ENGLISH_MARKERS = (
    " the ", " and ", " you ", " to ", " of ", " all ", " is ", " are ",
    "ignore", "instruction", "system", "previous", "password", "secret",
    "please", "send", "delete", "execute", "reveal",
)


def _english_score(s: str) -> int:
    lower = s.lower()
    return sum(lower.count(m) for m in _ENGLISH_MARKERS)


def _truncate_utf8(s: str, max_bytes: int) -> str:
    b = s.encode("utf-8")
    if len(b) <= max_bytes:
        return s
    cut = b[:max_bytes]
    while cut:
        try:
            return cut.decode("utf-8")
        except UnicodeDecodeError:
            cut = cut[:-1]
    return ""
