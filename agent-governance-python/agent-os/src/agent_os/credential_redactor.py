# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Credential redaction and PII/CRI detection for MCP audit and response safety."""

# Fake passwords quoted in the comments below, chosen so the apostrophe falls at
# a different offset in each. Not words.
# cspell:ignore efgh cdefgh

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

REDACTED_PLACEHOLDER = "[REDACTED]"

# Name of the optional group that marks the secret itself inside a
# keyword-anchored pattern. Detection needs the keyword for context, but
# replacing the whole match would take the key and separator with it:
# ``{"api_key": "S", "keep": 1}`` became ``{"[REDACTED]", "keep": 1}``, so a
# redaction turned parseable output into a parse failure. When a pattern defines
# this group, redaction replaces only that span.
_SECRET_GROUP = "secret"

# Characters that terminate an unquoted value, as a character-class body.
#
# Only whitespace and ``;`` end a value, which is what ``main`` used and what the
# syntaxes actually guarantee. A comma or a closing brace is *not* here: an
# earlier revision of this patch added ``,}]``, and that lost whole values
# instead of trailing characters -- ``token=ab,cdefghijkl`` and ``Password=abc}``
# passed through, both redacted on ``main`` -- because a value *containing* one
# of those characters ended early and fell under the length floor. Where they are
# structural they are excluded from the last character of the value instead; see
# ``_STRUCTURAL``.
_VALUE_END = r"\s;"

# Structural characters a bare value may contain but must not *end* on, as a
# character-class body.
#
# An unquoted value in a JSON or YAML flow mapping runs up to the delimiter that
# closes it (``{"password": hunter2}``), and redacting that delimiter along with
# the value turns a redaction into a parse failure. Excluding it from the value's
# last character rather than from the class throughout is what keeps a value that
# *contains* one intact: the regex backtracks to end one character earlier, so
# only the delimiter is given up, never the value.
#
# A quote is here for the same reason: it closes the value rather than belonging
# to it, and a redaction that eats the closing quote of a JSON string is exactly
# the parse failure ``_SECRET_GROUP`` exists to avoid. Without it, a value under
# the length floor reached the floor by *borrowing* its own quotes on
# backtracking, so ``{"api_key": "abc"}`` matched as the six-character
# ``"abc"}``. Both ends need it: a quote is excluded from the first character of
# a bare value too, so the group cannot grow leftwards into one either.
#
# For a keyword that also appears in a connection string this is a *preference*
# rather than a rule -- see ``allow_structural_end``. There, ``;`` is the only
# separator, so a brace is an ordinary password character and ``Password=abc}``
# is a four-character password, not a three-character one inside a brace. Which
# syntaxes a keyword is written in is a property of the pattern, fixed by its
# author -- unlike the value-shape exemptions this patch used to have, which
# whoever wrote the value could choose.
_STRUCTURAL = r",}\]\"'"


def _separator(*, colon_floor: int | None = None) -> str:
    """Build the ``:``/``=`` separator.

    Neither spelling exempts anything by the *shape* of its value. An earlier
    revision of this patch exempted the literals ``true``/``false``/``null`` and
    bare numbers, and values that were wholly an interpolation reference
    (``${VAR}``, ``{{var}}``, ``%VAR%``), to keep benign config out of the
    output. Review showed why an egress redactor cannot afford either: the
    exemption is chosen by whoever writes the value, so a tool on the far side
    of the MCP boundary walks a secret past the gate by wrapping it
    (``password=${DB_PASS:-S3cr3tHunter22}``, ``api_key=%Actual_Secret_123%``)
    or by shaping it (``token: 738291046512``). The failure direction here has
    to be over-redaction, so both guards are gone: a ``${VAR}`` reference in
    tool output is redacted, which costs a reader some context and leaks
    nothing.

    The length floors, not a value-shape guard, are what keep ordinary settings
    out: ``false``, ``true``, ``null`` and ``none`` are all shorter than the
    6-character floor on the generic keywords, so ``{"secret": false}`` does not
    match for want of length.
    """
    # A floor that applies to the ``:`` spelling only. ``password`` needs a low
    # floor for ``Password=1234``, but ``:`` is also how Python annotates a
    # parameter, so the same floor let source text match: in
    # ``def f(username: str, password: str):`` the value ``str):`` clears four
    # characters and the line tail was redacted. A connection string is written
    # with ``=``, so raising the floor for ``:`` costs no real spelling.
    colon_floor_guard = (
        "" if colon_floor is None else rf"(?=[\"']?[^{_VALUE_END}]{{{colon_floor},}})"
    )
    return rf"(?::\s*{colon_floor_guard}|=\s*)"


def _keyword_value(
    keywords: str,
    floor: int,
    value_class: str | None = None,
    *,
    colon_floor: int | None = None,
    allow_structural_end: bool = False,
) -> str:
    """Build a ``keyword <sep> value`` pattern whose value is a capture group.

    Args:
        keywords: Alternation of anchor keywords, already grouped.
        floor: Minimum value length.
        value_class: Character class for the value. When the value has a known
            alphabet (base64, say) that already excludes quotes and delimiters,
            one group is enough. When omitted the value is matched in three
            alternatives instead, so a *quoted* secret may contain the
            delimiters an unquoted one has to stop at: a quoted value runs to
            its own closing quote, while a bare one stops at ``_VALUE_END``.
        colon_floor: Optional larger floor for the ``:`` spelling only, for a
            keyword whose ``=`` form needs a floor too low to distinguish a
            short secret from source text. See :func:`_separator`.
        allow_structural_end: Whether a bare value may end on ``,}]`` when that
            is the only way it can match at all. False keeps the delimiter out of
            the redacted span unconditionally. True adds a lower-preference
            fallback for a keyword that also appears in a syntax where those
            characters are ordinary value characters -- ``password`` is written
            both as a JSON field and in a connection string, so ``hunter2}`` has
            to give the brace back in ``{"password": hunter2}`` and keep it in
            ``Password=abc}``. See ``_STRUCTURAL``.

    Returns:
        A pattern string with the secret captured in a ``secret*`` group.
    """
    # An optional quote before the separator: in ``"api_key": "..."`` the
    # closing quote of the *key* falls between the keyword and the separator.
    sep = _separator(colon_floor=colon_floor)
    head = rf"(?i)(?<![A-Za-z0-9]){keywords}[\"']?\s*{sep}"
    if value_class is not None:
        return rf"{head}[\"']?(?P<{_SECRET_GROUP}_bare>{value_class}{{{floor},}})"
    # The quoted classes exclude a newline as well as their own delimiter. A
    # JSON or YAML string cannot contain a raw newline, so a quote that is not
    # closed on its own line is an unterminated quote rather than the start of a
    # very long value. Without ``\n`` a stray opening quote consumed the
    # following lines and redacted them as one secret.
    #
    # The bare branch keeps its optional leading quote *outside* the capture
    # group. Dropping it altogether meant an unterminated quote matched nothing
    # at all and the secret leaked in full (``api_key="SECRET`` with no closing
    # quote). The quoted branches are tried first, so a properly terminated value
    # still matches them; the bare branch only takes over when they fail.
    #
    # Structural characters are excluded from the group's first and last
    # character but not from the middle, which is what distinguishes a delimiter
    # from a value character at the same offset. Excluding them throughout meant
    # an apostrophe inside a connection-string password ended the value
    # (``Password=abcd'efgh`` leaked the ``'efgh`` tail) or dropped it under the
    # floor entirely (``Password=ab'cdefgh``). Not excluding them at the ends
    # meant the group reached the floor by *borrowing* the delimiters around it:
    # ``{"api_key": "abc"}``, three characters long and untouched here before,
    # matched as the six-character ``"abc"}`` and took the closing brace with it.
    #
    # Written as first + middle + last rather than as a lookaround, because a
    # lookaround that rejects the alternative cannot *shorten* a match -- the
    # value ended early, fell under the floor, and leaked in full. Spelled this
    # way the engine backtracks into the middle run and gives the delimiter back
    # one character at a time, so a value that merely *contains* one keeps it.
    bare = rf"[^{_VALUE_END}]"
    edge = rf"[^{_VALUE_END}{_STRUCTURAL}]"
    bare_value = rf"{edge}{bare}{{{floor - 2},}}{edge}"
    if allow_structural_end:
        # Second, and only reachable when the first cannot match anywhere in the
        # value: a connection-string password really may end on a brace, since
        # ``;`` is that syntax's only delimiter. Ordered after the first, so where
        # both could apply -- ``{"password": hunter2}`` -- the brace is still
        # given back.
        bare_value = rf"(?:{bare_value}|{edge}{bare}{{{floor - 1},}})"
    return (
        rf"{head}"
        rf"(?:\"(?P<{_SECRET_GROUP}_dq>[^\"\n]{{{floor},}})\""
        rf"|'(?P<{_SECRET_GROUP}_sq>[^'\n]{{{floor},}})'"
        rf"|[\"']?(?P<{_SECRET_GROUP}_bare>{bare_value}))"
    )


# The alternatives of _keyword_value, in match order.
_SECRET_GROUPS = (f"{_SECRET_GROUP}_dq", f"{_SECRET_GROUP}_sq", f"{_SECRET_GROUP}_bare")


def _secret_span(match: re.Match[str]) -> tuple[int, int]:
    """Return the span to redact: the secret group if the pattern defines one.

    Falls back to the whole match, which is correct for the prefix-anchored
    patterns (``ghp_...``, ``AKIA...``) where the match *is* the secret.

    The group is exactly the span to redact, with no adjustment here: the
    delimiters a bare value must not end on are excluded by the pattern itself
    (see ``_STRUCTURAL``), and quotes are outside the group. Both have to hold in
    the pattern rather than be fixed up afterwards, because the length floor
    counts what the group captured -- a span this function shortened would be one
    the floor never applied to.
    """
    groups = match.re.groupindex
    for name in _SECRET_GROUPS:
        if name in groups and match.group(name) is not None:
            return match.span(name)
    return match.span()


@dataclass(frozen=True)
class CredentialPattern:
    """A named credential detection pattern."""

    name: str
    pattern: re.Pattern[str]


@dataclass(frozen=True)
class CredentialMatch:
    """A credential-like value detected in text.

    ``start`` and ``end`` are the character offsets of the match within the
    scanned string (``-1`` when unknown). They let callers reason about
    overlapping spans (for example, suppressing a PII match that falls inside a
    credential match) without re-scanning. ``matched_text`` holds the raw value
    and must never be logged or echoed to callers.
    """

    name: str
    matched_text: str
    start: int = -1
    end: int = -1


class CredentialRedactor:
    """Detect and redact credential-like material in strings and nested objects.

    Use this helper before persisting audit payloads or returning tool output to
    callers. The class operates on plain strings as well as nested dictionaries,
    lists, and tuples, replacing detected secret values with a stable
    placeholder.
    """

    # Python's stdlib ``re`` does not support per-pattern timeouts. These
    # patterns are kept simple and anchored to avoid pathological backtracking.
    #
    # Prefix-anchored patterns use a ``(?<![A-Za-z0-9])`` lookbehind rather than
    # ``\b`` so a secret glued directly to a preceding word character (for
    # example ``session_sk-...``) is still detected. ``\b`` treats ``_`` as a
    # word character, so ``_sk-`` has no boundary and the secret would be missed;
    # ``(?<![A-Za-z0-9])`` treats ``_`` (and ``-``, ``/``, ``.``, whitespace) as a
    # valid left edge while still not matching inside an alphanumeric word.
    PATTERNS: tuple[CredentialPattern, ...] = (
        CredentialPattern(
            name="OpenAI API key",
            pattern=re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9][A-Za-z0-9_-]{18,}\b"),
        ),
        CredentialPattern(
            name="GitHub token",
            pattern=re.compile(
                r"(?<![A-Za-z0-9])(?:gh[psour]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{22,})(?![A-Za-z0-9_])"
            ),
        ),
        CredentialPattern(
            name="AWS access key",
            pattern=re.compile(r"(?<![A-Za-z0-9])AKIA[A-Z0-9]{16}\b"),
        ),
        CredentialPattern(
            # The 40-char base64 secret value has no distinctive prefix, so it is
            # anchored to the assignment keyword to avoid matching arbitrary
            # base64 blobs. The generic "secret" pattern misses it because
            # "secret" inside "aws_secret_access_key" has no word boundary.
            name="AWS secret access key",
            pattern=re.compile(
                _keyword_value(
                    r"aws[_ -]?secret[_ -]?access[_ -]?key", 40, r"[A-Za-z0-9/+=]"
                )
            ),
        ),
        CredentialPattern(
            name="Azure key",
            pattern=re.compile(
                _keyword_value(
                    r"(?:accountkey|sharedaccesskey|azure[_-]?key)", 20, r"[A-Za-z0-9+/=]"
                )
            ),
        ),
        CredentialPattern(
            # Azure Storage SAS token. The "sig" query parameter carries the
            # secret HMAC signature (base64(HMAC-SHA256) = 44 chars, longer when
            # URL-encoded). Matching the sig value directly is order-independent
            # (SAS params are not ordered) and single-pass. The 43-char floor is
            # far above an incidental short "sig=" query value, so it stands in
            # for a context anchor without the false positives.
            name="Azure SAS token",
            pattern=re.compile(r"(?i)(?<![A-Za-z0-9])sig=[A-Za-z0-9%/+=_.~-]{43,}"),
        ),
        CredentialPattern(
            name="Bearer token",
            pattern=re.compile(r"(?<![A-Za-z0-9])Bearer\s+[A-Za-z0-9._\-+/=]{16,}\b"),
        ),
        CredentialPattern(
            name="PEM private key",
            pattern=re.compile(
                r"-----BEGIN (?P<label>(?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY)-----"
                r"(?:\r?\n[!-~ \t]*)*?"
                r"\r?\n-----END (?P=label)-----"
            ),
        ),
        CredentialPattern(
            # Also accepts ``:`` and quotes so the JSON and YAML spellings of a
            # password field are covered, not just the ``key=value`` of a
            # connection string.
            name="Connection string secret",
            pattern=re.compile(
                _keyword_value(
                    r"(?:password|passphrase|pwd|accountkey|sharedaccesssignature)",
                    4,
                    # ``:`` is also Python's annotation separator, and floor 4
                    # matched ``password: str):`` in a function signature.
                    colon_floor=8,
                    # These keywords are written in connection strings too, where
                    # ``}`` and ``,`` are ordinary password characters.
                    allow_structural_end=True,
                )
            ),
        ),
        CredentialPattern(
            name="Basic auth secret",
            pattern=re.compile(
                r"(?i)(?:\bBasic\s+[A-Za-z0-9+/=]{8,}\b|\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^@\s/]+@)"
            ),
        ),
        CredentialPattern(
            name="JWT",
            pattern=re.compile(r"(?<![A-Za-z0-9])eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9._-]{6,}\.[A-Za-z0-9._-]{6,}\b"),
        ),
        CredentialPattern(
            # Covers bot/user/legacy tokens (xoxb/xoxa/xoxp/xoxr/xoxs) and
            # app-level tokens (xapp-). No trailing \b: the "-" in the value
            # class lets a word boundary backtrack and redact only a prefix,
            # leaking the token's final secret segment. The value class already
            # bounds the match, so greedy consumption stops at the first
            # non-token character.
            name="Slack token",
            pattern=re.compile(r"(?<![A-Za-z0-9])(?:xox[baprs]|xapp)-[A-Za-z0-9-]{10,}"),
        ),
        CredentialPattern(
            name="Google API key",
            pattern=re.compile(r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_\-]{35}\b"),
        ),
        CredentialPattern(
            name="Stripe secret key",
            pattern=re.compile(r"(?<![A-Za-z0-9])(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b"),
        ),
        CredentialPattern(
            # The optional quote sits before the separator, not after the
            # keyword's word boundary: in ``"api_key": "..."`` the quote falls
            # between the keyword and the separator, and a pattern that goes
            # straight from the keyword to ``\s*[:=]`` never matches the JSON
            # spelling — the shape most MCP tool output arrives in.
            name="Generic API secret",
            pattern=re.compile(
                _keyword_value(
                    r"(?:api[_-]?key|client[_-]?secret|secret|token)", 6
                )
            ),
        ),
    )

    # PII / CRI patterns — detection-only (not used for redaction by default).
    # These catch personally identifiable information that should not flow
    # into LLM context in enterprise governance scenarios.
    PII_PATTERNS: tuple[CredentialPattern, ...] = (
        CredentialPattern(
            name="Email address",
            pattern=re.compile(
                r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
            ),
        ),
        CredentialPattern(
            name="US phone number",
            pattern=re.compile(
                r"(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)"
            ),
        ),
        CredentialPattern(
            name="US SSN",
            # Accept the space and dot separated forms the dash-only pattern
            # missed (issue #3239). A separator is required: this module feeds
            # the MCP gateway, where pii_leak is a hard-block category, so a
            # bare nine-digit match would deny any request carrying a tracking
            # number, ZIP+4, or ABA routing number. policy/lib/patterns.rego
            # keeps the looser form for detection-only reporting.
            # Use the lookaround idiom documented above rather than ``\b`` so an
            # SSN adjacent to ``_`` (``employee_123-45-6789``) is still detected.
            pattern=re.compile(
                r"(?<![A-Za-z0-9])\d{3}[\s.-]\d{2}[\s.-]\d{4}(?![A-Za-z0-9])"
            ),
        ),
        CredentialPattern(
            name="Credit card number",
            pattern=re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"),
        ),
        CredentialPattern(
            name="IPv4 address",
            pattern=re.compile(
                r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
            ),
        ),
    )

    @classmethod
    def find_pii_matches(cls, value: str | None) -> list[CredentialMatch]:
        """Return all PII/CRI-like matches found in a string.

        Unlike :meth:`find_matches`, these patterns detect personally
        identifiable information (email, phone, SSN, credit card, IP address)
        rather than secrets. Use for detection and policy enforcement, not
        for audit redaction.

        Args:
            value: String content to inspect.

        Returns:
            A list of ``CredentialMatch`` records for each detected PII span.
        """
        if not value:
            return []

        matches: list[CredentialMatch] = []
        for pii_pattern in cls.PII_PATTERNS:
            for match in pii_pattern.pattern.finditer(value):
                matches.append(
                    CredentialMatch(
                        name=pii_pattern.name,
                        matched_text=match.group(0),
                        start=match.start(),
                        end=match.end(),
                    )
                )
        return matches

    @classmethod
    def contains_pii(cls, value: str | None) -> bool:
        """Return whether a string contains any PII/CRI pattern.

        Args:
            value: String content to inspect.

        Returns:
            ``True`` when at least one PII pattern matches.
        """
        return bool(cls.find_pii_matches(value))

    @classmethod
    def redact(cls, value: str | None) -> str:
        """Redact credential-like values from a string.

        Redaction is driven by the exact spans that :meth:`find_matches`
        reports, so redaction removes precisely what detection finds. This is
        deliberately not a sequential ``subn`` over the patterns: applying
        patterns to a progressively mutated string lets an earlier greedy
        pattern consume the anchor keyword of a later one, which would remove
        less than detection reported and leave a secret in place.

        Args:
            value: String content that may contain credential-like material.

        Returns:
            A string with each detected credential replaced by
            ``REDACTED_PLACEHOLDER``. Empty input returns an empty string.
        """
        if not value:
            return ""

        spans = sorted(
            (match.start, match.end)
            for match in cls.find_matches(value)
            if match.start >= 0 and match.end > match.start
        )
        if not spans:
            return value

        merged: list[list[int]] = []
        for start, end in spans:
            if merged and start < merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])

        pieces: list[str] = []
        cursor = 0
        for start, end in merged:
            pieces.append(value[cursor:start])
            pieces.append(REDACTED_PLACEHOLDER)
            cursor = end
        pieces.append(value[cursor:])

        logger.info("Credential redaction applied to %s span(s)", len(merged))
        return "".join(pieces)

    @classmethod
    def scan_and_redact(cls, value: str | None) -> tuple[str, list[str]]:
        """Detect and redact credentials in a single, consistent operation.

        This is the one call a host should use to clean text before returning it
        to a model: it both removes credential-like material and reports which
        credential *types* were present. Redaction is driven by the same
        :meth:`find_matches` spans used for detection, so a type reported here is
        always removed from ``redacted_text``.

        Args:
            value: String content that may contain credential-like material.

        Returns:
            A tuple of ``(redacted_text, credential_type_names)``. The names are
            de-duplicated pattern labels (for example ``"Slack token"``) and
            contain no raw secret material, so the result is safe to log. Empty
            input returns ``("", [])``.
        """
        if not value:
            return "", []
        type_names = cls.detect_credential_types(value)
        return cls.redact(value), type_names

    @classmethod
    def redact_mapping(cls, mapping: dict[str, Any] | None) -> dict[str, Any]:
        """Redact all nested values in a mapping.

        Args:
            mapping: A possibly nested mapping containing strings, lists,
                tuples, or dictionaries.

        Returns:
            A new mapping with nested strings redacted recursively. Empty input
            returns an empty dictionary.
        """
        if not mapping:
            return {}
        return {key: cls.redact_data_structure(value) for key, value in mapping.items()}

    @classmethod
    def redact_dictionary(cls, mapping: dict[str, Any] | None) -> dict[str, Any]:
        """Compatibility alias for dictionary redaction.

        Args:
            mapping: Dictionary-like content to redact.

        Returns:
            The redacted mapping produced by :meth:`redact_mapping`.
        """
        return cls.redact_mapping(mapping)

    @classmethod
    def redact_data_structure(cls, value: Any) -> Any:
        """Recursively redact nested strings in dicts, lists, and tuples.

        Args:
            value: Any Python value that may contain nested strings.

        Returns:
            A value of the same general shape with strings redacted in place of
            their original secret-bearing content.
        """
        if isinstance(value, str):
            return cls.redact(value)
        if isinstance(value, dict):
            return {key: cls.redact_data_structure(item) for key, item in value.items()}
        if isinstance(value, list):
            return [cls.redact_data_structure(item) for item in value]
        if isinstance(value, tuple):
            return tuple(cls.redact_data_structure(item) for item in value)
        return value

    @classmethod
    def contains_credentials(cls, value: str | None) -> bool:
        """Return whether a string contains any known credential pattern.

        Args:
            value: String content to inspect.

        Returns:
            ``True`` when at least one credential pattern matches, otherwise
            ``False``.
        """
        return bool(cls.find_matches(value))

    @classmethod
    def detect_credential_types(cls, value: str | None) -> list[str]:
        """Return the names of detected credential patterns.

        Args:
            value: String content to inspect.

        Returns:
            A de-duplicated list of credential type labels in detection order.
        """
        return list(dict.fromkeys(match.name for match in cls.find_matches(value)))

    @classmethod
    def find_matches(cls, value: str | None) -> list[CredentialMatch]:
        """Return all credential-like matches found in a string.

        Args:
            value: String content to inspect.

        Returns:
            A list of ``CredentialMatch`` records describing each detected
            credential-like span. Empty input returns an empty list.
        """
        if not value:
            return []

        matches: list[CredentialMatch] = []
        for credential_pattern in cls.PATTERNS:
            for match in credential_pattern.pattern.finditer(value):
                # For a keyword-anchored pattern the reported span is the secret
                # alone, not the ``key: value`` pair that located it. The keyword
                # is context for detection; only the value is sensitive, and
                # redaction replaces exactly the span reported here.
                start, end = _secret_span(match)
                matches.append(
                    CredentialMatch(
                        name=credential_pattern.name,
                        matched_text=value[start:end],
                        start=start,
                        end=end,
                    )
                )
        return matches
