# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Credential redaction and PII/CRI detection for MCP audit and response safety."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

REDACTED_PLACEHOLDER = "[REDACTED]"


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
                r"(?i)aws[_ -]?secret[_ -]?access[_ -]?key"
                r"[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{40,}"
            ),
        ),
        CredentialPattern(
            name="Azure key",
            pattern=re.compile(
                r"(?i)(?:accountkey|sharedaccesskey|azure[_-]?key)\s*[:=]\s*[A-Za-z0-9+/=]{20,}"
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
            name="Connection string secret",
            pattern=re.compile(
                r"(?i)(?<![A-Za-z0-9])(?:password|pwd|accountkey|sharedaccesssignature)\s*=\s*[^;\s]{4,}"
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
            name="Generic API secret",
            pattern=re.compile(
                r"(?i)(?<![A-Za-z0-9])(?:api[_-]?key|client[_-]?secret|secret|token)\b\s*[:=]\s*['\"]?[^\s'\";]{6,}"
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
            pattern=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
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
                matches.append(
                    CredentialMatch(
                        name=credential_pattern.name,
                        matched_text=match.group(0),
                        start=match.start(),
                        end=match.end(),
                    )
                )
        return matches
