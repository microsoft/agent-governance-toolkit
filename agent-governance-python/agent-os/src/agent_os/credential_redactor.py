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
    """A credential-like value detected in text."""

    name: str
    matched_text: str


class CredentialRedactor:
    """Detect and redact credential-like material in strings and nested objects.

    Use this helper before persisting audit payloads or returning tool output to
    callers. The class operates on plain strings as well as nested dictionaries,
    lists, and tuples, replacing detected secret values with a stable
    placeholder.

    By default :meth:`redact` and its helpers scrub only secret-like material
    (:attr:`PATTERNS`). Personally identifiable information (:attr:`PII_PATTERNS`)
    is detected by :meth:`find_pii_matches` and :meth:`contains_pii` but is
    **not** removed unless ``redact_pii=True`` is passed to a redaction method.
    """

    # Python's stdlib ``re`` does not support per-pattern timeouts. These
    # patterns are kept simple and anchored to avoid pathological backtracking.
    PATTERNS: tuple[CredentialPattern, ...] = (
        CredentialPattern(
            name="OpenAI API key",
            pattern=re.compile(r"\bsk-[A-Za-z0-9][A-Za-z0-9_-]{18,}\b"),
        ),
        CredentialPattern(
            name="GitHub token",
            pattern=re.compile(
                r"(?<![A-Za-z0-9_])(?:gh[psour]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{22,})(?![A-Za-z0-9_])"
            ),
        ),
        CredentialPattern(
            name="AWS access key",
            pattern=re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
        ),
        CredentialPattern(
            name="Azure key",
            pattern=re.compile(
                r"(?i)(?:accountkey|sharedaccesskey|azure[_-]?key)\s*[:=]\s*[A-Za-z0-9+/=]{20,}"
            ),
        ),
        CredentialPattern(
            name="Bearer token",
            pattern=re.compile(r"\bBearer\s+[A-Za-z0-9._\-+/=]{16,}\b"),
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
                r"(?i)\b(?:password|pwd|accountkey|sharedaccesssignature)\s*=\s*[^;\s]{4,}"
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
            pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9._-]{6,}\.[A-Za-z0-9._-]{6,}\b"),
        ),
        CredentialPattern(
            name="Generic API secret",
            pattern=re.compile(
                r"(?i)\b(?:api[_-]?key|client[_-]?secret|secret|token)\b\s*[:=]\s*['\"]?[^\s'\";]{6,}"
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
            # Broadened to the canonical SSN form shared with
            # ``integrations/base.py`` (dash/space/dot/none), which mirrors the
            # YAML policy packs (see #2469 and #2594). Previously this only
            # matched the dashed form, so ``123 45 6789`` / ``123.45.6789`` /
            # ``123456789`` were detected by the integrations layer but not here.
            name="US SSN",
            pattern=re.compile(r"\b\d{3}[\s.-]?\d{2}[\s.-]?\d{4}\b"),
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
    def redact(cls, value: str | None, *, redact_pii: bool = False) -> str:
        """Redact credential-like values from a string.

        By default only secret-like material (API keys, tokens, private keys,
        ...) is redacted. Pass ``redact_pii=True`` to additionally scrub
        personally identifiable information (email, phone, SSN, credit card,
        IPv4 address) detected by :attr:`PII_PATTERNS`.

        Args:
            value: String content that may contain credential-like material.
            redact_pii: When ``True``, also redact PII/CRI patterns. Defaults
                to ``False`` to preserve the historical secrets-only behavior.

        Returns:
            A string with each detected credential (and, when ``redact_pii`` is
            set, each PII value) replaced by ``REDACTED_PLACEHOLDER``. Empty
            input returns an empty string.
        """
        if not value:
            return ""

        result = value
        redaction_count = 0
        for credential_pattern in cls.PATTERNS:
            updated, count = credential_pattern.pattern.subn(REDACTED_PLACEHOLDER, result)
            if count:
                redaction_count += count
                result = updated

        if redact_pii:
            for pii_pattern in cls.PII_PATTERNS:
                updated, count = pii_pattern.pattern.subn(REDACTED_PLACEHOLDER, result)
                if count:
                    redaction_count += count
                    result = updated

        if redaction_count:
            logger.info("Credential redaction applied to %s value(s)", redaction_count)

        return result

    @classmethod
    def redact_mapping(
        cls, mapping: dict[str, Any] | None, *, redact_pii: bool = False
    ) -> dict[str, Any]:
        """Redact all nested values in a mapping.

        Args:
            mapping: A possibly nested mapping containing strings, lists,
                tuples, or dictionaries.
            redact_pii: When ``True``, also redact PII/CRI patterns in nested
                strings. Defaults to ``False`` (secrets-only).

        Returns:
            A new mapping with nested strings redacted recursively. Empty input
            returns an empty dictionary.
        """
        if not mapping:
            return {}
        return {
            key: cls.redact_data_structure(value, redact_pii=redact_pii)
            for key, value in mapping.items()
        }

    @classmethod
    def redact_dictionary(
        cls, mapping: dict[str, Any] | None
    ) -> dict[str, Any]:
        """Compatibility alias for dictionary redaction.

        Args:
            mapping: Dictionary-like content to redact.

        Returns:
            The redacted mapping produced by :meth:`redact_mapping`.
        """
        return cls.redact_mapping(mapping)

    @classmethod
    def redact_data_structure(cls, value: Any, *, redact_pii: bool = False) -> Any:
        """Recursively redact nested strings in dicts, lists, and tuples.

        ``redact_pii`` defaults to ``False`` to preserve the historical
        secrets-only behavior. The only production caller (the MCP gateway
        audit path in ``mcp_gateway.py``) deliberately does not flip it: PII
        scrubbing is an opt-in capability and ships wired to zero callers by
        default, so audit logs retain their existing shape until a caller
        explicitly opts in. See issue #3239.

        Args:
            value: Any Python value that may contain nested strings.
            redact_pii: When ``True``, also redact PII/CRI patterns in every
                nested string. Defaults to ``False`` (secrets-only).

        Returns:
            A value of the same general shape with strings redacted in place of
            their original secret-bearing content.
        """
        if isinstance(value, str):
            return cls.redact(value, redact_pii=redact_pii)
        if isinstance(value, dict):
            return {
                key: cls.redact_data_structure(item, redact_pii=redact_pii)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [cls.redact_data_structure(item, redact_pii=redact_pii) for item in value]
        if isinstance(value, tuple):
            return tuple(
                cls.redact_data_structure(item, redact_pii=redact_pii) for item in value
            )
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
                    )
                )
        return matches
