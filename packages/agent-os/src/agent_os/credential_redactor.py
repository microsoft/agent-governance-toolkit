# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Credential redaction helpers for MCP audit and response safety."""

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
            pattern=re.compile(r"\b(?:ghp|ghs)_[A-Za-z0-9]{20,}\b"),
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
                r"-----BEGIN\s+(?P<label>(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY)-----"
                r"[\s\S]*?"
                r"-----END\s+(?P=label)-----",
                re.DOTALL,
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

    @classmethod
    def redact(cls, value: str | None) -> str:
        """Redact credential-like values from a string.

        Args:
            value: String content that may contain credential-like material.

        Returns:
            A string with each detected credential replaced by
            ``REDACTED_PLACEHOLDER``. Empty input returns an empty string.
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

        if redaction_count:
            logger.info("Credential redaction applied to %s value(s)", redaction_count)

        return result

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
                    )
                )
        return matches
