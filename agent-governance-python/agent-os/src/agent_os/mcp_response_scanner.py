# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Scan MCP tool responses for prompt injection and data leakage."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from agent_os.credential_redactor import CredentialMatch, CredentialRedactor

logger = logging.getLogger(__name__)

_INSTRUCTION_TAG_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"<(?:important|system|instruction|instructions|hidden|inject|admin|override|prompt|context|role)\b[^>]*>",
        re.IGNORECASE,
    ),
    re.compile(r"\[(?:system|admin|instructions?)\]", re.IGNORECASE),
)
_IMPERATIVE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"ignore\s+(?:all\s+)?previous\s+(?:instructions?|context|rules?)", re.IGNORECASE),
    re.compile(
        r"(?:forget|disregard|override)\s+(?:all\s+)?(?:previous|above|prior|earlier)",
        re.IGNORECASE,
    ),
    re.compile(r"\bexecute\s+this\b", re.IGNORECASE),
    re.compile(r"\byou\s+are\s+now\b", re.IGNORECASE),
    re.compile(r"\bnew\s+(?:role|instruction|directive|persona)\s*:", re.IGNORECASE),
    re.compile(r"\bfrom\s+now\s+on\b", re.IGNORECASE),
    re.compile(r"\bdo\s+not\s+(?:follow|obey|listen)\b", re.IGNORECASE),
)
_URL_PATTERN = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
_EXFILTRATION_URL_PATTERN = re.compile(
    r"(?i)(?:\b(?:api[_-]?key|token|secret|payload|data|dump|upload|exfil|webhook)\b|webhook\.site|requestbin|pastebin|ngrok|transfer\.sh)"
)


@dataclass(frozen=True)
class MCPResponseThreat:
    """A threat detected in tool output."""

    category: str
    description: str
    matched_pattern: str | None = None
    details: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class MCPResponseScanResult:
    """Result of scanning an MCP tool response."""

    is_safe: bool
    tool_name: str
    threats: list[MCPResponseThreat] = field(default_factory=list)

    @classmethod
    def safe(cls, tool_name: str) -> "MCPResponseScanResult":
        return cls(is_safe=True, tool_name=tool_name, threats=[])

    @classmethod
    def unsafe(
        cls,
        tool_name: str,
        *,
        reason: str,
        category: str = "error",
    ) -> "MCPResponseScanResult":
        return cls(
            is_safe=False,
            tool_name=tool_name,
            threats=[MCPResponseThreat(category=category, description=reason)],
        )


class MCPResponseScanner:
    """Scan tool responses before they are returned to an LLM.

    The scanner looks for prompt-injection markers, credential leaks, and
    likely exfiltration URLs, returning structured findings that callers can
    use to block or sanitize unsafe tool output.
    """

    def scan_response(
        self,
        response_content: str | None,
        tool_name: str = "unknown",
    ) -> MCPResponseScanResult:
        """Scan tool output and return a structured safety result.

        Args:
            response_content: Raw tool output to inspect.
            tool_name: Human-readable tool name for reporting.

        Returns:
            An ``MCPResponseScanResult`` marked safe when no threats are found.
            Unexpected scanner failures return an unsafe result.
        """
        try:
            if not response_content:
                return MCPResponseScanResult.safe(tool_name)

            threats: list[MCPResponseThreat] = []
            threats.extend(
                self._scan_patterns(
                    response_content,
                    patterns=_INSTRUCTION_TAG_PATTERNS,
                    category="instruction_injection",
                    description="Instruction tag detected in tool response.",
                )
            )
            threats.extend(
                self._scan_patterns(
                    response_content,
                    patterns=_IMPERATIVE_PATTERNS,
                    category="prompt_injection",
                    description="Imperative instruction detected in tool response.",
                )
            )
            credential_matches = self._deduplicate_credential_matches(
                CredentialRedactor.find_matches(response_content)
            )
            threats.extend(self._credential_threats(credential_matches, action="detected"))
            threats.extend(self._scan_pii_leaks(response_content, credential_matches))
            threats.extend(self._scan_exfiltration_urls(response_content))

            if not threats:
                return MCPResponseScanResult.safe(tool_name)

            logger.warning(
                "MCP response scan found %s issue(s) in tool %s",
                len(threats),
                tool_name,
            )
            return MCPResponseScanResult(is_safe=False, tool_name=tool_name, threats=threats)
        except Exception:
            logger.error("MCP response scanning failed closed", exc_info=True)
            return MCPResponseScanResult.unsafe(
                tool_name,
                reason="Response scanner error (fail-closed).",
            )

    def sanitize_response(
        self,
        response_content: str | None,
        tool_name: str = "unknown",
    ) -> tuple[str, list[MCPResponseThreat]]:
        """Strip instruction tags and redact credentials from tool output.

        This makes the returned content safe from prompt-injection tags and
        credential leakage in one pass, so a host does not have to stitch the
        scanner and :class:`CredentialRedactor` together by hand.

        Note: this removes instruction tags and *credentials* only. It does
        **not** remove PII (email, phone, SSN, credit card, IP); those are
        reported by :meth:`scan_response` and must be handled by policy. Do not
        treat sanitized output as PII-safe.

        Args:
            response_content: Raw tool output to sanitize.
            tool_name: Human-readable tool name for reporting.

        Returns:
            A tuple of ``(sanitized_content, removed_threats)`` where
            ``removed_threats`` lists the instruction tags stripped and the
            credential types redacted (by type name, never the raw secret). On
            failure the method returns an empty string and a fail-closed error
            finding.
        """
        try:
            if not response_content:
                return "", []

            sanitized = response_content
            removed: list[MCPResponseThreat] = []
            for pattern in _INSTRUCTION_TAG_PATTERNS:
                for match in pattern.finditer(sanitized):
                    removed.append(
                        MCPResponseThreat(
                            category="instruction_injection",
                            description="Instruction tag stripped from tool response.",
                            matched_pattern=match.group(0),
                        )
                    )
                sanitized = pattern.sub("", sanitized)

            credential_matches = self._deduplicate_credential_matches(
                CredentialRedactor.find_matches(sanitized)
            )
            if credential_matches:
                sanitized = CredentialRedactor.redact(sanitized)
                removed.extend(
                    self._credential_threats(credential_matches, action="redacted")
                )

            return sanitized, removed
        except Exception:
            logger.error("MCP response sanitization failed closed", exc_info=True)
            return "", [
                MCPResponseThreat(
                    category="error",
                    description=(
                        f"Response sanitization failed for tool '{tool_name}' (fail-closed)."
                    ),
                )
            ]

    @staticmethod
    def _scan_patterns(
        content: str,
        *,
        patterns: tuple[re.Pattern[str], ...],
        category: str,
        description: str,
    ) -> list[MCPResponseThreat]:
        threats: list[MCPResponseThreat] = []
        for pattern in patterns:
            for match in pattern.finditer(content):
                threats.append(
                    MCPResponseThreat(
                        category=category,
                        description=description,
                        matched_pattern=match.group(0),
                    )
                )
        return threats

    @staticmethod
    def _deduplicate_credential_matches(
        matches: list[CredentialMatch],
    ) -> list[CredentialMatch]:
        """Drop credential matches whose span is strictly inside a larger match.

        A single secret can match both a specific and a generic pattern (for
        example ``api_key=AIza...`` matches "Google API key" and "Generic API
        secret"). Keeping only the widest span per region avoids emitting
        duplicate ``credential_leak`` findings for one secret. Matches with equal
        spans or unknown offsets are all retained.
        """
        kept: list[CredentialMatch] = []
        for index, match in enumerate(matches):
            if match.start < 0:
                kept.append(match)
                continue
            match_size = match.end - match.start
            contained = any(
                other_index != index
                and other.start >= 0
                and other.start <= match.start
                and match.end <= other.end
                and (other.end - other.start) > match_size
                for other_index, other in enumerate(matches)
            )
            if not contained:
                kept.append(match)
        return kept

    @staticmethod
    def _credential_threats(
        matches: list[CredentialMatch], *, action: str
    ) -> list[MCPResponseThreat]:
        """Build credential threats from matches, exposing only the type name.

        ``action`` is "detected" (scan) or "redacted" (sanitize). The raw
        matched secret value is never placed in the threat.
        """
        return [
            MCPResponseThreat(
                category="credential_leak",
                description=f"{match.name} {action} in tool response.",
                matched_pattern=match.name,
                details={"credential_type": match.name},
            )
            for match in matches
        ]

    @staticmethod
    def _scan_pii_leaks(
        content: str,
        credential_matches: list[CredentialMatch] | None = None,
    ) -> list[MCPResponseThreat]:
        credential_spans = [
            (match.start, match.end)
            for match in (credential_matches or [])
            if match.start >= 0
        ]
        threats: list[MCPResponseThreat] = []
        for pii_match in CredentialRedactor.find_pii_matches(content):
            # Suppress PII that falls entirely inside a credential match: digit
            # runs in tokens such as Google "AIza..." keys otherwise register as
            # a false "US phone number" and would wrongly hard-block a secret
            # that is actually redactable.
            if pii_match.start >= 0 and any(
                start <= pii_match.start and pii_match.end <= end
                for start, end in credential_spans
            ):
                continue
            threats.append(
                MCPResponseThreat(
                    category="pii_leak",
                    description=f"{pii_match.name} detected in tool response.",
                    matched_pattern=pii_match.name,
                    details={"pii_type": pii_match.name},
                )
            )
        return threats

    @staticmethod
    def _scan_exfiltration_urls(content: str) -> list[MCPResponseThreat]:
        threats: list[MCPResponseThreat] = []
        for match in _URL_PATTERN.finditer(content):
            url = match.group(0)
            if not _EXFILTRATION_URL_PATTERN.search(url):
                continue
            threats.append(
                MCPResponseThreat(
                    category="data_exfiltration",
                    description="Potential data exfiltration URL detected in tool response.",
                    matched_pattern=url,
                )
            )
        return threats
