# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Chunk-level content scanner for retrieved RAG documents.

Detects PII patterns and prompt-injection payloads in retrieved chunks
before they reach the LLM context. Pure regex — deterministic, zero LLM
cost, < 1ms per chunk.

Injection patterns are sourced from the same taxonomy used by
``agent_os.memory_guard`` (OWASP ASI06).
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import List


def _normalize_for_matching(text: str) -> str:
    """Return *text* normalised so common Unicode obfuscation doesn't
    bypass the regex patterns.

    The patterns in this module are ASCII-shaped, but the LLM consumer
    of retrieved chunks reads Unicode without trouble. An attacker who
    controls a retrieved document can therefore insert zero-width
    characters between letters, replace letters with fullwidth or
    mathematical-script lookalikes, or rely on NFD vs NFC encoding
    differences to defeat the regexes while preserving the semantic
    content the LLM will read. Normalising before matching closes the
    common bypass shapes:

    - ``unicodedata.normalize("NFKC", ...)`` folds compatibility
      variants (fullwidth Latin → ASCII, mathematical script → Latin,
      ligatures decomposed, NFD ↔ NFC).
    - Stripping Unicode "format" category characters (``Cf``) removes
      zero-width spaces (U+200B), zero-width joiners (U+200D / U+200C),
      word joiners (U+2060), bidirectional control marks, and similar
      invisibles that an attacker uses to break ``\\b`` boundaries and
      character runs.
    - ``str.casefold()`` provides Unicode-aware case folding so the
      already-IGNORECASE injection patterns also catch
      uppercase-Unicode-equivalent obfuscations after NFKC mapping.

    Residual confusable shapes (Cyrillic ``і`` for Latin ``i``, Greek
    ``Ε`` for Latin ``E``, etc.) are not handled by NFKC and would
    require a Unicode TR39 confusables table; those are out of scope
    for this regex-based scanner and would warrant a heavier moderation
    primitive.
    """
    nfkc = unicodedata.normalize("NFKC", text)
    stripped = "".join(
        ch for ch in nfkc if unicodedata.category(ch) != "Cf"
    )
    return stripped.casefold()


_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE), "ignore previous instructions"),
    (re.compile(r"you\s+are\s+now\b", re.IGNORECASE), "role override: you are now"),
    (re.compile(r"system\s*prompt\s*:", re.IGNORECASE), "system prompt override"),
    (re.compile(r"disregard\s+(all\s+)?(prior|above)\s+", re.IGNORECASE), "disregard prior instructions"),
    (re.compile(r"forget\s+(everything|all|your)\s+", re.IGNORECASE), "memory wipe instruction"),
    (re.compile(r"new\s+instructions?\s*:", re.IGNORECASE), "new instructions injection"),
    (re.compile(r"override\s+(previous\s+)?instructions", re.IGNORECASE), "instruction override"),
    (re.compile(r"exec\s*\(|eval\s*\(|__import__\s*\(", re.IGNORECASE), "code execution attempt"),
]


_PII_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        # The TLD class previously was ``[A-Z|a-z]`` — the ``|`` is a
        # literal pipe character inside a character class, not an
        # alternation. The corrected class accepts ASCII letters only.
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "email address",
    ),
    (
        re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        "phone number",
    ),
    (
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "SSN",
    ),
    (
        # Credit-card BINs:
        #   Visa            4 followed by 12 or 15 digits
        #   Mastercard      51-55 followed by 14 digits (legacy 5-series)
        #   Mastercard      2221-2720 followed by 12 digits (2-series)
        #   Amex            34 or 37 followed by 13 digits
        #   Discover        6011 or 65xx followed by 12 digits
        re.compile(
            r"\b(?:"
            r"4[0-9]{12}(?:[0-9]{3})?"
            r"|5[1-5][0-9]{14}"
            r"|2(?:2(?:2[1-9]|[3-9][0-9])|[3-6][0-9]{2}|7(?:[01][0-9]|20))[0-9]{12}"
            r"|3[47][0-9]{13}"
            r"|6(?:011|5[0-9]{2})[0-9]{12}"
            r")\b"
        ),
        "credit card number",
    ),
]


@dataclass
class ScanResult:
    """Result of scanning a single chunk.

    Attributes:
        chunk_index: Zero-based position in the retrieved list.
        blocked: Whether this chunk should be withheld from the LLM.
        category: ``"injection"``, ``"pii"``, or ``None`` if clean.
        pattern_matched: Human-readable description of the matched pattern.
    """

    chunk_index: int
    blocked: bool
    category: str | None = None
    pattern_matched: str | None = None


class ContentScanner:
    """Scans retrieved document chunks for PII and injection payloads.

    Args:
        active_policies: List of policy names to enforce. Supported values:
            ``"block_injections"`` and ``"block_pii"``. Unknown values are
            ignored.

    Example::

        scanner = ContentScanner(["block_pii", "block_injections"])
        results = scanner.scan(chunks)
        clean = [c for r, c in zip(results, chunks) if not r.blocked]
    """

    def __init__(self, active_policies: List[str]) -> None:
        self._check_injections = "block_injections" in active_policies
        self._check_pii = "block_pii" in active_policies

    def scan(self, chunks: List[str]) -> List[ScanResult]:
        """Scan a list of text chunks and return a result per chunk.

        Args:
            chunks: List of text strings (document page contents or passages).

        Returns:
            One :class:`ScanResult` per chunk in the same order.
        """
        results: list[ScanResult] = []
        for i, chunk in enumerate(chunks):
            result = self._scan_chunk(i, chunk)
            results.append(result)
        return results

    def _scan_chunk(self, index: int, text: str) -> ScanResult:
        # Pattern matching runs against a Unicode-normalised view of the
        # text so common obfuscation (zero-width separators, fullwidth or
        # mathematical-script lookalikes, NFD/NFC encoding tricks) does
        # not let injection or PII payloads slip past the ASCII-shaped
        # regexes while remaining readable by the LLM.
        normalised = _normalize_for_matching(text)

        if self._check_injections:
            for pattern, description in _INJECTION_PATTERNS:
                if pattern.search(normalised):
                    return ScanResult(
                        chunk_index=index,
                        blocked=True,
                        category="injection",
                        pattern_matched=description,
                    )

        if self._check_pii:
            for pattern, description in _PII_PATTERNS:
                if pattern.search(normalised):
                    return ScanResult(
                        chunk_index=index,
                        blocked=True,
                        category="pii",
                        pattern_matched=description,
                    )

        return ScanResult(chunk_index=index, blocked=False)
