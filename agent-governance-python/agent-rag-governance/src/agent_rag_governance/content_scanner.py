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
from dataclasses import dataclass
from typing import List


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
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
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
        re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"),
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
        if self._check_injections:
            for pattern, description in _INJECTION_PATTERNS:
                if pattern.search(text):
                    return ScanResult(
                        chunk_index=index,
                        blocked=True,
                        category="injection",
                        pattern_matched=description,
                    )

        if self._check_pii:
            for pattern, description in _PII_PATTERNS:
                if pattern.search(text):
                    return ScanResult(
                        chunk_index=index,
                        blocked=True,
                        category="pii",
                        pattern_matched=description,
                    )

        return ScanResult(chunk_index=index, blocked=False)
