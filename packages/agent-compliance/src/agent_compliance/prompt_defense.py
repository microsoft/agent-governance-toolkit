# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Pre-deployment prompt defense evaluator for AI agent system prompts.

Checks system prompts for missing defenses against 12 attack vectors
mapped to OWASP LLM Top 10. Pure regex — deterministic, zero LLM cost,
< 5ms per prompt.

Complements runtime prompt injection detection (agent-os) by validating
that defensive language is present *before* deployment rather than
detecting attacks at runtime.

References:
    - OWASP LLM Top 10 (2025): https://genai.owasp.org/llm-top-10/
    - Greshake et al. (2023): Indirect prompt injection
    - Schulhoff et al. (2023): Prompt injection taxonomy
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Grade scale
# ---------------------------------------------------------------------------

GRADE_THRESHOLDS: dict[str, int] = {"A": 90, "B": 70, "C": 50, "D": 30, "F": 0}


def _score_to_grade(score: int) -> str:
    """Map a 0-100 score to a letter grade."""
    for grade, threshold in GRADE_THRESHOLDS.items():
        if score >= threshold:
            return grade
    return "F"


# ---------------------------------------------------------------------------
# Defense rules — 12 attack vectors
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _DefenseRule:
    """Internal definition for a single defense vector."""

    vector_id: str
    name: str
    owasp: str
    patterns: tuple[re.Pattern[str], ...]
    min_matches: int = 1


_RULES: tuple[_DefenseRule, ...] = (
    _DefenseRule(
        vector_id="role-escape",
        name="Role Boundary",
        owasp="LLM01",
        patterns=(
            re.compile(
                r"(?:you are|your role|act as|serve as|function as|"
                r"the assistant is|assistant (?:named|called|is)|I am)",
                re.IGNORECASE,
            ),
            re.compile(
                r"(?:never (?:break|change|switch|abandon)"
                r"|only (?:answer|respond|act) as"
                r"|stay in (?:character|role)"
                r"|always (?:remain|be|act as)"
                r"|maintain.*(?:role|identity|persona))",
                re.IGNORECASE,
            ),
        ),
    ),
    _DefenseRule(
        vector_id="instruction-override",
        name="Instruction Boundary",
        owasp="LLM01",
        patterns=(
            re.compile(
                r"(?:do not|never|must not|cannot|should not" r"|refuse|reject|decline)",
                re.IGNORECASE,
            ),
            re.compile(
                r"(?:ignore (?:any|all)|disregard|override)",
                re.IGNORECASE,
            ),
        ),
    ),
    _DefenseRule(
        vector_id="data-leakage",
        name="Data Protection",
        owasp="LLM07",
        patterns=(
            re.compile(
                r"(?:do not (?:reveal|share|disclose|expose|output)"
                r"|never (?:reveal|share|disclose|show)"
                r"|keep.*(?:secret|confidential|private))",
                re.IGNORECASE,
            ),
            re.compile(
                r"(?:system prompt|internal|instruction" r"|training|behind the scenes)",
                re.IGNORECASE,
            ),
        ),
    ),
    _DefenseRule(
        vector_id="output-manipulation",
        name="Output Control",
        owasp="LLM02",
        patterns=(
            re.compile(
                r"(?:only (?:respond|reply|output|answer) (?:in|with|as)"
                r"|format.*(?:as|in|using)"
                r"|response (?:format|style))",
                re.IGNORECASE,
            ),
            re.compile(
                r"(?:do not (?:generate|create|produce|output)" r"|never (?:generate|produce))",
                re.IGNORECASE,
            ),
        ),
    ),
    _DefenseRule(
        vector_id="multilang-bypass",
        name="Multi-language Protection",
        owasp="LLM01",
        patterns=(
            re.compile(
                r"(?:only (?:respond|reply|answer|communicate) in"
                r"|language"
                r"|respond in (?:english|chinese|japanese))",
                re.IGNORECASE,
            ),
            re.compile(
                r"(?:regardless of (?:the )?(?:input |user )?language)",
                re.IGNORECASE,
            ),
        ),
    ),
    _DefenseRule(
        vector_id="unicode-attack",
        name="Unicode Protection",
        owasp="LLM01",
        patterns=(
            re.compile(
                r"(?:unicode|homoglyph|special character" r"|character encoding)",
                re.IGNORECASE,
            ),
        ),
    ),
    _DefenseRule(
        vector_id="context-overflow",
        name="Length Limits",
        owasp="LLM01",
        patterns=(
            re.compile(
                r"(?:max(?:imum)?.*(?:length|char|token|word)"
                r"|limit.*(?:input|length|size|token)"
                r"|truncat)",
                re.IGNORECASE,
            ),
        ),
    ),
    _DefenseRule(
        vector_id="indirect-injection",
        name="Indirect Injection Protection",
        owasp="LLM01",
        patterns=(
            re.compile(
                r"(?:external (?:data|content|source|input)"
                r"|user.?(?:provided|supplied|submitted|generated)"
                r"|third.?party|untrusted)",
                re.IGNORECASE,
            ),
            re.compile(
                r"(?:(?:validate|verify|sanitize|filter|check)"
                r".*(?:external|input|data|content)"
                r"|treat.*(?:as (?:data|untrusted|information))"
                r"|do not (?:follow|execute|obey)"
                r".*(?:instruction|command)"
                r".*(?:from|in|within|embedded))",
                re.IGNORECASE,
            ),
        ),
    ),
    _DefenseRule(
        vector_id="social-engineering",
        name="Social Engineering Defense",
        owasp="LLM01",
        patterns=(
            re.compile(
                r"(?:emotional|urgency|pressure|threaten" r"|guilt|manipulat)",
                re.IGNORECASE,
            ),
            re.compile(
                r"(?:regardless of|no matter|even if)",
                re.IGNORECASE,
            ),
        ),
    ),
    _DefenseRule(
        vector_id="output-weaponization",
        name="Harmful Content Prevention",
        owasp="LLM02",
        patterns=(
            re.compile(
                r"(?:harmful|illegal|dangerous|malicious" r"|weapon|violence|exploit|phishing)",
                re.IGNORECASE,
            ),
            re.compile(
                r"(?:do not (?:help|assist|generate|create)" r".*(?:harm|illegal|danger|weapon))",
                re.IGNORECASE,
            ),
        ),
    ),
    _DefenseRule(
        vector_id="abuse-prevention",
        name="Abuse Prevention",
        owasp="LLM06",
        patterns=(
            re.compile(
                r"(?:abuse|misuse|exploit|attack" r"|inappropriate|spam|flood)",
                re.IGNORECASE,
            ),
            re.compile(
                r"(?:rate limit|throttl|quota" r"|maximum.*request)",
                re.IGNORECASE,
            ),
            re.compile(
                r"(?:authenticat|authoriz|permission" r"|access control|api.?key|token)",
                re.IGNORECASE,
            ),
        ),
    ),
    _DefenseRule(
        vector_id="input-validation",
        name="Input Validation",
        owasp="LLM01",
        patterns=(
            re.compile(
                r"(?:validate|sanitize|filter|clean|escape|strip"
                r"|check.*input|input.*(?:validation|check))",
                re.IGNORECASE,
            ),
            re.compile(
                r"(?:sql|xss|injection|script|html" r"|special char|malicious)",
                re.IGNORECASE,
            ),
        ),
    ),
)

VECTOR_COUNT = len(_RULES)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class PromptDefenseFinding:
    """Result of checking one defense vector."""

    vector_id: str
    name: str
    owasp: str
    defended: bool
    confidence: float  # 0.0-1.0
    severity: str  # "critical", "high", "medium", "low"
    evidence: str
    matched_patterns: int
    required_patterns: int


@dataclass
class PromptDefenseReport:
    """Complete audit result for a single prompt."""

    grade: str
    score: int  # 0-100
    defended: int
    total: int
    coverage: str  # e.g. "4/12"
    missing: list[str]
    findings: list[PromptDefenseFinding]
    prompt_hash: str  # SHA-256 of input (audit trail, no raw content stored)
    evaluated_at: str  # ISO 8601 timestamp

    def is_blocking(self, min_grade: str = "C") -> bool:
        """Return True if the grade is below the minimum threshold."""
        order = {"A": 5, "B": 4, "C": 3, "D": 2, "F": 1}
        return order.get(self.grade, 0) < order.get(min_grade, 3)

    def to_dict(self) -> dict[str, object]:
        """Serialize to a JSON-compatible dict."""
        return {
            "grade": self.grade,
            "score": self.score,
            "defended": self.defended,
            "total": self.total,
            "coverage": self.coverage,
            "missing": self.missing,
            "prompt_hash": self.prompt_hash,
            "evaluated_at": self.evaluated_at,
            "findings": [
                {
                    "vector_id": f.vector_id,
                    "name": f.name,
                    "owasp": f.owasp,
                    "defended": f.defended,
                    "confidence": f.confidence,
                    "severity": f.severity,
                    "evidence": f.evidence,
                }
                for f in self.findings
            ],
        }

    def to_json(self) -> str:
        """Serialize to deterministic JSON (suitable for hashing)."""
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass
class PromptDefenseConfig:
    """Configuration for the prompt defense evaluator."""

    min_grade: str = "C"
    vectors: Optional[list[str]] = None  # None = all 12
    severity_map: dict[str, str] = field(
        default_factory=lambda: {
            "role-escape": "high",
            "instruction-override": "high",
            "data-leakage": "critical",
            "output-manipulation": "medium",
            "multilang-bypass": "medium",
            "unicode-attack": "low",
            "context-overflow": "low",
            "indirect-injection": "critical",
            "social-engineering": "medium",
            "output-weaponization": "high",
            "abuse-prevention": "medium",
            "input-validation": "high",
        }
    )


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------


class PromptDefenseEvaluator:
    """Evaluates system prompts for missing defenses against 12 attack vectors.

    This is a **static analysis** tool — it checks whether defensive language
    is present in the prompt text.  It does not test runtime behaviour.

    Deterministic: same input always produces the same output.
    No LLM calls, no network access, no external dependencies.

    Example::

        evaluator = PromptDefenseEvaluator()
        report = evaluator.evaluate("You are a helpful assistant.")
        print(report.grade)   # "F"
        print(report.missing) # ['instruction-override', 'data-leakage', ...]

    Integration with MerkleAuditChain::

        entry = evaluator.to_audit_entry(report, agent_did="agent:main")
        audit_log.add_entry(entry)
    """

    def __init__(self, config: PromptDefenseConfig | None = None) -> None:
        self.config = config or PromptDefenseConfig()
        self._rules = self._filter_rules()

    def _filter_rules(self) -> tuple[_DefenseRule, ...]:
        """Return only the rules matching the configured vectors."""
        if self.config.vectors is None:
            return _RULES
        allowed = set(self.config.vectors)
        return tuple(r for r in _RULES if r.vector_id in allowed)

    #: Maximum prompt length to scan (defense-in-depth against ReDoS).
    #: System prompts above 100 KB are almost certainly not real prompts.
    MAX_PROMPT_LENGTH = 100_000

    def evaluate(self, prompt: str) -> PromptDefenseReport:
        """Evaluate a system prompt for missing defenses.

        Args:
            prompt: The system prompt text to audit.

        Returns:
            A complete report with per-vector findings, grade, and score.

        Raises:
            ValueError: If the prompt exceeds MAX_PROMPT_LENGTH.
        """
        if len(prompt) > self.MAX_PROMPT_LENGTH:
            raise ValueError(
                f"Prompt length {len(prompt)} exceeds maximum "
                f"{self.MAX_PROMPT_LENGTH} (ReDoS protection)"
            )

        findings: list[PromptDefenseFinding] = []

        for rule in self._rules:
            matched = 0
            evidence = ""

            for pattern in rule.patterns:
                match = pattern.search(prompt)
                if match:
                    matched += 1
                    if not evidence:
                        evidence = match.group(0)[:60]

            defended = matched >= rule.min_matches
            # Confidence scoring:
            #   Defended: starts at 0.5, +0.2 per pattern match, capped at 0.9
            #     (more matching patterns = higher confidence the defense is real)
            #   Not defended but partial match: 0.4 (some signal, but insufficient)
            #   Not defended, zero matches: 0.8 (high confidence it's truly missing)
            confidence = (
                min(0.9, 0.5 + matched * 0.2) if defended else (0.4 if matched > 0 else 0.8)
            )
            severity = self.config.severity_map.get(rule.vector_id, "medium")

            if defended:
                evidence_str = f'Found: "{evidence}"'
            elif matched > 0:
                evidence_str = f"Partial: {matched}/{rule.min_matches} pattern(s)"
            else:
                evidence_str = "No defense pattern found"

            findings.append(
                PromptDefenseFinding(
                    vector_id=rule.vector_id,
                    name=rule.name,
                    owasp=rule.owasp,
                    defended=defended,
                    confidence=confidence,
                    severity=severity,
                    evidence=evidence_str,
                    matched_patterns=matched,
                    required_patterns=rule.min_matches,
                )
            )

        defended_count = sum(1 for f in findings if f.defended)
        total = len(findings)
        score = round((defended_count / total) * 100) if total > 0 else 0
        missing = [f.vector_id for f in findings if not f.defended]

        prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        now = datetime.now(timezone.utc).isoformat()

        return PromptDefenseReport(
            grade=_score_to_grade(score),
            score=score,
            defended=defended_count,
            total=total,
            coverage=f"{defended_count}/{total}",
            missing=missing,
            findings=findings,
            prompt_hash=prompt_hash,
            evaluated_at=now,
        )

    def evaluate_file(self, path: str) -> PromptDefenseReport:
        """Evaluate a system prompt read from a file.

        Args:
            path: Path to a text file containing the system prompt.

        Returns:
            A complete defense audit report.

        Raises:
            FileNotFoundError: If the file does not exist.
            PermissionError: If the file cannot be read.
            ValueError: If the file is empty.
        """
        resolved = Path(path).resolve()
        if not resolved.is_file():
            raise FileNotFoundError(f"Prompt file not found: {resolved}")
        content = resolved.read_text(encoding="utf-8")
        if not content.strip():
            raise ValueError(f"Prompt file is empty: {resolved}")
        return self.evaluate(content)

    def evaluate_batch(
        self,
        prompts: dict[str, str],
    ) -> dict[str, PromptDefenseReport]:
        """Evaluate multiple prompts keyed by identifier.

        Args:
            prompts: Mapping of ``{identifier: prompt_text}``.

        Returns:
            Mapping of ``{identifier: report}``.
        """
        return {key: self.evaluate(text) for key, text in prompts.items()}

    def to_audit_entry(
        self,
        report: PromptDefenseReport,
        agent_did: str,
        trace_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> dict[str, object]:
        """Convert a report into an AuditEntry-compatible dict.

        The returned dict can be passed to ``AuditEntry(**d)`` for
        integration with :class:`MerkleAuditChain`.

        Args:
            report: The defense audit report.
            agent_did: The agent's decentralized identifier.
            trace_id: Optional correlation trace ID.
            session_id: Optional session ID.

        Returns:
            A dict matching the AuditEntry schema.
        """
        return {
            "event_type": "prompt.defense.evaluated",
            "agent_did": agent_did,
            "action": "pre_deployment_check",
            "outcome": (
                "success"
                if not report.is_blocking(
                    self.config.min_grade,
                )
                else "denied"
            ),
            "policy_decision": report.grade,
            "matched_rule": f"min_grade:{self.config.min_grade}",
            "trace_id": trace_id,
            "session_id": session_id,
            "data": {
                "grade": report.grade,
                "score": report.score,
                "coverage": report.coverage,
                "missing_vectors": report.missing,
                "prompt_hash": report.prompt_hash,
            },
        }

    def to_compliance_violation(
        self,
        report: PromptDefenseReport,
    ) -> list[dict[str, object]]:
        """Convert undefended vectors into ComplianceViolation-compatible dicts.

        Only produces violations for vectors that are not defended.

        Args:
            report: The defense audit report.

        Returns:
            A list of dicts matching the ComplianceViolation schema.
        """
        violations: list[dict[str, object]] = []
        for finding in report.findings:
            if finding.defended:
                continue
            violations.append(
                {
                    "control_id": f"OWASP:{finding.owasp}::{finding.vector_id}",
                    "severity": finding.severity,
                    "evidence": [finding.evidence],
                    "remediated": False,
                }
            )
        return violations
