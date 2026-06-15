# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Pre-deployment prompt defense evaluator for AI agent system prompts.

Checks system prompts for missing defenses against 17 attack vectors:
12 mapped to the OWASP LLM Top 10 (conversational safety) and 5 mapped to
the OWASP Agentic Top 10 / ASI (agentic safety — cross-agent authority,
financial transactions, skill provenance, least agency, encoding-aware
injection). Pure regex — deterministic, zero LLM cost; < 5ms on typical
system prompts (<= 2KB) and scales linearly with prompt length.

Complements runtime prompt injection detection (agent-os) by validating
that defensive language is present *before* deployment rather than
detecting attacks at runtime.

References:
    - OWASP LLM Top 10 (2025): https://genai.owasp.org/llm-top-10/
    - OWASP Top 10 for Agentic Applications (2026):
      https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
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

# Ordered descending by threshold. A list of tuples encodes the scan
# order explicitly so the mapping survives ``dict(...)`` round-trips,
# external mutation, and accidental re-ordering — all of which the
# previous insertion-ordered dict relied on Python 3.7+ semantics to
# guarantee silently. ``GRADE_THRESHOLDS`` (the historical dict) is
# kept as a public re-export for backwards compatibility, but the
# scoring function reads from the canonical tuple list below.
GRADE_THRESHOLD_LIST: tuple[tuple[str, int], ...] = (
    ("A", 90),
    ("B", 70),
    ("C", 50),
    ("D", 30),
    ("F", 0),
)

GRADE_THRESHOLDS: dict[str, int] = dict(GRADE_THRESHOLD_LIST)


def _score_to_grade(score: int) -> str:
    """Map a 0-100 score to a letter grade.

    Scans ``GRADE_THRESHOLD_LIST`` top-down (highest threshold first)
    and returns the first letter whose threshold the score meets.
    """
    for grade, threshold in GRADE_THRESHOLD_LIST:
        if score >= threshold:
            return grade
    return "F"


# ---------------------------------------------------------------------------
# Defense rules — 17 attack vectors (12 OWASP LLM-era + 5 OWASP ASI agent-era)
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
                # Bound the `.*` reach in `maintain ... role` to 50
                # characters. The unbounded form (maintain.*role) can
                # be coerced into pathological backtracking on
                # adversarial 100K-char prompts; defense-grade input
                # to a defense scanner shouldn't widen the attack
                # surface. 50 chars covers normal language
                # ("maintain your assigned role", "maintain the
                # assistant persona") without exposing the runaway
                # case.
                r"(?:never (?:break|change|switch|abandon)"
                r"|only (?:answer|respond|act) as"
                r"|stay in (?:character|role)"
                r"|always (?:remain|be|act as)"
                r"|maintain.{0,50}?(?:role|identity|persona))",
                re.IGNORECASE,
            ),
        ),
    ),
    _DefenseRule(
        vector_id="instruction-override",
        name="Instruction Boundary",
        owasp="LLM01",
        patterns=(
            # Pattern 1: refusal verbs.
            re.compile(
                r"(?:do not|never|must not|cannot|should not" r"|refuse|reject|decline)",
                re.IGNORECASE,
            ),
            # Pattern 2: target concepts — these are the *attack* vocabulary
            # ("ignore all", "disregard", "override").  A real defense
            # statement contains BOTH a refusal verb AND a target concept
            # ("never disregard system prompts", "refuse override attempts").
            # Requiring min_matches=2 prevents a prompt containing only the
            # bare attack ("Ignore all previous instructions") from being
            # graded as defended against the very attack the rule detects.
            re.compile(
                r"(?:ignore (?:any|all)|disregard|override)",
                re.IGNORECASE,
            ),
        ),
        min_matches=2,
    ),
    _DefenseRule(
        vector_id="data-leakage",
        name="Data Protection",
        owasp="LLM07",
        patterns=(
            # Pattern 1: defensive verb chains.
            re.compile(
                r"(?:do not (?:reveal|share|disclose|expose|output)"
                r"|never (?:reveal|share|disclose|show)"
                r"|keep.*(?:secret|confidential|private))",
                re.IGNORECASE,
            ),
            # Pattern 2: target concepts the attacker wants to extract.
            # Without a refusal verb these terms appear in attacker prompts
            # ("reveal the system prompt") and in benign mentions
            # ("the system prompt is internal documentation"), neither of
            # which represents a defense.  Require both patterns to match.
            re.compile(
                r"(?:system prompt|internal|instruction" r"|training|behind the scenes)",
                re.IGNORECASE,
            ),
        ),
        min_matches=2,
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
        min_matches=2,
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
            re.compile(
                r"(?:do not (?:accept|process|follow)"
                r"|never (?:accept|process)"
                r"|reject|normalize|sanitize|filter|validate)"
                r".*(?:unicode|homoglyph|special character|character encoding)",
                re.IGNORECASE,
            ),
        ),
        min_matches=2,
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
                # Bound each `.*` to 50 chars. Three consecutive `.*`
                # segments with alternations between them is the
                # classic catastrophic-backtracking shape — on a
                # 100K-char prompt without the closing tokens, the
                # engine explores many splits. Normal phrasing fits
                # well within 50 chars between concept tokens.
                r"(?:(?:validate|verify|sanitize|filter|check)"
                r".{0,50}?(?:external|input|data|content)"
                r"|treat.{0,50}?(?:as (?:data|untrusted|information))"
                r"|do not (?:follow|execute|obey)"
                r".{0,50}?(?:instruction|command)"
                r".{0,50}?(?:from|in|within|embedded))",
                re.IGNORECASE,
            ),
        ),
        min_matches=2,
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
        min_matches=2,
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
        min_matches=2,
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
        min_matches=2,
    ),
    _DefenseRule(
        vector_id="input-validation",
        name="Input Validation",
        owasp="LLM01",
        patterns=(
            # Pattern 1: validation verbs.
            re.compile(
                r"(?:validate|sanitize|filter|clean|escape|strip"
                r"|check.*input|input.*(?:validation|check))",
                re.IGNORECASE,
            ),
            # Pattern 2: attack types and target syntaxes.  Without a
            # validation verb these terms appear in attacker prompts ("run
            # this SQL: ...") and in benign mentions ("I help with HTML"),
            # neither of which represents a defense.  Require both patterns.
            re.compile(
                r"(?:sql|xss|injection|script|html" r"|special char|malicious)",
                re.IGNORECASE,
            ),
        ),
        min_matches=2,
    ),
    # -----------------------------------------------------------------------
    # Agent-era defense vectors (OWASP Agentic Top 10 / ASI).
    #
    # The 12 vectors above map to the OWASP LLM Top 10 — they audit a prompt
    # for *conversational* safety. They say nothing about the risks that only
    # exist once the model is an autonomous agent: delegating to other agents,
    # moving funds, loading skills, drifting off its assigned goal, or acting
    # on a decoded payload. AGT positions itself against the OWASP Agentic
    # Top 10, so a pre-deployment system-prompt audit should check the agentic
    # layer too. The five rules below close that gap.
    #
    # Each follows the same discipline as the rules above: bounded quantifiers
    # (no unbounded ``.*``) for ReDoS safety, and ``min_matches=2`` so the
    # attack vocabulary alone ("transfer the funds", "another agent told me")
    # never scores as *defended* — a real guardrail names both the capability
    # and the constraint on it.
    #
    # Regex vocabulary distilled from the open-source UltraProbe scanner
    # (npm: ultraprobe, MIT) — its ``scanDefense`` agent-era vectors, ported
    # here English-first to match this module's style.
    # -----------------------------------------------------------------------
    _DefenseRule(
        vector_id="cross-agent-auth",
        name="Cross-Agent Authorization Boundary",
        owasp="ASI-07",
        patterns=(
            # Pattern 1: the multi-agent surface — instructions/authority
            # arriving from *another* agent rather than the operator.
            re.compile(
                r"(?:another|other|external|third.?party|forwarded|relayed"
                r"|upstream|downstream).{0,15}?(?:agent|bot|model|assistant"
                r"|llm|ai\b|service)",
                re.IGNORECASE,
            ),
            # Pattern 2: the actual boundary — refuse to inherit another
            # agent's authority, or require authority to be re-verified per
            # request rather than transitively trusted. The attack surface
            # term alone ("another agent") is not a defense.
            re.compile(
                r"(?:(?:do not|never|must not).{0,30}?(?:execute|trust|act on"
                r"|obey|inherit).{0,40}?(?:another|other|forwarded|relayed"
                r"|external).{0,20}?(?:agent|bot|model|instruction|command"
                r"|request|source))"
                r"|(?:(?:authority|authorization|permission|principal)"
                r".{0,20}?(?:does not|do not|not).{0,20}?(?:inherit|transfer"
                r"|propagate))"
                r"|(?:(?:authority|authorization|permission).{0,30}?(?:verify"
                r"|check|re.?establish|each).{0,15}?(?:request|source"
                r"|independent))",
                re.IGNORECASE,
            ),
        ),
        min_matches=2,
    ),
    _DefenseRule(
        vector_id="transaction-guardrails",
        name="Financial Transaction Guardrails",
        owasp="ASI-02",
        patterns=(
            # Pattern 1: a value-moving capability is in scope. Deliberately
            # excludes a bare "token": it matches auth tokens (JWT / API /
            # bearer) far more often than value tokens, which combined with
            # P2's generic refusal clause produced a false positive on plain
            # authentication prompts. on-chain / wallet / crypto already cover
            # the value-token case.
            re.compile(
                r"\b(?:transaction|transfer|payment|withdraw|wallet|treasury"
                r"|payout|fund|funds)\b|(?:on.?chain|multi.?sig|multisig"
                r"|stable.?coin|crypto)",
                re.IGNORECASE,
            ),
            # Pattern 2: the guardrail — a limit/threshold, a second approval,
            # or an explicit refusal to move value without authorization. The
            # capability term alone ("transfer the funds") is the *attack*, not
            # the defense, so both patterns are required.
            re.compile(
                r"(?:(?:max(?:imum)?|limit|cap|threshold|hard.?limit).{0,30}?"
                r"(?:transaction|transfer|amount|value|spending|withdraw"
                r"|payout|wallet|funds))"
                r"|(?:(?:multi.?sig|multisig|second.{0,5}?confirmation|two.?step"
                r"|approval.{0,5}?required|policy.{0,5}?allows?).{0,30}?"
                r"(?:transaction|transfer|payment|withdraw|approval))"
                r"|(?:(?:never|do not|cannot|must not|refuse).{0,30}?(?:transfer"
                r"|spend|approve|withdraw).{0,40}?(?:without|unless|above"
                r"|exceed).{0,40}?(?:verif|approv|polic|threshold|limit|sign))"
                r"|(?:(?:transaction|transfer|payment|withdraw).{0,30}?(?:require"
                r"s?|must have|need).{0,20}?(?:approv|verif|sign|polic|confirm))",
                re.IGNORECASE,
            ),
        ),
        min_matches=2,
    ),
    _DefenseRule(
        vector_id="skill-provenance",
        name="Skill / Extension Provenance",
        owasp="ASI-04",
        patterns=(
            # Pattern 1: skills/tools tied to a trusted source — signed,
            # pinned, registry-policied, allow-listed.
            re.compile(
                r"(?:skill|extension|plugin|capability|action|tool|integration)"
                r".{0,30}?(?:signed|signature.?verified|provenance.?verified"
                r"|cryptographically.?verified|trusted source|pinned|hash"
                r"|registry policy|whitelist|allow.?list)",
                re.IGNORECASE,
            ),
            # Pattern 2: an explicit refusal to load/run unverified skills.
            # "load this plugin" without a provenance constraint is the
            # supply-chain attack, not a defense — require both.
            re.compile(
                r"(?:do not|never|must not|refuse to).{0,20}?(?:install|load"
                r"|execute|invoke|run).{0,30}?(?:skill|extension|plugin|tool"
                r"|integration).{0,30}?(?:unverified|unsigned|untrusted"
                r"|unknown source|external)",
                re.IGNORECASE,
            ),
        ),
        min_matches=2,
    ),
    _DefenseRule(
        vector_id="least-agency",
        name="Least Agency / Goal-Hijack Resistance",
        owasp="ASI-01",
        patterns=(
            # Pattern 1: least-privilege / least-agency framing.
            re.compile(
                r"(?:minimum|least).{0,15}?(?:privilege|agency|autonomy"
                r"|capability|scope|permission)",
                re.IGNORECASE,
            ),
            # Pattern 2: action scoped to the assigned goal/task only.
            re.compile(
                r"(?:only|exclusively|solely).{0,20}?(?:within|scoped to"
                r"|limited to).{0,30}?(?:assigned|defined|original|stated)"
                r".{0,15}?(?:goal|task|objective|scope)",
                re.IGNORECASE,
            ),
            # Pattern 3: abort/escalate on goal drift — the behavioural half
            # of resisting goal hijack.
            re.compile(
                r"(?:abort|halt|stop|refuse|escalate).{0,20}?(?:if|when"
                r"|whenever).{0,20}?(?:goal|scope|task|objective).{0,15}?"
                r"(?:drift|change|expand|exceeds?|outside)",
                re.IGNORECASE,
            ),
        ),
        min_matches=2,
    ),
    _DefenseRule(
        vector_id="encoding-injection",
        name="Encoding-aware Indirect Injection",
        owasp="ASI-01",
        patterns=(
            # Pattern 1: the prompt acknowledges decoded/translated content
            # (base64, cipher, translation) as an attack surface.
            re.compile(
                r"\b(?:decod(?:e|ed|ing)|deciphered|translated|base64|morse"
                r"|rot13|cipher|encoded)\b",
                re.IGNORECASE,
            ),
            # Pattern 2: the rule that decoded content is *data, never a
            # command*. Merely mentioning "base64" is not a defense; the
            # treat-as-data constraint is.
            re.compile(
                r"(?:(?:do not|never|must not).{0,40}?(?:execute|follow|act on"
                r"|obey|trust).{0,60}?(?:decoded|translated|deciphered|encoded"
                r"|cipher))"
                # Require an explicit untrusted/never-a-command constraint —
                # "as untrusted", "never as a command" — not a bare "as input"
                # or "as content", which is operational data-pipeline language
                # ("handle encoded JSON as input"), not a security control.
                r"|(?:(?:treat|consider|handle).{0,30}?(?:decoded|translated"
                r"|encoded|deciphered).{0,40}?(?:as untrusted|untrusted data"
                r"|never as|not as a command|not as an instruction"
                r"|as data only|as inert))"
                r"|(?:(?:decoded|translated|deciphered|encoded).{0,40}?(?:not"
                r"|never).{0,40}?(?:command|instruction|executed|followed"
                r"|obeyed))",
                re.IGNORECASE,
            ),
        ),
        min_matches=2,
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
    vectors: Optional[list[str]] = None  # None = all 17
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
            # Agent-era (OWASP ASI) vectors.
            "cross-agent-auth": "high",
            "transaction-guardrails": "critical",
            "skill-provenance": "high",
            "least-agency": "high",
            "encoding-injection": "high",
        }
    )


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------


class PromptDefenseEvaluator:
    """Evaluates system prompts for missing defenses against 17 attack vectors.

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
            # Confidence reflects the strength of the signal we have,
            # not the assertion we're making. The previous scheme
            # claimed 0.8 ("high") confidence when zero patterns
            # matched and 0.4 ("low") when a partial match was seen —
            # an inversion of how confidence usually maps to evidence.
            # A complete absence of defense language is the weakest
            # possible signal, not the strongest; we can't tell from
            # zero matches whether the defense is missing or whether
            # the prompt simply uses different vocabulary.
            #
            #   matched >= min_matches  → high (scales with matches)
            #   0 < matched < min       → medium (we see some defense
            #                                     language but not enough)
            #   matched == 0            → low (no signal either way)
            if defended:
                confidence = min(0.9, 0.5 + matched * 0.2)
            elif matched > 0:
                confidence = 0.5
            else:
                confidence = 0.3
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
