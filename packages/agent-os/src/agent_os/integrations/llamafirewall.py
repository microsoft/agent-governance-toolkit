# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""LlamaFirewall integration adapter — chain Meta's LlamaFirewall with Agent OS for defense-in-depth."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from agent_os.prompt_injection import (
    DetectionConfig,
    DetectionResult,
    PromptInjectionDetector,
    ThreatLevel,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class FirewallMode(Enum):
    """Operating mode for the combined firewall."""
    LLAMAFIREWALL_ONLY = "llamafirewall_only"
    AGENT_OS_ONLY = "agent_os_only"
    CHAIN_BOTH = "chain_both"
    VOTE_MAJORITY = "vote_majority"


class FirewallVerdict(Enum):
    """Unified verdict across scanners."""
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    BLOCKED = "blocked"
    ERROR = "error"


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class FirewallResult:
    """Combined result from LlamaFirewall and/or Agent OS scanning."""
    verdict: FirewallVerdict
    source: str  # "llamafirewall", "agent_os", "combined"
    score: float  # 0.0 (safe) to 1.0 (blocked)
    details: dict[str, Any] = field(default_factory=dict)
    prompt_guard_result: dict[str, Any] | None = None
    alignment_check_result: dict[str, Any] | None = None
    code_shield_result: dict[str, Any] | None = None
    agent_os_result: DetectionResult | None = None


# ---------------------------------------------------------------------------
# LlamaFirewallAdapter
# ---------------------------------------------------------------------------

class LlamaFirewallAdapter:
    """Adapter that chains Meta's LlamaFirewall with Agent OS prompt injection detection.

    Usage::

        adapter = LlamaFirewallAdapter(mode=FirewallMode.CHAIN_BOTH)
        result = await adapter.scan_prompt("ignore previous instructions")
        if result.verdict == FirewallVerdict.BLOCKED:
            print("Blocked!")
    """

    def __init__(
        self,
        mode: FirewallMode = FirewallMode.CHAIN_BOTH,
        agent_os_config: DetectionConfig | None = None,
    ) -> None:
        self._mode = mode
        self._detector = PromptInjectionDetector(config=agent_os_config)
        self._llama_available = False

        # Lazy import of llamafirewall
        try:
            import llamafirewall  # noqa: F401
            self._llama_available = True
        except ImportError:
            self._llama_available = False

        # Fallback if llama is required but not installed
        if mode in (FirewallMode.LLAMAFIREWALL_ONLY, FirewallMode.CHAIN_BOTH, FirewallMode.VOTE_MAJORITY):
            if not self._llama_available:
                logger.warning(
                    "llamafirewall package not installed — falling back to AGENT_OS_ONLY mode"
                )
                if mode == FirewallMode.LLAMAFIREWALL_ONLY:
                    self._mode = FirewallMode.AGENT_OS_ONLY

    # -- public API ---------------------------------------------------------

    async def scan_prompt(
        self,
        prompt: str,
        context: str | None = None,
    ) -> FirewallResult:
        """Scan a prompt using the configured mode (async)."""
        mode = self._mode

        if mode == FirewallMode.AGENT_OS_ONLY:
            aos_result = self._run_agent_os(prompt)
            return self._combine_results(None, aos_result, mode)

        if mode == FirewallMode.LLAMAFIREWALL_ONLY:
            llama_result = self._run_llamafirewall(prompt, context)
            return self._combine_results(llama_result, None, mode)

        # CHAIN_BOTH or VOTE_MAJORITY — run both
        llama_result = self._run_llamafirewall(prompt, context) if self._llama_available else None
        aos_result = self._run_agent_os(prompt)
        return self._combine_results(llama_result, aos_result, mode)

    def scan_prompt_sync(
        self,
        prompt: str,
        context: str | None = None,
    ) -> FirewallResult:
        """Scan a prompt using the configured mode (synchronous)."""
        mode = self._mode

        if mode == FirewallMode.AGENT_OS_ONLY:
            aos_result = self._run_agent_os(prompt)
            return self._combine_results(None, aos_result, mode)

        if mode == FirewallMode.LLAMAFIREWALL_ONLY:
            llama_result = self._run_llamafirewall(prompt, context)
            return self._combine_results(llama_result, None, mode)

        # CHAIN_BOTH or VOTE_MAJORITY
        llama_result = self._run_llamafirewall(prompt, context) if self._llama_available else None
        aos_result = self._run_agent_os(prompt)
        return self._combine_results(llama_result, aos_result, mode)

    async def scan_code(
        self,
        code: str,
        language: str = "python",
    ) -> FirewallResult:
        """Scan code using CodeShield if available, otherwise return SAFE with warning."""
        if not self._llama_available:
            return FirewallResult(
                verdict=FirewallVerdict.SAFE,
                source="agent_os",
                score=0.0,
                details={"warning": "CodeShield not available — llamafirewall not installed"},
            )

        try:
            from llamafirewall import CodeShield  # type: ignore[import-untyped]
            shield = CodeShield()
            result = shield.scan(code, language=language)
            verdict = self._map_llama_verdict(result.get("verdict", "safe"))
            return FirewallResult(
                verdict=verdict,
                source="llamafirewall",
                score=result.get("score", 0.0),
                details={"language": language},
                code_shield_result=result,
            )
        except ImportError:
            return FirewallResult(
                verdict=FirewallVerdict.SAFE,
                source="agent_os",
                score=0.0,
                details={"warning": "CodeShield import failed"},
            )
        except Exception as exc:
            logger.error("CodeShield scan error: %s", exc, exc_info=True)
            return FirewallResult(
                verdict=FirewallVerdict.ERROR,
                source="llamafirewall",
                score=0.0,
                details={"error": str(exc)},
            )

    # -- internal scanners --------------------------------------------------

    def _run_llamafirewall(
        self,
        prompt: str,
        context: str | None = None,
    ) -> dict[str, Any]:
        """Call LlamaFirewall's scan API with graceful error handling."""
        try:
            from llamafirewall import LlamaFirewall as LF  # type: ignore[import-untyped]
            fw = LF()
            result = fw.scan(prompt, context=context)
            return {
                "verdict": result.get("verdict", "safe"),
                "score": result.get("score", 0.0),
                "prompt_guard": result.get("prompt_guard"),
                "alignment_check": result.get("alignment_check"),
            }
        except ImportError:
            logger.warning("llamafirewall not importable — returning empty result")
            return {"verdict": "error", "score": 0.0, "error": "import_failed"}
        except Exception as exc:
            logger.error("LlamaFirewall scan error: %s", exc, exc_info=True)
            return {"verdict": "error", "score": 0.0, "error": str(exc)}

    def _run_agent_os(self, prompt: str) -> DetectionResult:
        """Run Agent OS PromptInjectionDetector — always available."""
        return self._detector.detect(prompt, source="llamafirewall_adapter")

    # -- result combination -------------------------------------------------

    def _combine_results(
        self,
        llama_result: dict[str, Any] | None,
        aos_result: DetectionResult | None,
        mode: FirewallMode,
    ) -> FirewallResult:
        """Merge results from both scanners based on the operating mode."""
        llama_score = llama_result.get("score", 0.0) if llama_result else 0.0
        llama_verdict_str = llama_result.get("verdict", "safe") if llama_result else "safe"
        llama_verdict = self._map_llama_verdict(llama_verdict_str)

        aos_score = aos_result.confidence if aos_result else 0.0
        aos_verdict = self._agent_os_verdict(aos_result) if aos_result else FirewallVerdict.SAFE

        # Single-scanner modes
        if mode == FirewallMode.AGENT_OS_ONLY:
            return FirewallResult(
                verdict=aos_verdict,
                source="agent_os",
                score=aos_score,
                details={"mode": mode.value},
                agent_os_result=aos_result,
            )

        if mode == FirewallMode.LLAMAFIREWALL_ONLY:
            return FirewallResult(
                verdict=llama_verdict,
                source="llamafirewall",
                score=llama_score,
                details={"mode": mode.value},
                prompt_guard_result=llama_result.get("prompt_guard") if llama_result else None,
                alignment_check_result=llama_result.get("alignment_check") if llama_result else None,
            )

        # CHAIN_BOTH: block if either blocks, use max score (most conservative)
        if mode == FirewallMode.CHAIN_BOTH:
            combined_score = max(llama_score, aos_score)
            if llama_verdict == FirewallVerdict.BLOCKED or aos_verdict == FirewallVerdict.BLOCKED:
                combined_verdict = FirewallVerdict.BLOCKED
            elif llama_verdict == FirewallVerdict.SUSPICIOUS or aos_verdict == FirewallVerdict.SUSPICIOUS:
                combined_verdict = FirewallVerdict.SUSPICIOUS
            elif llama_verdict == FirewallVerdict.ERROR or aos_verdict == FirewallVerdict.ERROR:
                combined_verdict = FirewallVerdict.ERROR
            else:
                combined_verdict = FirewallVerdict.SAFE

            return FirewallResult(
                verdict=combined_verdict,
                source="combined",
                score=combined_score,
                details={"mode": mode.value, "llama_verdict": llama_verdict_str, "aos_verdict": aos_verdict.value},
                prompt_guard_result=llama_result.get("prompt_guard") if llama_result else None,
                alignment_check_result=llama_result.get("alignment_check") if llama_result else None,
                agent_os_result=aos_result,
            )

        # VOTE_MAJORITY: require both to agree for block, use average score
        if mode == FirewallMode.VOTE_MAJORITY:
            combined_score = (llama_score + aos_score) / 2.0
            block_votes = sum([
                llama_verdict == FirewallVerdict.BLOCKED,
                aos_verdict == FirewallVerdict.BLOCKED,
            ])
            if block_votes >= 2:
                combined_verdict = FirewallVerdict.BLOCKED
            elif block_votes == 1:
                combined_verdict = FirewallVerdict.SUSPICIOUS
            else:
                combined_verdict = FirewallVerdict.SAFE

            return FirewallResult(
                verdict=combined_verdict,
                source="combined",
                score=combined_score,
                details={
                    "mode": mode.value,
                    "block_votes": block_votes,
                    "llama_verdict": llama_verdict_str,
                    "aos_verdict": aos_verdict.value,
                },
                prompt_guard_result=llama_result.get("prompt_guard") if llama_result else None,
                alignment_check_result=llama_result.get("alignment_check") if llama_result else None,
                agent_os_result=aos_result,
            )

        # Fallback (should not reach here)
        return FirewallResult(
            verdict=FirewallVerdict.ERROR,
            source="combined",
            score=0.0,
            details={"error": f"unknown mode: {mode}"},
        )

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _map_llama_verdict(verdict_str: str) -> FirewallVerdict:
        """Map LlamaFirewall string verdict to FirewallVerdict."""
        mapping = {
            "safe": FirewallVerdict.SAFE,
            "suspicious": FirewallVerdict.SUSPICIOUS,
            "blocked": FirewallVerdict.BLOCKED,
            "error": FirewallVerdict.ERROR,
            "malicious": FirewallVerdict.BLOCKED,
            "benign": FirewallVerdict.SAFE,
        }
        return mapping.get(verdict_str.lower(), FirewallVerdict.SUSPICIOUS)

    @staticmethod
    def _agent_os_verdict(result: DetectionResult) -> FirewallVerdict:
        """Map Agent OS DetectionResult to FirewallVerdict."""
        if not result.is_injection:
            return FirewallVerdict.SAFE
        if result.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
            return FirewallVerdict.BLOCKED
        return FirewallVerdict.SUSPICIOUS

    @property
    def available_scanners(self) -> list[str]:
        """Return list of active scanner names."""
        scanners: list[str] = []
        if self._mode in (FirewallMode.AGENT_OS_ONLY, FirewallMode.CHAIN_BOTH, FirewallMode.VOTE_MAJORITY):
            scanners.append("agent_os")
        if self._llama_available and self._mode in (
            FirewallMode.LLAMAFIREWALL_ONLY, FirewallMode.CHAIN_BOTH, FirewallMode.VOTE_MAJORITY,
        ):
            scanners.append("llamafirewall")
        return scanners
