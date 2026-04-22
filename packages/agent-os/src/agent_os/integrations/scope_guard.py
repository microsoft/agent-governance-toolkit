# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Scope Guard — prevents agent actions from exceeding configured scope limits.

Evaluates file count, line count, and scope drift against per-agent
configuration to produce PASS / SOFT_FAIL / HARD_FAIL decisions.
Integrates with the PolicyEngine for governance audit trails.

Usage::

    from agent_os.integrations.scope_guard import ScopeGuard, ScopeConfig

    config = ScopeConfig(max_files=10, max_lines=500)
    guard = ScopeGuard()
    result = guard.evaluate(
        agent_id="implementer",
        config=config,
        changed_files=["src/main.py", "tests/test_main.py"],
        insertions=120,
        deletions=30,
    )
    print(result.decision)  # "PASS"
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class ScopeConfig:
    """Per-agent scope configuration.

    Attributes:
        max_files: Maximum number of files an agent may change.
        max_lines: Maximum total lines (insertions + deletions) allowed.
        mode: Guard mode — ``"on"`` (default) to enforce, ``"off"`` to skip.
        drift_detection: Whether to evaluate drift indicators.
    """

    max_files: int = 10
    max_lines: int = 500
    mode: str = "on"
    drift_detection: bool = True


@dataclass
class ScopeEvaluation:
    """Result of a scope guard evaluation.

    Attributes:
        decision: One of ``"PASS"``, ``"SOFT_FAIL"``, ``"HARD_FAIL"``.
        files_changed: Number of files changed.
        lines_changed: Total lines changed (insertions + deletions).
        max_files: Configured file limit.
        max_lines: Configured line limit.
        drift_indicators: Drift indicator dicts passed in for audit.
        reason: Human-readable explanation of the decision.
        excess_files: File paths that exceed the file limit.
    """

    decision: str
    files_changed: int
    lines_changed: int
    max_files: int
    max_lines: int
    drift_indicators: list[dict[str, Any]] = field(default_factory=list)
    reason: str = ""
    excess_files: list[str] = field(default_factory=list)


def _escalate(current: str, proposed: str) -> str:
    """Return the more severe of two decisions."""
    severity = {"PASS": 0, "SOFT_FAIL": 1, "HARD_FAIL": 2}
    if severity.get(proposed, 0) > severity.get(current, 0):
        return proposed
    return current


def _get_diff_stats(
    repo_path: str, base_branch: str = "main"
) -> tuple[list[str], int, int]:
    """Return ``(changed_files, insertions, deletions)`` via ``git diff --numstat``.

    Args:
        repo_path: Path to a git repository or worktree.
        base_branch: Branch to diff against.

    Returns:
        Tuple of (file paths, total insertions, total deletions).
    """
    try:
        result = subprocess.run(  # noqa: S603 — trusted subprocess in scope guard
            ["git", "diff", "--numstat", base_branch],  # noqa: S607 — known CLI tool path
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        logger.warning("_get_diff_stats failed: %s", exc)
        return [], 0, 0

    files: list[str] = []
    insertions = 0
    deletions = 0
    for line in result.stdout.strip().splitlines():
        parts = line.split("\t")
        if len(parts) == 3:
            ins = int(parts[0]) if parts[0] != "-" else 0
            dels = int(parts[1]) if parts[1] != "-" else 0
            insertions += ins
            deletions += dels
            files.append(parts[2])
    return files, insertions, deletions


class ScopeGuard:
    """Evaluates whether agent changes are within configured scope limits.

    Optionally records governance audit events through a *policy_engine*.
    The policy engine, when provided, must expose a
    ``record_event(event: dict)`` method.

    Args:
        policy_engine: Optional governance policy engine for audit trails.
    """

    def __init__(self, policy_engine: Optional[Any] = None) -> None:
        self._policy_engine = policy_engine

    # ── public API ──────────────────────────────────────────

    def evaluate(
        self,
        agent_id: str,
        config: ScopeConfig,
        changed_files: list[str],
        insertions: int,
        deletions: int,
        drift_indicators: Optional[list[dict[str, Any]]] = None,
    ) -> ScopeEvaluation:
        """Evaluate whether an agent's changes are within scope.

        Decision logic:
            1. ``config.mode == "off"`` → always ``PASS``.
            2. files > ``max_files × 2`` **or** lines > ``max_lines × 2`` → ``HARD_FAIL``.
            3. files > ``max_files`` **or** lines > ``max_lines`` → ``SOFT_FAIL``.
            4. Any drift indicator with ``severity == "warning"`` → ``SOFT_FAIL``.
            5. Otherwise → ``PASS``.

        Args:
            agent_id: Unique agent identifier.
            config: Scope configuration for this agent.
            changed_files: List of changed file paths.
            insertions: Total lines added.
            deletions: Total lines removed.
            drift_indicators: Optional list of drift indicator dicts.  Each
                dict may contain ``severity`` (``"info"`` | ``"warning"``).

        Returns:
            A :class:`ScopeEvaluation` with the decision and supporting data.
        """
        max_files = config.max_files
        max_lines = config.max_lines
        files_changed = len(changed_files)
        lines_changed = insertions + deletions
        drift_indicators = drift_indicators or []

        # Mode "off" → always pass
        if config.mode == "off":
            evaluation = ScopeEvaluation(
                decision="PASS",
                files_changed=files_changed,
                lines_changed=lines_changed,
                max_files=max_files,
                max_lines=max_lines,
                reason="Scope guard disabled (mode=off)",
            )
            self._record(agent_id, evaluation)
            return evaluation

        reasons: list[str] = []
        decision = "PASS"

        # Check file count
        if max_files > 0 and files_changed > max_files:
            if files_changed > max_files * 2:
                decision = "HARD_FAIL"
                reasons.append(
                    f"files changed ({files_changed}) exceeds 2× limit "
                    f"({max_files * 2})"
                )
            else:
                decision = _escalate(decision, "SOFT_FAIL")
                reasons.append(
                    f"files changed ({files_changed}) exceeds limit ({max_files})"
                )

        # Check line count
        if max_lines > 0 and lines_changed > max_lines:
            if lines_changed > max_lines * 2:
                decision = "HARD_FAIL"
                reasons.append(
                    f"lines changed ({lines_changed}) exceeds 2× limit "
                    f"({max_lines * 2})"
                )
            else:
                decision = _escalate(decision, "SOFT_FAIL")
                reasons.append(
                    f"lines changed ({lines_changed}) exceeds limit ({max_lines})"
                )

        # Check drift indicators
        if config.drift_detection and drift_indicators:
            warnings = [
                d for d in drift_indicators if d.get("severity") == "warning"
            ]
            if warnings:
                decision = _escalate(decision, "SOFT_FAIL")
                reasons.append(
                    f"{len(warnings)} scope drift warning(s) detected"
                )

        # Excess files for downstream remediation
        excess_files: list[str] = []
        if max_files > 0 and files_changed > max_files:
            excess_files = changed_files[max_files:]

        reason = "; ".join(reasons) if reasons else "All scope checks passed"

        evaluation = ScopeEvaluation(
            decision=decision,
            files_changed=files_changed,
            lines_changed=lines_changed,
            max_files=max_files,
            max_lines=max_lines,
            drift_indicators=drift_indicators,
            reason=reason,
            excess_files=excess_files,
        )

        self._record(agent_id, evaluation)
        return evaluation

    def evaluate_from_git(
        self,
        agent_id: str,
        config: ScopeConfig,
        repo_path: str,
        base_branch: str = "main",
        drift_indicators: Optional[list[dict[str, Any]]] = None,
    ) -> ScopeEvaluation:
        """Convenience wrapper that reads diff stats from *repo_path*.

        Args:
            agent_id: Unique agent identifier.
            config: Scope configuration.
            repo_path: Path to the git repository.
            base_branch: Branch to diff against (default ``"main"``).
            drift_indicators: Optional drift indicator dicts.

        Returns:
            A :class:`ScopeEvaluation`.
        """
        changed_files, insertions, deletions = _get_diff_stats(
            repo_path, base_branch
        )
        return self.evaluate(
            agent_id=agent_id,
            config=config,
            changed_files=changed_files,
            insertions=insertions,
            deletions=deletions,
            drift_indicators=drift_indicators,
        )

    # ── internal helpers ────────────────────────────────────

    def _record(self, agent_id: str, evaluation: ScopeEvaluation) -> None:
        """Record the evaluation as an audit event if a policy engine is set."""
        if self._policy_engine is None:
            return
        try:
            self._policy_engine.record_event(
                {
                    "type": "scope_evaluation",
                    "agent_id": agent_id,
                    "decision": evaluation.decision,
                    "files_changed": evaluation.files_changed,
                    "max_files": evaluation.max_files,
                    "lines_changed": evaluation.lines_changed,
                    "max_lines": evaluation.max_lines,
                    "reason": evaluation.reason,
                }
            )
        except Exception:  # pragma: no cover — best-effort audit
            logger.exception("Failed to record scope evaluation event")
