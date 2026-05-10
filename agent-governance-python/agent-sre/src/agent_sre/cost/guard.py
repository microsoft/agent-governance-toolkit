# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""Cost guard — budget management and simple threshold alerting for agents."""

from __future__ import annotations

import math
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class BudgetAction(Enum):
    """Action to take when budget threshold is hit."""

    ALERT = "alert"
    THROTTLE = "throttle"
    KILL = "kill"


class CostAlertSeverity(Enum):
    """Severity of a cost alert."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class CostRecord:
    """A single cost event."""

    agent_id: str
    task_id: str
    cost_usd: float
    timestamp: float = field(default_factory=time.time)
    breakdown: dict[str, float] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "task_id": self.task_id,
            "cost_usd": self.cost_usd,
            "timestamp": self.timestamp,
            "breakdown": self.breakdown,
        }


@dataclass
class CostAlert:
    """A cost alert."""

    severity: CostAlertSeverity
    message: str
    agent_id: str = ""
    current_value: float = 0.0
    threshold: float = 0.0
    timestamp: float = field(default_factory=time.time)
    action: BudgetAction = BudgetAction.ALERT

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity.value,
            "message": self.message,
            "agent_id": self.agent_id,
            "current_value": self.current_value,
            "threshold": self.threshold,
            "action": self.action.value,
        }


@dataclass
class AgentBudget:
    """Budget configuration for a single agent."""

    agent_id: str
    daily_limit_usd: float = 100.0
    per_task_limit_usd: float = 2.0
    spent_today_usd: float = 0.0
    task_count_today: int = 0
    throttled: bool = False
    killed: bool = False

    @property
    def remaining_today_usd(self) -> float:
        return max(0.0, self.daily_limit_usd - self.spent_today_usd)

    @property
    def utilization_percent(self) -> float:
        if self.daily_limit_usd <= 0:
            return 0.0
        return (self.spent_today_usd / self.daily_limit_usd) * 100

    @property
    def avg_cost_per_task(self) -> float:
        if self.task_count_today <= 0:
            return 0.0
        return self.spent_today_usd / self.task_count_today

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "daily_limit_usd": self.daily_limit_usd,
            "per_task_limit_usd": self.per_task_limit_usd,
            "spent_today_usd": round(self.spent_today_usd, 4),
            "remaining_today_usd": round(self.remaining_today_usd, 4),
            "utilization_percent": round(self.utilization_percent, 1),
            "task_count_today": self.task_count_today,
            "avg_cost_per_task": round(self.avg_cost_per_task, 4),
            "throttled": self.throttled,
            "killed": self.killed,
        }


class CostGuard:
    """Cost tracking, budgeting, and anomaly detection.

    Tracks per-task and per-agent costs, enforces budgets,
    detects anomalies, and can auto-throttle or kill agents.
    """

    def __init__(
        self,
        per_task_limit: float = 2.0,
        per_agent_daily_limit: float = 100.0,
        org_monthly_budget: float = 5000.0,
        anomaly_detection: bool = True,
        auto_throttle: bool = True,
        kill_switch_threshold: float = 0.95,
        alert_thresholds: list[float] | None = None,
    ) -> None:
        # Validate numeric inputs before any assignment to prevent
        # partially-initialized objects with corrupt state (NaN/Inf/negative).
        if not math.isfinite(org_monthly_budget) or org_monthly_budget < 0:
            raise ValueError(f"org_monthly_budget must be finite and non-negative, got {org_monthly_budget}")
        if not math.isfinite(per_task_limit) or per_task_limit < 0:
            raise ValueError(f"per_task_limit must be finite and non-negative, got {per_task_limit}")
        if not math.isfinite(per_agent_daily_limit) or per_agent_daily_limit < 0:
            raise ValueError(f"per_agent_daily_limit must be finite and non-negative, got {per_agent_daily_limit}")
        if not math.isfinite(kill_switch_threshold) or not (0.0 <= kill_switch_threshold <= 1.0):
            raise ValueError(
                f"kill_switch_threshold must be finite and in [0.0, 1.0], got {kill_switch_threshold}"
            )
        resolved_thresholds = alert_thresholds if alert_thresholds is not None else [0.50, 0.75, 0.90, 0.95]
        for i, t in enumerate(resolved_thresholds):
            if not math.isfinite(t) or not (0.0 <= t <= 1.0):
                raise ValueError(
                    f"alert_thresholds[{i}] must be finite and in [0.0, 1.0], got {t}"
                )

        self.per_task_limit = per_task_limit
        self.per_agent_daily_limit = per_agent_daily_limit
        self.org_monthly_budget = org_monthly_budget
        self.anomaly_detection = anomaly_detection
        self.auto_throttle = auto_throttle
        self.kill_switch_threshold = kill_switch_threshold
        self.alert_thresholds = resolved_thresholds

        self._budgets: dict[str, AgentBudget] = {}
        self._records: list[CostRecord] = []
        self._alerts: list[CostAlert] = []
        self._cost_history: deque[float] = deque(maxlen=1000)
        self._org_spent_month: float = 0.0
        self._org_killed: bool = False
        self._lock = threading.Lock()

    def get_budget(self, agent_id: str) -> AgentBudget:
        """Get or create budget for an agent."""
        with self._lock:
            return self._get_or_create_budget_locked(agent_id)

    def _get_or_create_budget_locked(self, agent_id: str) -> AgentBudget:
        """Caller must hold ``self._lock``."""
        if agent_id not in self._budgets:
            self._budgets[agent_id] = AgentBudget(
                agent_id=agent_id,
                daily_limit_usd=self.per_agent_daily_limit,
                per_task_limit_usd=self.per_task_limit,
            )
        return self._budgets[agent_id]

    def check_task(self, agent_id: str, estimated_cost: float = 0.0) -> tuple[bool, str]:
        """Check if a task should be allowed to proceed.

        Returns (allowed, reason).

        WARNING — this is an advisory check. ``check_task`` does NOT
        reserve budget, so two concurrent callers that both pass the
        check can both proceed and overshoot the limit. For
        budget-critical paths use :meth:`check_and_charge` instead,
        which atomically combines the check with the cost reservation
        under a single lock.
        """
        if not math.isfinite(estimated_cost):
            return False, f"Invalid estimated cost: {estimated_cost}"
        if estimated_cost < 0:
            return False, f"Invalid negative estimated cost: {estimated_cost}"

        with self._lock:
            allowed, reason = self._check_locked(agent_id, estimated_cost)
            return allowed, reason

    def _check_locked(
        self, agent_id: str, estimated_cost: float
    ) -> tuple[bool, str]:
        """Caller must hold ``self._lock``. Pure check; no mutation."""
        if self._org_killed:
            return False, "Organization budget exhausted"

        budget = self._get_or_create_budget_locked(agent_id)

        if budget.killed:
            return False, "Agent killed — budget exhausted"

        if budget.throttled:
            return False, "Agent throttled — approaching daily limit"

        if estimated_cost > self.per_task_limit:
            return False, f"Estimated cost ${estimated_cost:.2f} exceeds per-task limit ${self.per_task_limit:.2f}"

        if budget.spent_today_usd + estimated_cost > budget.daily_limit_usd:
            remaining = max(0.0, budget.daily_limit_usd - budget.spent_today_usd)
            return False, f"Would exceed daily budget (${remaining:.2f} remaining)"

        if self.org_monthly_budget > 0:
            if self._org_spent_month + estimated_cost > self.org_monthly_budget:
                org_remaining = max(0.0, self.org_monthly_budget - self._org_spent_month)
                return False, (
                    f"Would exceed org monthly budget "
                    f"(${org_remaining:.2f} remaining)"
                )

        return True, "ok"

    def check_and_charge(
        self,
        agent_id: str,
        task_id: str,
        cost_usd: float,
        breakdown: dict[str, float] | None = None,
    ) -> tuple[bool, str, list[CostAlert]]:
        """Atomically check budget and record a cost.

        Combines :meth:`check_task` and :meth:`record_cost` in a
        single locked transaction so two concurrent callers cannot
        both pass the check and both record costs that overshoot the
        limit. This is the correct primitive for any path that needs
        budget enforcement to actually hold under concurrency.

        Returns:
            ``(allowed, reason, alerts)``. When ``allowed`` is
            ``False``, ``alerts`` is an empty list and no cost was
            recorded; the caller should not proceed with the work.
            When ``allowed`` is ``True``, the cost has already been
            charged and any threshold/anomaly alerts are returned.
        """
        if not math.isfinite(cost_usd):
            raise ValueError(f"cost_usd must be finite, got {cost_usd}")
        if cost_usd < 0:
            raise ValueError(f"cost_usd must be non-negative, got {cost_usd}")

        with self._lock:
            allowed, reason = self._check_locked(agent_id, cost_usd)
            if not allowed:
                return False, reason, []
            alerts = self._record_cost_locked(
                agent_id=agent_id,
                task_id=task_id,
                cost_usd=cost_usd,
                breakdown=breakdown,
            )
            return True, reason, alerts

    def record_cost(
        self,
        agent_id: str,
        task_id: str,
        cost_usd: float,
        breakdown: dict[str, float] | None = None,
    ) -> list[CostAlert]:
        """Record a task cost and check budgets.

        Returns any alerts triggered.

        WARNING — this method records cost unconditionally; it does
        NOT check budgets first. For budget-critical paths use
        :meth:`check_and_charge`.
        """
        if not math.isfinite(cost_usd):
            raise ValueError(f"cost_usd must be finite, got {cost_usd}")
        if cost_usd < 0:
            raise ValueError(f"cost_usd must be non-negative, got {cost_usd}")

        with self._lock:
            return self._record_cost_locked(
                agent_id=agent_id,
                task_id=task_id,
                cost_usd=cost_usd,
                breakdown=breakdown,
            )

    def _record_cost_locked(
        self,
        agent_id: str,
        task_id: str,
        cost_usd: float,
        breakdown: dict[str, float] | None = None,
    ) -> list[CostAlert]:
        """Caller must hold ``self._lock``. Recording + alerts only."""
        alerts: list[CostAlert] = []
        record = CostRecord(
            agent_id=agent_id,
            task_id=task_id,
            cost_usd=cost_usd,
            breakdown=breakdown or {},
        )

        if True:  # preserved indent for minimal diff against the prior body
            budget = self._get_or_create_budget_locked(agent_id)
            self._records.append(record)
            self._cost_history.append(cost_usd)

            # Update budget and org spend atomically.
            prev_spent = budget.spent_today_usd
            budget.spent_today_usd += cost_usd
            budget.task_count_today += 1
            prev_org_spent = self._org_spent_month
            self._org_spent_month += cost_usd

            # Per-task limit check
            if cost_usd > self.per_task_limit:
                alerts.append(CostAlert(
                    severity=CostAlertSeverity.WARNING,
                    message=f"Task cost ${cost_usd:.2f} exceeded per-task limit ${self.per_task_limit:.2f}",
                    agent_id=agent_id,
                    current_value=cost_usd,
                    threshold=self.per_task_limit,
                ))

            # Daily budget threshold alerts
            utilization = (
                budget.spent_today_usd / budget.daily_limit_usd
                if budget.daily_limit_usd > 0 else 0.0
            )
            prev_util = (
                prev_spent / budget.daily_limit_usd if budget.daily_limit_usd > 0 else 0.0
            )
            for threshold in self.alert_thresholds:
                if prev_util < threshold <= utilization:
                    severity = CostAlertSeverity.CRITICAL if threshold >= 0.90 else CostAlertSeverity.WARNING
                    alerts.append(CostAlert(
                        severity=severity,
                        message=f"Agent {agent_id} at {utilization * 100:.0f}% daily budget",
                        agent_id=agent_id,
                        current_value=budget.spent_today_usd,
                        threshold=budget.daily_limit_usd * threshold,
                    ))

            # Auto-throttle
            if self.auto_throttle and utilization >= self.kill_switch_threshold:
                budget.killed = True
                alerts.append(CostAlert(
                    severity=CostAlertSeverity.CRITICAL,
                    message=f"Agent {agent_id} KILLED — {utilization * 100:.0f}% budget consumed",
                    agent_id=agent_id,
                    current_value=budget.spent_today_usd,
                    threshold=budget.daily_limit_usd * self.kill_switch_threshold,
                    action=BudgetAction.KILL,
                ))
            elif self.auto_throttle and utilization >= 0.85:
                budget.throttled = True
                alerts.append(CostAlert(
                    severity=CostAlertSeverity.WARNING,
                    message=f"Agent {agent_id} THROTTLED — {utilization * 100:.0f}% budget consumed",
                    agent_id=agent_id,
                    current_value=budget.spent_today_usd,
                    threshold=budget.daily_limit_usd * 0.85,
                    action=BudgetAction.THROTTLE,
                ))

            # Org budget kill alert
            if self.auto_throttle and self.org_monthly_budget > 0:
                org_util = self._org_spent_month / self.org_monthly_budget
                prev_org_util = prev_org_spent / self.org_monthly_budget
                if prev_org_util < self.kill_switch_threshold <= org_util:
                    self._org_killed = True
                    for b in self._budgets.values():
                        b.killed = True
                    alerts.append(CostAlert(
                        severity=CostAlertSeverity.CRITICAL,
                        message=(
                            f"Org budget kill switch triggered -- "
                            f"{org_util * 100:.0f}% of monthly budget consumed"
                        ),
                        agent_id=agent_id,
                        current_value=self._org_spent_month,
                        threshold=self.org_monthly_budget * self.kill_switch_threshold,
                        action=BudgetAction.KILL,
                    ))

            # Anomaly detection
            if self.anomaly_detection and len(self._cost_history) >= 10:
                anomaly_alert = self._check_anomaly_locked(agent_id, cost_usd)
                if anomaly_alert:
                    alerts.append(anomaly_alert)

            self._alerts.extend(alerts)

        return alerts

    def _check_anomaly_locked(self, agent_id: str, cost_usd: float) -> CostAlert | None:
        """Check if a cost is anomalous using Z-score. Caller must hold ``self._lock``."""
        history = list(self._cost_history)
        if len(history) < 10:
            return None

        mean = sum(history) / len(history)
        variance = sum((x - mean) ** 2 for x in history) / len(history)
        std_dev = math.sqrt(variance) if variance > 0 else 0.0

        if std_dev == 0:
            return None

        z_score = (cost_usd - mean) / std_dev
        if z_score > 2.0:
            return CostAlert(
                severity=CostAlertSeverity.WARNING,
                message=f"Anomalous cost detected: ${cost_usd:.4f} (z-score: {z_score:.1f}, mean: ${mean:.4f})",
                agent_id=agent_id,
                current_value=cost_usd,
                threshold=mean + 2 * std_dev,
            )
        return None

    def reset_daily(self, agent_id: str | None = None) -> None:
        """Reset daily budgets (call at start of each day)."""
        with self._lock:
            targets = [agent_id] if agent_id else list(self._budgets.keys())
            for aid in targets:
                if aid in self._budgets:
                    budget = self._budgets[aid]
                    budget.spent_today_usd = 0.0
                    budget.task_count_today = 0
                    budget.throttled = False
                    budget.killed = False

    @property
    def org_spent_month(self) -> float:
        with self._lock:
            return self._org_spent_month

    @property
    def org_remaining_month(self) -> float:
        with self._lock:
            return max(0.0, self.org_monthly_budget - self._org_spent_month)

    @property
    def alerts(self) -> list[CostAlert]:
        with self._lock:
            return list(self._alerts)

    def summary(self) -> dict[str, Any]:
        """Get cost summary across all agents."""
        with self._lock:
            return {
                "org_monthly_budget": self.org_monthly_budget,
                "org_spent_month": round(self._org_spent_month, 4),
                "org_remaining_month": round(max(0.0, self.org_monthly_budget - self._org_spent_month), 4),
                "total_records": len(self._records),
                "total_alerts": len(self._alerts),
                "agents": {aid: b.to_dict() for aid, b in self._budgets.items()},
            }
