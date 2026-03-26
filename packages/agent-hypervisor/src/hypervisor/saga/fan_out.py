# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""
Parallel Saga Fan-Out — stub implementation.

Public Preview: only sequential ALL_MUST_SUCCEED execution.
Fan-out groups execute branches one at a time.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from hypervisor.saga.state_machine import SagaStep, StepState


class FanOutPolicy(str, Enum):
    ALL_MUST_SUCCEED = "all_must_succeed"
    MAJORITY_MUST_SUCCEED = "majority_must_succeed"
    ANY_MUST_SUCCEED = "any_must_succeed"


@dataclass
class FanOutBranch:
    branch_id: str = field(default_factory=lambda: f"branch:{uuid.uuid4().hex[:8]}")
    step: SagaStep | None = None
    result: Any = None
    error: str | None = None
    succeeded: bool = False


@dataclass
class FanOutGroup:
    group_id: str = field(default_factory=lambda: f"fanout:{uuid.uuid4().hex[:8]}")
    saga_id: str = ""
    policy: FanOutPolicy = FanOutPolicy.ALL_MUST_SUCCEED
    branches: list[FanOutBranch] = field(default_factory=list)
    resolved: bool = False
    policy_satisfied: bool = False
    compensation_needed: list[str] = field(default_factory=list)

    @property
    def success_count(self) -> int:
        return sum(1 for b in self.branches if b.succeeded)

    @property
    def failure_count(self) -> int:
        return sum(1 for b in self.branches if not b.succeeded and b.error)

    @property
    def total_branches(self) -> int:
        return len(self.branches)

    def check_policy(self) -> bool:
        """Public Preview: only ALL_MUST_SUCCEED is enforced."""
        return self.success_count == self.total_branches


class FanOutOrchestrator:
    """Fan-out stub (Public Preview: sequential execution, ALL_MUST_SUCCEED only)."""

    def __init__(self) -> None:
        self._groups: dict[str, FanOutGroup] = {}

    def create_group(self, saga_id: str, policy: FanOutPolicy = FanOutPolicy.ALL_MUST_SUCCEED) -> FanOutGroup:
        group = FanOutGroup(saga_id=saga_id, policy=FanOutPolicy.ALL_MUST_SUCCEED)
        self._groups[group.group_id] = group
        return group

    def add_branch(self, group_id: str, step: SagaStep) -> FanOutBranch:
        group = self._get_group(group_id)
        branch = FanOutBranch(step=step)
        group.branches.append(branch)
        return branch

    async def execute(
        self, group_id: str, executors: dict[str, Callable[..., Any]], timeout_seconds: int = 300,
    ) -> FanOutGroup:
        """Execute branches sequentially (Public Preview)."""
        group = self._get_group(group_id)

        for branch in group.branches:
            if not branch.step:
                branch.error = "No step assigned"
                continue
            executor = executors.get(branch.step.step_id)
            if not executor:
                branch.error = f"No executor for step {branch.step.step_id}"
                continue
            try:
                branch.step.transition(StepState.EXECUTING)
                result = await asyncio.wait_for(executor(), timeout=branch.step.timeout_seconds)
                branch.result = result
                branch.succeeded = True
                branch.step.execute_result = result
                branch.step.transition(StepState.COMMITTED)
            except Exception as e:
                branch.error = str(e)
                branch.step.error = str(e)
                branch.step.transition(StepState.FAILED)
                break  # ALL_MUST_SUCCEED: stop on first failure

        group.policy_satisfied = group.check_policy()
        group.resolved = True
        if not group.policy_satisfied:
            group.compensation_needed = [b.step.step_id for b in group.branches if b.succeeded and b.step]
        return group

    def get_group(self, group_id: str) -> FanOutGroup | None:
        return self._groups.get(group_id)

    def _get_group(self, group_id: str) -> FanOutGroup:
        group = self._groups.get(group_id)
        if not group:
            raise ValueError(f"Fan-out group {group_id} not found")
        return group

    @property
    def active_groups(self) -> list[FanOutGroup]:
        return [g for g in self._groups.values() if not g.resolved]
