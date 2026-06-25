# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""
Parallel Saga Fan-Out.

Executes a group of saga branches and resolves it against the group's
``FanOutPolicy`` (ALL / MAJORITY / ANY must succeed). Branches are run
sequentially but execution stops as soon as the policy outcome is decided
(e.g. ANY stops on the first success, ALL on the first failure).
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
        """True if the branch outcomes satisfy this group's policy.

        ALL: every branch succeeded (vacuously true with no branches).
        MAJORITY: a strict majority of branches succeeded.
        ANY: at least one branch succeeded.
        """
        total = self.total_branches
        if self.policy == FanOutPolicy.ALL_MUST_SUCCEED:
            return self.success_count == total
        if self.policy == FanOutPolicy.MAJORITY_MUST_SUCCEED:
            return self.success_count * 2 > total
        if self.policy == FanOutPolicy.ANY_MUST_SUCCEED:
            return self.success_count >= 1
        return False

    def is_decided(self) -> bool:
        """True once the resolved branches already determine ``check_policy``,
        so remaining branches need not run.

        ALL is decided on the first failure; ANY on the first success; MAJORITY
        once a majority has succeeded or become unreachable.
        """
        total = self.total_branches
        succ, fail = self.success_count, self.failure_count
        if self.policy == FanOutPolicy.ALL_MUST_SUCCEED:
            return fail >= 1
        if self.policy == FanOutPolicy.ANY_MUST_SUCCEED:
            return succ >= 1
        if self.policy == FanOutPolicy.MAJORITY_MUST_SUCCEED:
            return succ * 2 > total or fail * 2 >= total
        return False


class FanOutOrchestrator:
    """Runs fan-out branches and resolves the group against its ``FanOutPolicy``."""

    def __init__(self) -> None:
        self._groups: dict[str, FanOutGroup] = {}

    def create_group(
        self, saga_id: str, policy: FanOutPolicy = FanOutPolicy.ALL_MUST_SUCCEED
    ) -> FanOutGroup:
        group = FanOutGroup(saga_id=saga_id, policy=policy)
        self._groups[group.group_id] = group
        return group

    def add_branch(self, group_id: str, step: SagaStep) -> FanOutBranch:
        group = self._get_group(group_id)
        branch = FanOutBranch(step=step)
        group.branches.append(branch)
        return branch

    async def execute(
        self,
        group_id: str,
        executors: dict[str, Callable[..., Any]],
        timeout_seconds: int = 300,
    ) -> FanOutGroup:
        """Run branches until the group's policy outcome is decided.

        Branches run one at a time; after each resolves, execution stops early
        if ``is_decided`` (the policy can no longer change). Unrun branches stay
        PENDING. On an unsatisfied policy, every succeeded branch is queued for
        compensation.
        """
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
            if group.is_decided():
                break

        group.policy_satisfied = group.check_policy()
        group.resolved = True
        if not group.policy_satisfied:
            group.compensation_needed = [
                b.step.step_id for b in group.branches if b.succeeded and b.step
            ]
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
