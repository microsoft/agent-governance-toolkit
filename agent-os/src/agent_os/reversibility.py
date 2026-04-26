# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Action reversibility assessment and compensation primitives.

Pre-execution check: is this action reversible? If not, require
additional approval or block entirely. Post-execution: provide
compensation actions to undo effects.

Addresses the criticism that AGT has no "rollback/reversibility
guarantees." Now every action can be assessed for reversibility
before execution, and compensation plans are generated for
irreversible operations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ReversibilityLevel(str, Enum):
    """How reversible an action is."""
    FULLY_REVERSIBLE = "fully_reversible"      # Can be undone completely (e.g., write a file)
    PARTIALLY_REVERSIBLE = "partially_reversible"  # Can be partially undone (e.g., send email — recall possible)
    IRREVERSIBLE = "irreversible"              # Cannot be undone (e.g., delete, deploy, send to external)
    UNKNOWN = "unknown"                        # Reversibility cannot be determined


class CompensatingAction(BaseModel):
    """An action that can undo or mitigate a previous action."""
    description: str
    action: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    effectiveness: str = Field(
        default="full",
        description="full, partial, or mitigation-only",
    )
    time_window: str = Field(
        default="",
        description="Time window in which compensation is possible (e.g., '30 minutes')",
    )


class ReversibilityAssessment(BaseModel):
    """Pre-execution assessment of an action's reversibility."""
    action: str
    level: ReversibilityLevel
    reason: str
    compensating_actions: list[CompensatingAction] = Field(default_factory=list)
    requires_extra_approval: bool = False
    assessed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# Default reversibility classifications
_REVERSIBILITY_MAP: dict[str, dict[str, Any]] = {
    # Fully reversible
    "write_file": {
        "level": ReversibilityLevel.FULLY_REVERSIBLE,
        "reason": "File writes can be reverted by restoring previous version",
        "compensating": [
            CompensatingAction(
                description="Restore previous file version",
                action="restore_file_backup",
                effectiveness="full",
            )
        ],
    },
    "create_file": {
        "level": ReversibilityLevel.FULLY_REVERSIBLE,
        "reason": "Created files can be deleted",
        "compensating": [
            CompensatingAction(
                description="Delete the created file",
                action="delete_file",
                effectiveness="full",
            )
        ],
    },
    "database_write": {
        "level": ReversibilityLevel.FULLY_REVERSIBLE,
        "reason": "Database writes can be rolled back within transaction",
        "compensating": [
            CompensatingAction(
                description="Rollback transaction",
                action="rollback_transaction",
                effectiveness="full",
                time_window="within transaction scope",
            )
        ],
    },
    "create_pr": {
        "level": ReversibilityLevel.FULLY_REVERSIBLE,
        "reason": "Pull requests can be closed",
        "compensating": [
            CompensatingAction(
                description="Close the pull request",
                action="close_pr",
                effectiveness="full",
            )
        ],
    },

    # Partially reversible
    "send_email": {
        "level": ReversibilityLevel.PARTIALLY_REVERSIBLE,
        "reason": "Email recall may work within org, but external delivery cannot be undone",
        "compensating": [
            CompensatingAction(
                description="Recall email (internal only)",
                action="recall_email",
                effectiveness="partial",
                time_window="30 minutes",
            ),
            CompensatingAction(
                description="Send correction/retraction",
                action="send_correction",
                effectiveness="mitigation-only",
            ),
        ],
    },
    "update_record": {
        "level": ReversibilityLevel.PARTIALLY_REVERSIBLE,
        "reason": "Previous value may be recoverable from audit log",
        "compensating": [
            CompensatingAction(
                description="Restore from audit trail",
                action="restore_from_audit",
                effectiveness="partial",
            )
        ],
    },

    # Irreversible
    "deploy": {
        "level": ReversibilityLevel.IRREVERSIBLE,
        "reason": "Production deployments affect live users immediately",
        "compensating": [
            CompensatingAction(
                description="Rollback deployment",
                action="rollback_deploy",
                effectiveness="partial",
                time_window="depends on deployment pipeline",
            )
        ],
        "requires_extra_approval": True,
    },
    "delete_file": {
        "level": ReversibilityLevel.IRREVERSIBLE,
        "reason": "Deleted files may not be recoverable without backups",
        "compensating": [
            CompensatingAction(
                description="Restore from backup if available",
                action="restore_from_backup",
                effectiveness="partial",
            )
        ],
        "requires_extra_approval": True,
    },
    "delete_record": {
        "level": ReversibilityLevel.IRREVERSIBLE,
        "reason": "Deleted records may not be recoverable",
        "compensating": [],
        "requires_extra_approval": True,
    },
    "execute_trade": {
        "level": ReversibilityLevel.IRREVERSIBLE,
        "reason": "Executed trades are settled and cannot be undone",
        "compensating": [
            CompensatingAction(
                description="Execute offsetting trade",
                action="offsetting_trade",
                effectiveness="mitigation-only",
            )
        ],
        "requires_extra_approval": True,
    },
    "ssh_connect": {
        "level": ReversibilityLevel.IRREVERSIBLE,
        "reason": "Remote commands may have irreversible effects",
        "compensating": [],
        "requires_extra_approval": True,
    },
    "execute_code": {
        "level": ReversibilityLevel.IRREVERSIBLE,
        "reason": "Arbitrary code execution effects are unpredictable",
        "compensating": [],
        "requires_extra_approval": True,
    },
}


class ReversibilityChecker:
    """Assess action reversibility before execution.

    Usage:
        checker = ReversibilityChecker()
        assessment = checker.assess("deploy")
        if assessment.level == ReversibilityLevel.IRREVERSIBLE:
            # require extra approval
            ...
    """

    def __init__(
        self,
        custom_rules: dict[str, dict[str, Any]] | None = None,
        block_irreversible: bool = False,
    ) -> None:
        self._rules = dict(_REVERSIBILITY_MAP)
        if custom_rules:
            self._rules.update(custom_rules)
        self._block_irreversible = block_irreversible

    def assess(self, action: str) -> ReversibilityAssessment:
        """Assess the reversibility of an action before execution."""
        rule = self._rules.get(action)

        if not rule:
            return ReversibilityAssessment(
                action=action,
                level=ReversibilityLevel.UNKNOWN,
                reason=f"No reversibility data for action '{action}'",
                requires_extra_approval=True,
            )

        return ReversibilityAssessment(
            action=action,
            level=rule["level"],
            reason=rule["reason"],
            compensating_actions=rule.get("compensating", []),
            requires_extra_approval=rule.get("requires_extra_approval", False),
        )

    def is_safe(self, action: str) -> bool:
        """Quick check: is this action safely reversible?"""
        assessment = self.assess(action)
        return assessment.level == ReversibilityLevel.FULLY_REVERSIBLE

    def should_block(self, action: str) -> bool:
        """Check if action should be blocked per policy."""
        if not self._block_irreversible:
            return False
        assessment = self.assess(action)
        return assessment.level == ReversibilityLevel.IRREVERSIBLE

    def get_compensation_plan(self, action: str) -> list[CompensatingAction]:
        """Get the compensation plan for an action."""
        assessment = self.assess(action)
        return assessment.compensating_actions
