# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Policy Templates for Common Governance Scenarios

Pre-built GovernancePolicy configurations for common use cases,
from maximum-security lockdown to permissive development environments.

Usage:
    from agent_os.integrations import PolicyTemplates

    policy = PolicyTemplates.strict()
    policy = PolicyTemplates.enterprise()
    policy = PolicyTemplates.custom(max_tokens=5000, require_human_approval=True)
"""

from .base import GovernancePolicy


class PolicyTemplates:
    """Factory class providing pre-built GovernancePolicy configurations."""

    @staticmethod
    def strict() -> GovernancePolicy:
        """Maximum security policy: deny all except allowlist.

        Suitable for high-risk environments where every action must be
        tightly controlled. Low token and tool-call limits, dangerous
        patterns blocked, and human approval required.
        """
        return GovernancePolicy(
            max_tokens=1000,
            max_tool_calls=3,
            allowed_tools=["read_file", "search", "list_files"],
            blocked_patterns=[
                "eval",
                "exec",
                "rm -rf",
                "DROP TABLE",
                "DELETE FROM",
                "subprocess",
                "os.system",
                "__import__",
            ],
            require_human_approval=True,
            timeout_seconds=60,
            confidence_threshold=0.95,
            drift_threshold=0.05,
            log_all_calls=True,
            checkpoint_frequency=1,
            max_concurrent=3,
            backpressure_threshold=2,
        )

    @staticmethod
    def permissive() -> GovernancePolicy:
        """Permissive policy for development and testing.

        High limits with no blocked patterns. All tools allowed.
        No human approval required. Useful for local development
        and experimentation.
        """
        return GovernancePolicy(
            max_tokens=100000,
            max_tool_calls=100,
            allowed_tools=[],
            blocked_patterns=[],
            require_human_approval=False,
            timeout_seconds=600,
            confidence_threshold=0.5,
            drift_threshold=0.5,
            log_all_calls=False,
            checkpoint_frequency=50,
            max_concurrent=50,
            backpressure_threshold=40,
        )

    @staticmethod
    def enterprise() -> GovernancePolicy:
        """Production enterprise policy with balanced defaults.

        Moderate limits with SQL injection and shell injection patterns
        blocked. Audit logging enabled. Suitable for production
        deployments that need a balance of safety and usability.
        """
        return GovernancePolicy(
            max_tokens=10000,
            max_tool_calls=20,
            allowed_tools=[],
            blocked_patterns=[
                "DROP TABLE",
                "DELETE FROM",
                "INSERT INTO",
                "UPDATE.*SET",
                "; --",
                "rm -rf",
                "os.system",
                "subprocess",
            ],
            require_human_approval=False,
            timeout_seconds=300,
            confidence_threshold=0.85,
            drift_threshold=0.10,
            log_all_calls=True,
            checkpoint_frequency=3,
            max_concurrent=10,
            backpressure_threshold=8,
        )

    @staticmethod
    def research() -> GovernancePolicy:
        """Research and academic policy with generous limits.

        Allows broad exploration but blocks destructive operations.
        Suitable for research environments where agents need freedom
        to experiment but must not cause damage.
        """
        return GovernancePolicy(
            max_tokens=50000,
            max_tool_calls=50,
            allowed_tools=[],
            blocked_patterns=[
                "rm -rf",
                "DROP TABLE",
                "DELETE FROM",
                "os.system",
                "subprocess",
            ],
            require_human_approval=False,
            timeout_seconds=600,
            confidence_threshold=0.7,
            drift_threshold=0.25,
            log_all_calls=True,
            checkpoint_frequency=10,
            max_concurrent=20,
            backpressure_threshold=15,
        )

    @staticmethod
    def minimal() -> GovernancePolicy:
        """Bare minimum governance: just a basic token cap.

        The lightest possible policy — only a token limit is enforced.
        All other settings use permissive defaults. Useful when you
        want governance scaffolding without restrictive controls.
        """
        return GovernancePolicy(
            max_tokens=4096,
            max_tool_calls=10,
            allowed_tools=[],
            blocked_patterns=[],
            require_human_approval=False,
            timeout_seconds=300,
            log_all_calls=False,
            checkpoint_frequency=5,
        )

    @staticmethod
    def custom(**kwargs) -> GovernancePolicy:
        """Create a custom policy by merging overrides onto default values.

        Any keyword argument accepted by GovernancePolicy can be provided.
        Unspecified fields fall back to GovernancePolicy defaults.

        Args:
            **kwargs: Fields to override on the GovernancePolicy dataclass.

        Returns:
            A GovernancePolicy instance with the given overrides applied.

        Example:
            policy = PolicyTemplates.custom(
                max_tokens=5000,
                require_human_approval=True,
                blocked_patterns=["eval", "exec"],
            )
        """
        return GovernancePolicy(**kwargs)
