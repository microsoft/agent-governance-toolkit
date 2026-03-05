# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Environment Variable Configuration

Centralized configuration loaded from environment variables with AGENT_OS_ prefix.
Provides a single source of truth for all Agent OS settings.
"""

import os
from dataclasses import dataclass, fields
from typing import Optional

from .base import GovernancePolicy


@dataclass
class AgentOSConfig:
    """Centralized configuration loaded from environment variables with AGENT_OS_ prefix."""

    # Policy defaults
    max_tokens: int = 10000
    max_tool_calls: int = 50
    log_level: str = "INFO"

    # Backend
    state_backend: str = "memory"  # memory, redis, dynamodb
    redis_url: str = "redis://localhost:6379"

    # Audit
    audit_enabled: bool = True
    audit_max_entries: int = 10000

    # Health
    health_check_timeout: float = 5.0

    # Rate limiting
    rate_limit_calls: int = 100
    rate_limit_window: int = 60

    # Webhooks
    webhook_timeout: float = 5.0
    webhook_retries: int = 3

    @classmethod
    def from_env(cls) -> "AgentOSConfig":
        """Load configuration from AGENT_OS_* environment variables."""
        kwargs = {}
        for f in fields(cls):
            env_key = f"AGENT_OS_{f.name.upper()}"
            val = os.environ.get(env_key)
            if val is not None:
                if f.type == "int" or f.type is int:
                    kwargs[f.name] = int(val)
                elif f.type == "float" or f.type is float:
                    kwargs[f.name] = float(val)
                elif f.type == "bool" or f.type is bool:
                    kwargs[f.name] = val.lower() in ("true", "1", "yes")
                else:
                    kwargs[f.name] = val
        return cls(**kwargs)

    def to_policy(self) -> GovernancePolicy:
        """Convert to a GovernancePolicy with these defaults."""
        return GovernancePolicy(
            max_tokens=self.max_tokens,
            max_tool_calls=self.max_tool_calls,
            log_all_calls=self.audit_enabled,
        )

    def to_dict(self) -> dict:
        """Serialize configuration to a dictionary."""
        return {f.name: getattr(self, f.name) for f in fields(self)}

    @classmethod
    def from_dict(cls, data: dict) -> "AgentOSConfig":
        """Deserialize configuration from a dictionary."""
        valid_keys = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)


# Singleton
_config: Optional[AgentOSConfig] = None


def get_config() -> AgentOSConfig:
    """Get or create the global configuration."""
    global _config
    if _config is None:
        _config = AgentOSConfig.from_env()
    return _config


def reset_config():
    """Reset global config (useful for testing)."""
    global _config
    _config = None
