# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent OS Exception Hierarchy

Standardized exceptions with error codes for all Agent OS components.
Each exception carries an error_code, optional details dict, and timestamp
for structured error handling and logging.
"""

from datetime import datetime, timezone


class AgentOSError(Exception):
    """Base exception for all Agent OS errors."""

    def __init__(self, message, error_code=None, details=None):
        super().__init__(message)
        self.error_code = error_code or "AGENT_OS_ERROR"
        self.details = details or {}
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self):
        return {
            "error": self.error_code,
            "message": str(self),
            "details": self.details,
            "timestamp": self.timestamp,
        }


# --- Policy errors ---

class PolicyError(AgentOSError):
    """Base exception for policy-related errors."""

    def __init__(self, message, error_code=None, details=None):
        super().__init__(message, error_code or "POLICY_ERROR", details)


class PolicyViolationError(PolicyError):
    """Raised when a governance policy check fails."""

    def __init__(self, message, error_code=None, details=None):
        super().__init__(message, error_code or "POLICY_VIOLATION", details)


class PolicyDeniedError(PolicyError):
    """Raised when a policy explicitly denies an action."""

    def __init__(self, message, error_code=None, details=None):
        super().__init__(message, error_code or "POLICY_DENIED", details)


class PolicyTimeoutError(PolicyError):
    """Raised when a policy evaluation times out."""

    def __init__(self, message, error_code=None, details=None):
        super().__init__(message, error_code or "POLICY_TIMEOUT", details)


# --- Budget errors ---

class BudgetError(AgentOSError):
    """Base exception for budget-related errors."""

    def __init__(self, message, error_code=None, details=None):
        super().__init__(message, error_code or "BUDGET_ERROR", details)


class BudgetExceededError(BudgetError):
    """Raised when a budget limit is exceeded."""

    def __init__(self, message, error_code=None, details=None):
        super().__init__(message, error_code or "BUDGET_EXCEEDED", details)


class BudgetWarningError(BudgetError):
    """Raised when approaching a budget limit."""

    def __init__(self, message, error_code=None, details=None):
        super().__init__(message, error_code or "BUDGET_WARNING", details)


# --- Identity errors ---

class IdentityError(AgentOSError):
    """Base exception for identity-related errors."""

    def __init__(self, message, error_code=None, details=None):
        super().__init__(message, error_code or "IDENTITY_ERROR", details)


class IdentityVerificationError(IdentityError):
    """Raised when identity verification fails."""

    def __init__(self, message, error_code=None, details=None):
        super().__init__(message, error_code or "IDENTITY_VERIFICATION_FAILED", details)


class CredentialExpiredError(IdentityError):
    """Raised when credentials have expired."""

    def __init__(self, message, error_code=None, details=None):
        super().__init__(message, error_code or "CREDENTIAL_EXPIRED", details)


# --- Integration errors ---

class IntegrationError(AgentOSError):
    """Base exception for integration-related errors."""

    def __init__(self, message, error_code=None, details=None):
        super().__init__(message, error_code or "INTEGRATION_ERROR", details)


class AdapterNotFoundError(IntegrationError):
    """Raised when a requested adapter is not found."""

    def __init__(self, message, error_code=None, details=None):
        super().__init__(message, error_code or "ADAPTER_NOT_FOUND", details)


class AdapterTimeoutError(IntegrationError):
    """Raised when an adapter operation times out."""

    def __init__(self, message, error_code=None, details=None):
        super().__init__(message, error_code or "ADAPTER_TIMEOUT", details)


# --- Configuration errors ---

class ConfigurationError(AgentOSError):
    """Base exception for configuration-related errors."""

    def __init__(self, message, error_code=None, details=None):
        super().__init__(message, error_code or "CONFIGURATION_ERROR", details)


class InvalidPolicyError(ConfigurationError):
    """Raised when a policy definition is invalid."""

    def __init__(self, message, error_code=None, details=None):
        super().__init__(message, error_code or "INVALID_POLICY", details)


class MissingConfigError(ConfigurationError):
    """Raised when required configuration is missing."""

    def __init__(self, message, error_code=None, details=None):
        super().__init__(message, error_code or "MISSING_CONFIG", details)


# --- Rate limit errors ---

class RateLimitError(AgentOSError):
    """Raised when a rate limit is hit."""

    def __init__(self, message, error_code=None, details=None):
        super().__init__(message, error_code or "RATE_LIMIT_EXCEEDED", details)


# --- Security errors ---


class SecurityError(AgentOSError):
    """Raised when a sandbox security violation is detected."""

    def __init__(self, message, error_code=None, details=None):
        super().__init__(message, error_code or "SECURITY_VIOLATION", details)


# --- Serialization errors ---


class SerializationError(AgentOSError):
    """Raised when state serialization or deserialization fails."""

    def __init__(self, message, error_code=None, details=None):
        super().__init__(message, error_code or "SERIALIZATION_ERROR", details)
