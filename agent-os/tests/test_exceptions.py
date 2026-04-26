# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the Agent OS exception hierarchy."""

import pytest

from agent_os.exceptions import (
    AgentOSError,
    PolicyError,
    PolicyViolationError,
    PolicyDeniedError,
    PolicyTimeoutError,
    BudgetError,
    BudgetExceededError,
    BudgetWarningError,
    IdentityError,
    IdentityVerificationError,
    CredentialExpiredError,
    IntegrationError,
    AdapterNotFoundError,
    AdapterTimeoutError,
    ConfigurationError,
    InvalidPolicyError,
    MissingConfigError,
    RateLimitError,
)


# --- Hierarchy tests ---

class TestExceptionHierarchy:
    """Verify the inheritance chain for all exception classes."""

    def test_base_inherits_from_exception(self):
        assert issubclass(AgentOSError, Exception)

    @pytest.mark.parametrize("cls", [
        PolicyError, BudgetError, IdentityError,
        IntegrationError, ConfigurationError, RateLimitError,
    ])
    def test_mid_level_inherits_from_base(self, cls):
        assert issubclass(cls, AgentOSError)

    @pytest.mark.parametrize("cls,parent", [
        (PolicyViolationError, PolicyError),
        (PolicyDeniedError, PolicyError),
        (PolicyTimeoutError, PolicyError),
        (BudgetExceededError, BudgetError),
        (BudgetWarningError, BudgetError),
        (IdentityVerificationError, IdentityError),
        (CredentialExpiredError, IdentityError),
        (AdapterNotFoundError, IntegrationError),
        (AdapterTimeoutError, IntegrationError),
        (InvalidPolicyError, ConfigurationError),
        (MissingConfigError, ConfigurationError),
    ])
    def test_leaf_inherits_from_parent(self, cls, parent):
        assert issubclass(cls, parent)
        assert issubclass(cls, AgentOSError)

    def test_rate_limit_is_leaf_and_base(self):
        assert issubclass(RateLimitError, AgentOSError)


# --- Error code defaults ---

class TestErrorCodeDefaults:
    """Each exception should have a sensible default error_code."""

    @pytest.mark.parametrize("cls,expected_code", [
        (AgentOSError, "AGENT_OS_ERROR"),
        (PolicyError, "POLICY_ERROR"),
        (PolicyViolationError, "POLICY_VIOLATION"),
        (PolicyDeniedError, "POLICY_DENIED"),
        (PolicyTimeoutError, "POLICY_TIMEOUT"),
        (BudgetError, "BUDGET_ERROR"),
        (BudgetExceededError, "BUDGET_EXCEEDED"),
        (BudgetWarningError, "BUDGET_WARNING"),
        (IdentityError, "IDENTITY_ERROR"),
        (IdentityVerificationError, "IDENTITY_VERIFICATION_FAILED"),
        (CredentialExpiredError, "CREDENTIAL_EXPIRED"),
        (IntegrationError, "INTEGRATION_ERROR"),
        (AdapterNotFoundError, "ADAPTER_NOT_FOUND"),
        (AdapterTimeoutError, "ADAPTER_TIMEOUT"),
        (ConfigurationError, "CONFIGURATION_ERROR"),
        (InvalidPolicyError, "INVALID_POLICY"),
        (MissingConfigError, "MISSING_CONFIG"),
        (RateLimitError, "RATE_LIMIT_EXCEEDED"),
    ])
    def test_default_error_code(self, cls, expected_code):
        err = cls("test message")
        assert err.error_code == expected_code

    def test_custom_error_code_overrides_default(self):
        err = PolicyViolationError("oops", error_code="CUSTOM_CODE")
        assert err.error_code == "CUSTOM_CODE"


# --- to_dict() ---

class TestToDict:
    """The to_dict method should return a structured dict."""

    def test_to_dict_keys(self):
        err = AgentOSError("something broke")
        d = err.to_dict()
        assert set(d.keys()) == {"error", "message", "details", "timestamp"}

    def test_to_dict_values(self):
        err = BudgetExceededError("over limit", details={"used": 100, "max": 50})
        d = err.to_dict()
        assert d["error"] == "BUDGET_EXCEEDED"
        assert d["message"] == "over limit"
        assert d["details"] == {"used": 100, "max": 50}
        assert isinstance(d["timestamp"], str)

    def test_to_dict_empty_details(self):
        err = RateLimitError("slow down")
        d = err.to_dict()
        assert d["details"] == {}

    def test_timestamp_is_iso_format(self):
        err = AgentOSError("ts check")
        # ISO format: YYYY-MM-DDTHH:MM:SS.ffffff
        ts = err.to_dict()["timestamp"]
        assert "T" in ts
        assert len(ts) >= 19  # minimum: 2024-01-01T00:00:00


# --- Details propagation ---

class TestDetailsPropagation:
    """Details dict should propagate through the hierarchy."""

    def test_details_default_empty(self):
        err = PolicyError("msg")
        assert err.details == {}

    def test_details_passed_through(self):
        details = {"policy": "budget", "limit": 1000}
        err = BudgetExceededError("exceeded", details=details)
        assert err.details == details
        assert err.details["policy"] == "budget"

    def test_details_on_leaf_exception(self):
        details = {"adapter": "langchain", "timeout_ms": 5000}
        err = AdapterTimeoutError("timed out", details=details)
        assert err.details == details

    def test_details_not_shared_between_instances(self):
        err1 = PolicyViolationError("a")
        err2 = PolicyViolationError("b")
        err1.details["key"] = "val"
        assert "key" not in err2.details


# --- isinstance checks ---

class TestIsInstanceChecks:
    """Catching a parent should also catch child exceptions."""

    def test_catch_agent_os_error_catches_policy(self):
        err = PolicyViolationError("denied")
        assert isinstance(err, AgentOSError)
        assert isinstance(err, PolicyError)
        assert isinstance(err, PolicyViolationError)

    def test_catch_budget_error_catches_exceeded(self):
        err = BudgetExceededError("over")
        assert isinstance(err, AgentOSError)
        assert isinstance(err, BudgetError)

    def test_policy_not_instance_of_budget(self):
        err = PolicyViolationError("x")
        assert not isinstance(err, BudgetError)

    def test_raise_and_catch_parent(self):
        with pytest.raises(AgentOSError):
            raise AdapterNotFoundError("no adapter")

    def test_raise_and_catch_mid_level(self):
        with pytest.raises(IntegrationError):
            raise AdapterTimeoutError("timeout")

    def test_raise_and_catch_exact(self):
        with pytest.raises(CredentialExpiredError):
            raise CredentialExpiredError("expired")


# --- Message propagation ---

class TestMessagePropagation:
    """str(err) should return the message."""

    def test_str_returns_message(self):
        err = MissingConfigError("config file not found")
        assert str(err) == "config file not found"

    def test_message_in_args(self):
        err = InvalidPolicyError("bad policy def")
        assert err.args[0] == "bad policy def"


# --- Backward compatibility with base.py ---

class TestBackwardCompatibility:
    """PolicyViolationError imported from base.py should be the same class."""

    def test_base_import_is_same_class(self):
        from agent_os.integrations.base import PolicyViolationError as BasePVE
        assert BasePVE is PolicyViolationError

    def test_integrations_init_import(self):
        from agent_os.integrations import PolicyViolationError as InitPVE
        assert InitPVE is PolicyViolationError
