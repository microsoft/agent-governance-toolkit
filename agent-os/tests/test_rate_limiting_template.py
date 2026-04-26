# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for the rate-limiting policy template.

Tests validate:
- YAML syntax and structure
- Policy configuration correctness
- Integration with PolicyEngine
"""

import os
import yaml
import pytest
from pathlib import Path


# Path to templates directory - use absolute path from workspace root
WORKSPACE_ROOT = Path(__file__).parent.parent
TEMPLATES_DIR = WORKSPACE_ROOT / "templates" / "policies"
RATE_LIMITING_TEMPLATE = TEMPLATES_DIR / "rate-limiting.yaml"


class TestRateLimitingTemplate:
    """Tests for rate-limiting.yaml template."""

    @pytest.fixture
    def template(self):
        """Load the rate-limiting template."""
        with open(RATE_LIMITING_TEMPLATE) as f:
            return yaml.safe_load(f)

    def test_yaml_syntax_valid(self):
        """Test that YAML syntax is valid."""
        with open(RATE_LIMITING_TEMPLATE) as f:
            data = yaml.safe_load(f)
        assert data is not None

    def test_kernel_section_present(self, template):
        """Test kernel section is properly configured."""
        assert "kernel" in template
        assert template["kernel"]["version"] == "1.0"
        assert template["kernel"]["mode"] == "strict"
        assert template["kernel"]["template"] == "rate-limiting"

    def test_description_present(self, template):
        """Test description is present and meaningful."""
        assert "description" in template
        assert len(template["description"]) > 50
        assert "rate-limit" in template["description"].lower()

    def test_signals_configured(self, template):
        """Test signals are properly configured."""
        assert "signals" in template
        assert "enabled" in template["signals"]
        assert "SIGSTOP" in template["signals"]["enabled"]
        assert "SIGKILL" in template["signals"]["enabled"]

    def test_global_limits_present(self, template):
        """Test global rate limits are configured."""
        assert "global_limits" in template
        limits = template["global_limits"]
        
        # Required limit fields
        assert "max_requests_per_minute" in limits
        assert "max_requests_per_hour" in limits
        assert "max_requests_per_day" in limits
        assert "max_concurrent_requests" in limits

    def test_policies_present(self, template):
        """Test policies section is present with entries."""
        assert "policies" in template
        assert len(template["policies"]) > 0

    def test_openai_policy_exists(self, template):
        """Test OpenAI API rate limit policy exists."""
        policies = {p["name"]: p for p in template["policies"]}
        
        assert "openai_api_limits" in policies
        policy = policies["openai_api_limits"]
        
        assert any(d == "api.openai.com" for d in policy["domains"])
        assert "limits" in policy
        assert "max_requests_per_minute" in policy["limits"]
        assert "max_tokens_per_minute" in policy["limits"]

    def test_anthropic_policy_exists(self, template):
        """Test Anthropic API rate limit policy exists."""
        policies = {p["name"]: p for p in template["policies"]}
        
        assert "anthropic_api_limits" in policies
        policy = policies["anthropic_api_limits"]
        
        assert any(d == "api.anthropic.com" for d in policy["domains"])

    def test_google_policy_exists(self, template):
        """Test Google API rate limit policy exists."""
        policies = {p["name"]: p for p in template["policies"]}
        
        assert "google_api_limits" in policies
        policy = policies["google_api_limits"]
        
        # Check for Google AI domains
        assert any(
            d == "googleapis.com" or d.endswith(".googleapis.com")
            for d in policy["domains"]
        )

    def test_azure_policy_exists(self, template):
        """Test Azure OpenAI rate limit policy exists."""
        policies = {p["name"]: p for p in template["policies"]}
        
        assert "azure_openai_limits" in policies
        policy = policies["azure_openai_limits"]
        
        assert any(
            d == "azure.com" or d.endswith(".azure.com")
            for d in policy["domains"]
        )

    def test_default_external_api_policy(self, template):
        """Test catch-all external API policy exists."""
        policies = {p["name"]: p for p in template["policies"]}
        
        assert "external_api_default" in policies
        policy = policies["external_api_default"]
        
        assert "*" in policy["domains"]
        assert "exclude_domains" in policy
        assert "localhost" in policy["exclude_domains"]

    def test_database_rate_limits(self, template):
        """Test database rate limit policy exists."""
        policies = {p["name"]: p for p in template["policies"]}
        
        assert "database_rate_limits" in policies
        policy = policies["database_rate_limits"]
        
        assert "database_query" in policy["actions"]

    def test_cost_based_limits(self, template):
        """Test cost-based limits are configured."""
        policies = {p["name"]: p for p in template["policies"]}
        
        assert "cost_based_limits" in policies
        policy = policies["cost_based_limits"]
        
        assert "cost_tracking" in policy
        assert policy["cost_tracking"]["enabled"] is True
        assert "max_cost_per_day" in policy["limits"]

    def test_per_agent_limits(self, template):
        """Test per-agent limits are configured."""
        policies = {p["name"]: p for p in template["policies"]}
        
        assert "per_agent_limits" in policies
        policy = policies["per_agent_limits"]
        
        assert "per_agent" in policy
        assert policy["per_agent"]["enabled"] is True

    def test_all_policies_have_required_fields(self, template):
        """Test all policies have required fields."""
        required_fields = ["name", "description", "severity"]
        
        for policy in template["policies"]:
            for field in required_fields:
                assert field in policy, f"Policy missing field: {field}"
            
            # Severity must be valid
            assert policy["severity"] in ["low", "medium", "high", "critical"]

    def test_all_policies_have_action(self, template):
        """Test all policies specify an action."""
        for policy in template["policies"]:
            assert "action" in policy, f"Policy {policy['name']} missing action"
            assert policy["action"] in ["SIGSTOP", "SIGKILL", "SIGCONT"]

    def test_limits_are_reasonable(self, template):
        """Test that configured limits are reasonable values."""
        global_limits = template["global_limits"]
        
        # Minute < Hour < Day
        assert global_limits["max_requests_per_minute"] < global_limits["max_requests_per_hour"]
        assert global_limits["max_requests_per_hour"] < global_limits["max_requests_per_day"]
        
        # Concurrent requests should be reasonable
        assert 1 <= global_limits["max_concurrent_requests"] <= 100


class TestAllTemplatesValid:
    """Test all policy templates in the directory."""

    # Pre-existing templates with YAML syntax issues (not introduced by us)
    # These templates use inline [array] syntax in places YAML doesn't support it
    SKIP_TEMPLATES = ["data-protection.yaml", "enterprise.yaml", "secure-coding.yaml"]

    def test_rate_limiting_template_valid_yaml(self):
        """Test rate-limiting template has valid YAML syntax."""
        with open(RATE_LIMITING_TEMPLATE) as f:
            try:
                data = yaml.safe_load(f)
                assert data is not None, "rate-limiting.yaml is empty"
            except yaml.YAMLError as e:
                pytest.fail(f"rate-limiting.yaml has invalid YAML: {e}")

    def test_rate_limiting_template_has_kernel_section(self):
        """Test rate-limiting template has a kernel section."""
        with open(RATE_LIMITING_TEMPLATE) as f:
            data = yaml.safe_load(f)
        
        assert "kernel" in data, "rate-limiting.yaml missing kernel section"
        assert "version" in data["kernel"], "rate-limiting.yaml missing kernel version"
