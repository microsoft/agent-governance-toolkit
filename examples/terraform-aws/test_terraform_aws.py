# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Structural tests for examples/terraform-aws.

Validates HCL structure, required resources, variable definitions, output
declarations, and AGT governance config correctness without running
terraform apply or requiring cloud credentials.
"""

from __future__ import annotations

import re
from pathlib import Path

import hcl2
import pytest

EXAMPLE_DIR = Path(__file__).parent

# ── HCL fixtures ─────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def main_tf() -> dict:
    with open(EXAMPLE_DIR / "main.tf") as f:
        return hcl2.load(f)


@pytest.fixture(scope="module")
def variables_tf() -> dict:
    with open(EXAMPLE_DIR / "variables.tf") as f:
        return hcl2.load(f)


@pytest.fixture(scope="module")
def outputs_tf() -> dict:
    with open(EXAMPLE_DIR / "outputs.tf") as f:
        return hcl2.load(f)


# ── File existence ────────────────────────────────────────────────────────────


class TestFilesExist:
    def test_main_tf_exists(self):
        assert (EXAMPLE_DIR / "main.tf").exists()

    def test_variables_tf_exists(self):
        assert (EXAMPLE_DIR / "variables.tf").exists()

    def test_outputs_tf_exists(self):
        assert (EXAMPLE_DIR / "outputs.tf").exists()

    def test_readme_exists(self):
        assert (EXAMPLE_DIR / "README.md").exists()


# ── Terraform block ───────────────────────────────────────────────────────────


class TestTerraformBlock:
    def test_required_version_present(self, main_tf):
        tf_blocks = main_tf.get("terraform", [])
        assert tf_blocks, "terraform block missing from main.tf"
        block = tf_blocks[0]
        assert "required_version" in block, "required_version missing from terraform block"

    def test_required_version_is_1_5_or_higher(self, main_tf):
        version_constraint = main_tf["terraform"][0]["required_version"]
        assert "1.5" in version_constraint or "1.6" in version_constraint or ">=" in version_constraint

    def test_aws_provider_declared(self, main_tf):
        providers = main_tf.get("terraform", [{}])[0].get("required_providers", [{}])[0]
        assert "aws" in providers, "aws provider missing from required_providers"

    def test_random_provider_declared(self, main_tf):
        providers = main_tf.get("terraform", [{}])[0].get("required_providers", [{}])[0]
        assert "random" in providers, "random provider missing from required_providers"

    def test_aws_provider_version_constraint(self, main_tf):
        providers = main_tf["terraform"][0]["required_providers"][0]
        aws_version = providers["aws"].get("version", "")
        assert ">= 5.0" in aws_version or "~> 5" in aws_version, (
            f"aws provider version constraint should pin to >= 5.0, got: {aws_version}"
        )


# ── Required AWS resources ────────────────────────────────────────────────────


class TestRequiredResources:
    def _resource_names(self, main_tf: dict, resource_type: str) -> list[str]:
        # hcl2 wraps resource type keys in quotes: '"aws_vpc"'
        key = f'"{resource_type}"'
        names = []
        for block in main_tf.get("resource", []):
            if key in block:
                names.extend(block[key].keys())
        return names

    def test_vpc_present(self, main_tf):
        assert self._resource_names(main_tf, "aws_vpc"), "aws_vpc resource missing"

    def test_private_subnets_present(self, main_tf):
        assert self._resource_names(main_tf, "aws_subnet"), "aws_subnet resources missing"

    def test_nat_gateway_present(self, main_tf):
        assert self._resource_names(main_tf, "aws_nat_gateway"), "aws_nat_gateway missing — agents need outbound access"

    def test_security_group_present(self, main_tf):
        assert self._resource_names(main_tf, "aws_security_group"), "aws_security_group missing"

    def test_kms_key_present(self, main_tf):
        assert self._resource_names(main_tf, "aws_kms_key"), "aws_kms_key missing — required for receipt signing"

    def test_s3_bucket_present(self, main_tf):
        assert self._resource_names(main_tf, "aws_s3_bucket"), "aws_s3_bucket missing — required for audit logs"

    def test_iam_role_present(self, main_tf):
        assert self._resource_names(main_tf, "aws_iam_role"), "aws_iam_role missing — agents need least-privilege role"

    def test_iam_policy_present(self, main_tf):
        assert self._resource_names(main_tf, "aws_iam_policy"), "aws_iam_policy missing"

    def test_secrets_manager_secret_present(self, main_tf):
        assert self._resource_names(main_tf, "aws_secretsmanager_secret"), (
            "aws_secretsmanager_secret missing — required for Ed25519 signing key"
        )

    def test_cloudwatch_log_group_present(self, main_tf):
        assert self._resource_names(main_tf, "aws_cloudwatch_log_group"), (
            "aws_cloudwatch_log_group missing — required for governance events"
        )

    def test_instance_profile_present(self, main_tf):
        assert self._resource_names(main_tf, "aws_iam_instance_profile"), "aws_iam_instance_profile missing"


# ── SSM parameters — AGT governance config ───────────────────────────────────


class TestSSMParameters:
    """All AGT_* governance config values must be stored as SSM parameters."""

    EXPECTED_PARAMS = {
        "trust_level",
        "max_tool_calls",
        "rate_limit_rpm",
        "audit_enabled",
        "kill_switch_enabled",
        "audit_bucket",
    }

    def _ssm_param_names(self, main_tf: dict) -> set[str]:
        names = set()
        for block in main_tf.get("resource", []):
            if '"aws_ssm_parameter"' in block:
                names.update(k.strip('"') for k in block['"aws_ssm_parameter"'].keys())
        return names

    def test_all_agt_params_present(self, main_tf):
        found = self._ssm_param_names(main_tf)
        missing = self.EXPECTED_PARAMS - found
        assert not missing, f"SSM parameters missing for AGT config keys: {missing}"

    def test_trust_level_param_present(self, main_tf):
        assert "trust_level" in self._ssm_param_names(main_tf)

    def test_max_tool_calls_param_present(self, main_tf):
        assert "max_tool_calls" in self._ssm_param_names(main_tf)

    def test_audit_enabled_param_present(self, main_tf):
        assert "audit_enabled" in self._ssm_param_names(main_tf)

    def test_kill_switch_param_present(self, main_tf):
        assert "kill_switch_enabled" in self._ssm_param_names(main_tf)

    def test_audit_bucket_param_present(self, main_tf):
        assert "audit_bucket" in self._ssm_param_names(main_tf)


# ── S3 security hardening ─────────────────────────────────────────────────────


class TestS3Security:
    def test_public_access_block_present(self, main_tf):
        found = any(
            '"aws_s3_bucket_public_access_block"' in block
            for block in main_tf.get("resource", [])
        )
        assert found, "aws_s3_bucket_public_access_block missing — S3 bucket must block public access"

    def test_bucket_versioning_present(self, main_tf):
        found = any(
            '"aws_s3_bucket_versioning"' in block
            for block in main_tf.get("resource", [])
        )
        assert found, "aws_s3_bucket_versioning missing — audit logs must be versioned"

    def test_bucket_encryption_present(self, main_tf):
        found = any(
            '"aws_s3_bucket_server_side_encryption_configuration"' in block
            for block in main_tf.get("resource", [])
        )
        assert found, "S3 server-side encryption missing — audit logs must be KMS-encrypted"

    def test_bucket_lifecycle_present(self, main_tf):
        found = any(
            '"aws_s3_bucket_lifecycle_configuration"' in block
            for block in main_tf.get("resource", [])
        )
        assert found, "S3 lifecycle configuration missing — audit log retention tiers required"

    def test_bucket_policy_present(self, main_tf):
        found = any(
            '"aws_s3_bucket_policy"' in block
            for block in main_tf.get("resource", [])
        )
        assert found, "aws_s3_bucket_policy missing — TLS enforcement policy required"

    def test_tls_deny_in_bucket_policy(self, main_tf):
        raw = (EXAMPLE_DIR / "main.tf").read_text()
        assert "DenyInsecureTransport" in raw or "aws:SecureTransport" in raw, (
            "Bucket policy must deny non-TLS access (aws:SecureTransport = false)"
        )


# ── KMS key hardening ─────────────────────────────────────────────────────────


class TestKMSSecurity:
    def test_kms_key_rotation_enabled(self, main_tf):
        for block in main_tf.get("resource", []):
            if '"aws_kms_key"' in block:
                for _name, config in block['"aws_kms_key"'].items():
                    assert config.get("enable_key_rotation") is True, (
                        "KMS key must have enable_key_rotation = true"
                    )

    def test_kms_alias_present(self, main_tf):
        found = any('"aws_kms_alias"' in block for block in main_tf.get("resource", []))
        assert found, "aws_kms_alias missing — KMS key should have a human-readable alias"

    def test_kms_deletion_window_set(self, main_tf):
        for block in main_tf.get("resource", []):
            if '"aws_kms_key"' in block:
                for _name, config in block['"aws_kms_key"'].items():
                    assert "deletion_window_in_days" in config, (
                        "deletion_window_in_days must be set on KMS key"
                    )


# ── Security group — egress-only ──────────────────────────────────────────────


class TestSecurityGroup:
    def test_https_egress_rule_present(self, main_tf):
        raw = (EXAMPLE_DIR / "main.tf").read_text()
        assert "443" in raw, "Security group must allow HTTPS (port 443) egress"

    def test_no_inbound_allow_all(self, main_tf):
        raw = (EXAMPLE_DIR / "main.tf").read_text()
        # Fail if there is an ingress rule with cidr 0.0.0.0/0
        assert 'ingress' not in raw or '0.0.0.0/0' not in raw.split('ingress')[1].split('egress')[0], (
            "Security group must not allow inbound traffic from 0.0.0.0/0"
        )


# ── Variables ─────────────────────────────────────────────────────────────────


class TestVariables:
    EXPECTED_VARS = {
        "project",
        "environment",
        "aws_region",
        "trust_level",
        "max_tool_calls",
        "rate_limit_rpm",
        "audit_enabled",
        "kill_switch_enabled",
        "retention_days",
        "vpc_cidr",
        "private_subnet_cidrs",
        "public_subnet_cidrs",
        "tags",
    }

    def _var_names(self, variables_tf: dict) -> set[str]:
        # hcl2 wraps variable names in quotes: '"project"'
        return {k.strip('"') for block in variables_tf.get("variable", []) for k in block}

    def test_all_required_vars_declared(self, variables_tf):
        declared = self._var_names(variables_tf)
        missing = self.EXPECTED_VARS - declared
        assert not missing, f"Variables missing from variables.tf: {missing}"

    def test_trust_level_has_validation(self, variables_tf):
        raw = (EXAMPLE_DIR / "variables.tf").read_text()
        assert "trust_level" in raw
        assert "validation" in raw, "trust_level must have a validation block"
        assert "unclassified" in raw, "trust_level validation must include all GovernanceTier values"
        assert "critical" in raw

    def test_project_has_validation(self, variables_tf):
        raw = (EXAMPLE_DIR / "variables.tf").read_text()
        assert "validation" in raw, "project variable must have a validation block"

    def test_retention_days_has_validation(self, variables_tf):
        raw = (EXAMPLE_DIR / "variables.tf").read_text()
        assert "retention_days" in raw
        assert "180" in raw, "retention_days must enforce a minimum of 180 days"

    def test_environment_default_is_dev(self, variables_tf):
        for block in variables_tf.get("variable", []):
            if '"environment"' in block:
                default = str(block['"environment"'].get("default", "")).strip('"')
                assert default == "dev", f"environment default should be 'dev', got {default!r}"

    def test_trust_level_default_is_standard(self, variables_tf):
        for block in variables_tf.get("variable", []):
            if '"trust_level"' in block:
                default = str(block['"trust_level"'].get("default", "")).strip('"')
                assert default == "standard", f"trust_level default should be 'standard', got {default!r}"


# ── Outputs ───────────────────────────────────────────────────────────────────


class TestOutputs:
    EXPECTED_OUTPUTS = {
        "vpc_id",
        "private_subnet_ids",
        "agent_security_group_id",
        "kms_key_arn",
        "audit_log_bucket",
        "signing_key_secret_arn",
        "agent_iam_role_arn",
        "cloudwatch_log_group",
        "ssm_parameter_prefix",
    }

    def _output_names(self, outputs_tf: dict) -> set[str]:
        return {k.strip('"') for block in outputs_tf.get("output", []) for k in block}

    def test_all_required_outputs_declared(self, outputs_tf):
        declared = self._output_names(outputs_tf)
        missing = self.EXPECTED_OUTPUTS - declared
        assert not missing, f"Outputs missing from outputs.tf: {missing}"

    def test_kms_key_arn_output_present(self, outputs_tf):
        assert "kms_key_arn" in self._output_names(outputs_tf)

    def test_audit_bucket_output_present(self, outputs_tf):
        assert "audit_log_bucket" in self._output_names(outputs_tf)

    def test_ssm_prefix_output_present(self, outputs_tf):
        assert "ssm_parameter_prefix" in self._output_names(outputs_tf), (
            "ssm_parameter_prefix output required so callers know where to read AGT config"
        )

    def test_agent_role_arn_output_present(self, outputs_tf):
        assert "agent_iam_role_arn" in self._output_names(outputs_tf)


# ── README content ────────────────────────────────────────────────────────────


class TestREADME:
    @pytest.fixture(scope="class")
    def readme(self) -> str:
        return (EXAMPLE_DIR / "README.md").read_text()

    def test_quick_start_section_present(self, readme):
        assert "Quick Start" in readme or "quick start" in readme.lower()

    def test_terraform_init_command_present(self, readme):
        assert "terraform init" in readme

    def test_governance_config_table_present(self, readme):
        assert "AGT_TRUST_LEVEL" in readme
        assert "AGT_MAX_TOOL_CALLS" in readme
        assert "AGT_AUDIT_ENABLED" in readme

    def test_signing_key_bootstrap_documented(self, readme):
        assert "signing" in readme.lower() and ("bootstrap" in readme.lower() or "populate" in readme.lower()), (
            "README must document how to populate the Ed25519 signing key after apply"
        )

    def test_known_limitations_documented(self, readme):
        assert "limitation" in readme.lower() or "Known" in readme, (
            "README must document known limitations (e.g. AGT_POLICY_PATH not provisioned)"
        )

    def test_ssm_runtime_config_reading_documented(self, readme):
        assert "ssm" in readme.lower() or "SSM" in readme, (
            "README must show how agents read AGT config from SSM at runtime"
        )
