# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Structural tests for examples/terraform-azure.

Validates HCL structure, required resources, variable definitions, output
declarations, and AGT governance config correctness without running
terraform apply or requiring Azure credentials.
"""

from __future__ import annotations

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
        assert "required_version" in tf_blocks[0], "required_version missing from terraform block"

    def test_azurerm_provider_declared(self, main_tf):
        providers = main_tf.get("terraform", [{}])[0].get("required_providers", [{}])[0]
        assert "azurerm" in providers, "azurerm provider missing from required_providers"

    def test_random_provider_declared(self, main_tf):
        providers = main_tf.get("terraform", [{}])[0].get("required_providers", [{}])[0]
        assert "random" in providers, "random provider missing from required_providers"

    def test_azurerm_provider_version_constraint(self, main_tf):
        providers = main_tf["terraform"][0]["required_providers"][0]
        version = providers["azurerm"].get("version", "")
        assert ">= 3.85" in version or "~> 3" in version or ">= 4" in version, (
            f"azurerm provider version constraint too loose: {version}"
        )

    def test_azurerm_provider_features_block_present(self, main_tf):
        providers = main_tf.get("provider", [])
        azurerm_providers = [p for p in providers if '"azurerm"' in p]
        assert azurerm_providers, "azurerm provider block missing (needs features {})"


# ── Required Azure resources ──────────────────────────────────────────────────


class TestRequiredResources:
    def _resource_names(self, main_tf: dict, resource_type: str) -> list[str]:
        key = f'"{resource_type}"'
        names = []
        for block in main_tf.get("resource", []):
            if key in block:
                names.extend(block[key].keys())
        return names

    def test_resource_group_present(self, main_tf):
        assert self._resource_names(main_tf, "azurerm_resource_group"), (
            "azurerm_resource_group missing"
        )

    def test_vnet_present(self, main_tf):
        assert self._resource_names(main_tf, "azurerm_virtual_network"), (
            "azurerm_virtual_network missing"
        )

    def test_subnet_present(self, main_tf):
        assert self._resource_names(main_tf, "azurerm_subnet"), (
            "azurerm_subnet missing — agents need a private subnet"
        )

    def test_nsg_present(self, main_tf):
        assert self._resource_names(main_tf, "azurerm_network_security_group"), (
            "azurerm_network_security_group missing"
        )

    def test_managed_identity_present(self, main_tf):
        assert self._resource_names(main_tf, "azurerm_user_assigned_identity"), (
            "azurerm_user_assigned_identity missing — agents must use passwordless auth"
        )

    def test_key_vault_present(self, main_tf):
        assert self._resource_names(main_tf, "azurerm_key_vault"), (
            "azurerm_key_vault missing — required for Ed25519 signing key"
        )

    def test_key_vault_secret_present(self, main_tf):
        assert self._resource_names(main_tf, "azurerm_key_vault_secret"), (
            "azurerm_key_vault_secret missing — Ed25519 signing key must be stored"
        )

    def test_storage_account_present(self, main_tf):
        assert self._resource_names(main_tf, "azurerm_storage_account"), (
            "azurerm_storage_account missing — required for audit logs"
        )

    def test_storage_container_present(self, main_tf):
        assert self._resource_names(main_tf, "azurerm_storage_container"), (
            "azurerm_storage_container missing — audit log container required"
        )

    def test_storage_lifecycle_present(self, main_tf):
        assert self._resource_names(main_tf, "azurerm_storage_management_policy"), (
            "azurerm_storage_management_policy missing — audit log lifecycle tiers required"
        )

    def test_app_configuration_present(self, main_tf):
        assert self._resource_names(main_tf, "azurerm_app_configuration"), (
            "azurerm_app_configuration missing — required for AGT_* governance config"
        )

    def test_log_analytics_workspace_present(self, main_tf):
        assert self._resource_names(main_tf, "azurerm_log_analytics_workspace"), (
            "azurerm_log_analytics_workspace missing — required for governance events"
        )


# ── App Configuration keys — AGT governance config ───────────────────────────


class TestAppConfigurationKeys:
    """All AGT_* governance config values must be stored as App Configuration keys."""

    EXPECTED_KEYS = {
        "trust_level",
        "max_tool_calls",
        "rate_limit_rpm",
        "audit_enabled",
        "kill_switch_enabled",
        "audit_container",
    }

    def _appconfig_key_names(self, main_tf: dict) -> set[str]:
        names = set()
        for block in main_tf.get("resource", []):
            if '"azurerm_app_configuration_key"' in block:
                names.update(k.strip('"') for k in block['"azurerm_app_configuration_key"'].keys())
        return names

    def test_all_agt_keys_present(self, main_tf):
        found = self._appconfig_key_names(main_tf)
        missing = self.EXPECTED_KEYS - found
        assert not missing, f"App Configuration keys missing for AGT config: {missing}"

    def test_trust_level_key_present(self, main_tf):
        assert "trust_level" in self._appconfig_key_names(main_tf)

    def test_max_tool_calls_key_present(self, main_tf):
        assert "max_tool_calls" in self._appconfig_key_names(main_tf)

    def test_audit_enabled_key_present(self, main_tf):
        assert "audit_enabled" in self._appconfig_key_names(main_tf)

    def test_kill_switch_key_present(self, main_tf):
        assert "kill_switch_enabled" in self._appconfig_key_names(main_tf)

    def test_audit_container_key_present(self, main_tf):
        assert "audit_container" in self._appconfig_key_names(main_tf)

    def test_keys_have_environment_label(self, main_tf):
        raw = (EXAMPLE_DIR / "main.tf").read_text()
        assert "var.environment" in raw or "${var.environment}" in raw, (
            "App Configuration keys must be labelled with var.environment"
        )


# ── Key Vault security hardening ──────────────────────────────────────────────


class TestKeyVaultSecurity:
    def test_key_vault_uses_premium_sku(self, main_tf):
        for block in main_tf.get("resource", []):
            if '"azurerm_key_vault"' in block:
                for _name, config in block['"azurerm_key_vault"'].items():
                    sku = str(config.get("sku_name", "")).strip('"')
                    assert sku == "premium", (
                        "Key Vault must use 'premium' SKU to support HSM-backed keys"
                    )

    def test_key_vault_rbac_enabled(self, main_tf):
        for block in main_tf.get("resource", []):
            if '"azurerm_key_vault"' in block:
                for _name, config in block['"azurerm_key_vault"'].items():
                    assert config.get("enable_rbac_authorization") is True, (
                        "Key Vault must use RBAC authorization (not legacy access policies)"
                    )

    def test_key_vault_network_acls_deny_default(self, main_tf):
        raw = (EXAMPLE_DIR / "main.tf").read_text()
        assert "default_action" in raw and "Deny" in raw, (
            "Key Vault network_acls must set default_action = Deny"
        )

    def test_key_vault_purge_protection_prod_conditional(self, main_tf):
        raw = (EXAMPLE_DIR / "main.tf").read_text()
        assert "purge_protection_enabled" in raw, (
            "Key Vault must set purge_protection_enabled (true in prod)"
        )
        assert 'var.environment == "prod"' in raw or "var.environment ==" in raw, (
            "purge_protection_enabled should be conditional on environment == prod"
        )

    def test_signing_key_secret_has_ignore_changes(self, main_tf):
        raw = (EXAMPLE_DIR / "main.tf").read_text()
        assert "ignore_changes" in raw, (
            "Key Vault signing key secret must have lifecycle ignore_changes = [value] "
            "so terraform apply does not overwrite a real key with the placeholder"
        )

    def test_role_assignments_for_managed_identity(self, main_tf):
        role_assignments = []
        for block in main_tf.get("resource", []):
            if '"azurerm_role_assignment"' in block:
                role_assignments.extend(k.strip('"') for k in block['"azurerm_role_assignment"'].keys())
        kv_assignments = [r for r in role_assignments if "kv" in r]
        assert kv_assignments, (
            "No Key Vault role assignments found for managed identity"
        )


# ── Storage security hardening ────────────────────────────────────────────────


class TestStorageSecurity:
    def test_tls_only_enforced(self, main_tf):
        for block in main_tf.get("resource", []):
            if '"azurerm_storage_account"' in block:
                for _name, config in block['"azurerm_storage_account"'].items():
                    assert config.get("https_traffic_only_enabled") is True, (
                        "Storage account must enforce HTTPS-only traffic"
                    )

    def test_min_tls_version_set(self, main_tf):
        for block in main_tf.get("resource", []):
            if '"azurerm_storage_account"' in block:
                for _name, config in block['"azurerm_storage_account"'].items():
                    tls = str(config.get("min_tls_version", "")).strip('"')
                    assert tls == "TLS1_2", (
                        f"min_tls_version must be TLS1_2, got {tls!r}"
                    )

    def test_public_access_blocked(self, main_tf):
        for block in main_tf.get("resource", []):
            if '"azurerm_storage_account"' in block:
                for _name, config in block['"azurerm_storage_account"'].items():
                    assert config.get("allow_nested_items_to_be_public") is False, (
                        "Storage account must block public access to blobs"
                    )

    def test_blob_versioning_enabled(self, main_tf):
        raw = (EXAMPLE_DIR / "main.tf").read_text()
        assert "versioning_enabled" in raw, (
            "Blob versioning must be enabled on audit log storage"
        )

    def test_grs_replication_in_prod(self, main_tf):
        raw = (EXAMPLE_DIR / "main.tf").read_text()
        assert "GRS" in raw, (
            "Storage account must use GRS replication in prod for durability"
        )
        assert 'var.environment == "prod"' in raw or "var.environment ==" in raw, (
            "GRS replication should be conditional on environment == prod"
        )

    def test_container_access_is_private(self, main_tf):
        for block in main_tf.get("resource", []):
            if '"azurerm_storage_container"' in block:
                for _name, config in block['"azurerm_storage_container"'].items():
                    access = str(config.get("container_access_type", "")).strip('"')
                    assert access == "private", (
                        f"Audit log container must be private, got {access!r}"
                    )


# ── NSG — deny-all inbound ────────────────────────────────────────────────────


class TestNSGRules:
    def test_deny_all_inbound_rule_present(self, main_tf):
        raw = (EXAMPLE_DIR / "main.tf").read_text()
        assert "DenyAllInbound" in raw, (
            "NSG must have a DenyAllInbound rule — agent subnets must block all inbound"
        )

    def test_https_outbound_rule_present(self, main_tf):
        raw = (EXAMPLE_DIR / "main.tf").read_text()
        assert "AllowHttpsOutbound" in raw or "443" in raw, (
            "NSG must allow HTTPS outbound (port 443) for LLM API calls"
        )

    def test_subnet_nsg_association_present(self, main_tf):
        found = any(
            '"azurerm_subnet_network_security_group_association"' in block
            for block in main_tf.get("resource", [])
        )
        assert found, (
            "azurerm_subnet_network_security_group_association missing — NSG must be attached to subnet"
        )


# ── Managed Identity RBAC ─────────────────────────────────────────────────────


class TestManagedIdentityRBAC:
    def _role_assignment_names(self, main_tf: dict) -> list[str]:
        names = []
        for block in main_tf.get("resource", []):
            if '"azurerm_role_assignment"' in block:
                names.extend(k.strip('"') for k in block['"azurerm_role_assignment"'].keys())
        return names

    def test_storage_role_assignment_present(self, main_tf):
        names = self._role_assignment_names(main_tf)
        storage_assignments = [n for n in names if "storage" in n]
        assert storage_assignments, (
            "No storage role assignment found — managed identity needs access to write audit logs"
        )

    def test_appconfig_role_assignment_present(self, main_tf):
        names = self._role_assignment_names(main_tf)
        appconfig_assignments = [n for n in names if "appconfig" in n]
        assert appconfig_assignments, (
            "No App Configuration role assignment — managed identity needs to read AGT config"
        )


# ── Variables ─────────────────────────────────────────────────────────────────


class TestVariables:
    EXPECTED_VARS = {
        "project",
        "environment",
        "location",
        "resource_group_name",
        "trust_level",
        "max_tool_calls",
        "rate_limit_rpm",
        "audit_enabled",
        "kill_switch_enabled",
        "retention_days",
        "vnet_address_space",
        "private_subnet_prefix",
        "tags",
    }

    def _var_names(self, variables_tf: dict) -> set[str]:
        return {k.strip('"') for block in variables_tf.get("variable", []) for k in block}

    def test_all_required_vars_declared(self, variables_tf):
        declared = self._var_names(variables_tf)
        missing = self.EXPECTED_VARS - declared
        assert not missing, f"Variables missing from variables.tf: {missing}"

    def test_trust_level_has_validation(self, variables_tf):
        raw = (EXAMPLE_DIR / "variables.tf").read_text()
        assert "validation" in raw, "trust_level must have a validation block"
        assert "unclassified" in raw and "critical" in raw, (
            "trust_level validation must list all GovernanceTier values"
        )

    def test_retention_days_minimum_enforced(self, variables_tf):
        raw = (EXAMPLE_DIR / "variables.tf").read_text()
        assert "retention_days" in raw
        assert "180" in raw, "retention_days must enforce a minimum of 180 days"

    def test_environment_default_is_dev(self, variables_tf):
        for block in variables_tf.get("variable", []):
            if '"environment"' in block:
                default = str(block['"environment"'].get("default", "")).strip('"')
                assert default == "dev"

    def test_trust_level_default_is_standard(self, variables_tf):
        for block in variables_tf.get("variable", []):
            if '"trust_level"' in block:
                default = str(block['"trust_level"'].get("default", "")).strip('"')
                assert default == "standard"

    def test_location_default_set(self, variables_tf):
        for block in variables_tf.get("variable", []):
            if '"location"' in block:
                default = str(block['"location"'].get("default", "")).strip('"')
                assert default, "location must have a default value"


# ── Outputs ───────────────────────────────────────────────────────────────────


class TestOutputs:
    EXPECTED_OUTPUTS = {
        "resource_group_name",
        "vnet_id",
        "agent_subnet_id",
        "managed_identity_id",
        "managed_identity_client_id",
        "key_vault_uri",
        "signing_key_secret_id",
        "audit_storage_account_name",
        "audit_container_name",
        "app_configuration_endpoint",
        "log_analytics_workspace_id",
    }

    def _output_names(self, outputs_tf: dict) -> set[str]:
        return {k.strip('"') for block in outputs_tf.get("output", []) for k in block}

    def test_all_required_outputs_declared(self, outputs_tf):
        declared = self._output_names(outputs_tf)
        missing = self.EXPECTED_OUTPUTS - declared
        assert not missing, f"Outputs missing from outputs.tf: {missing}"

    def test_managed_identity_client_id_output_present(self, outputs_tf):
        assert "managed_identity_client_id" in self._output_names(outputs_tf), (
            "managed_identity_client_id output required — agents need AZURE_CLIENT_ID"
        )

    def test_app_config_endpoint_output_present(self, outputs_tf):
        assert "app_configuration_endpoint" in self._output_names(outputs_tf), (
            "app_configuration_endpoint output required so agents know where to read AGT config"
        )

    def test_key_vault_uri_output_present(self, outputs_tf):
        assert "key_vault_uri" in self._output_names(outputs_tf)


# ── README content ────────────────────────────────────────────────────────────


class TestREADME:
    @pytest.fixture(scope="class")
    def readme(self) -> str:
        return (EXAMPLE_DIR / "README.md").read_text()

    def test_quick_start_section_present(self, readme):
        assert "Quick Start" in readme or "quick start" in readme.lower()

    def test_az_login_documented(self, readme):
        assert "az login" in readme, "README must document az login step"

    def test_terraform_init_command_present(self, readme):
        assert "terraform init" in readme

    def test_governance_config_table_present(self, readme):
        assert "AGT_TRUST_LEVEL" in readme
        assert "AGT_MAX_TOOL_CALLS" in readme
        assert "AGT_AUDIT_ENABLED" in readme

    def test_prod_vs_dev_differences_documented(self, readme):
        assert "prod" in readme.lower() and "dev" in readme.lower(), (
            "README must document prod vs dev differences (GRS, purge protection, etc.)"
        )

    def test_signing_key_bootstrap_documented(self, readme):
        assert "signing" in readme.lower() and ("bootstrap" in readme.lower() or "populate" in readme.lower()), (
            "README must document how to populate the Ed25519 signing key"
        )

    def test_app_configuration_runtime_reading_documented(self, readme):
        assert "appconfig" in readme.lower() or "App Configuration" in readme, (
            "README must show how agents read AGT config from App Configuration at runtime"
        )

    def test_ignore_changes_lifecycle_explained(self, readme):
        assert "ignore_changes" in readme, (
            "README must explain the ignore_changes lifecycle rule on the signing key secret"
        )

    def test_known_limitations_documented(self, readme):
        assert "limitation" in readme.lower() or "Known" in readme
