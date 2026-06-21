# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# cspell:ignore appconfig appconfiguration passwordless myagent myagentprodsa
#
# Example: governed agent infrastructure on Azure
#
# Provisions all Azure resources required to run AGT-governed agents in production:
#   - Resource Group, VNet, private subnet with service endpoints, NSG (deny-all inbound)
#   - User-Assigned Managed Identity for passwordless agent authentication
#   - Key Vault (Premium, purge-protected in prod) for the Ed25519 signing key
#   - Storage Account + Blob container with lifecycle tiers and TLS enforcement
#   - App Configuration store for all AGT_* governance config values
#   - Log Analytics Workspace for governance event ingestion and retention
#
# Usage:
#   cd examples/terraform-azure
#   az login
#   terraform init
#   terraform plan -var="project=myagent"
#   terraform apply -var="project=myagent"
#
# Agents read governance config from App Configuration at runtime:
#   az appconfig kv list --name <appconfig-name> --label <environment>

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.85, < 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5"
    }
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy    = false
      recover_soft_deleted_key_vaults = true
    }
  }
}

data "azurerm_client_config" "current" {}

locals {
  name_prefix         = "${var.project}-${var.environment}"
  resource_group_name = var.resource_group_name != "" ? var.resource_group_name : "${local.name_prefix}-rg"

  common_tags = merge(var.tags, {
    "agt-project"     = var.project
    "agt-environment" = var.environment
    "agt-trust-level" = var.trust_level
    "agt-managed-by"  = "terraform"
  })
}

# ── Resource Group ────────────────────────────────────────────────────────────

resource "azurerm_resource_group" "this" {
  name     = local.resource_group_name
  location = var.location
  tags     = local.common_tags
}

# ── VNet, subnet, and NSG ─────────────────────────────────────────────────────

resource "azurerm_virtual_network" "this" {
  name                = "${local.name_prefix}-vnet"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  address_space       = var.vnet_address_space
  tags                = local.common_tags
}

resource "azurerm_subnet" "agents" {
  name                 = "${local.name_prefix}-agents"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [var.private_subnet_prefix]

  service_endpoints = [
    "Microsoft.KeyVault",
    "Microsoft.Storage",
    "Microsoft.CognitiveServices",
  ]
}

resource "azurerm_network_security_group" "agents" {
  name                = "${local.name_prefix}-agents-nsg"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name

  security_rule {
    name                       = "DenyAllInbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowHttpsOutbound"
    priority                   = 100
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = var.private_subnet_prefix
    destination_address_prefix = "Internet"
  }

  tags = local.common_tags
}

resource "azurerm_subnet_network_security_group_association" "agents" {
  subnet_id                 = azurerm_subnet.agents.id
  network_security_group_id = azurerm_network_security_group.agents.id
}

# ── User-Assigned Managed Identity ───────────────────────────────────────────

resource "azurerm_user_assigned_identity" "agent" {
  name                = "${local.name_prefix}-agent-identity"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.common_tags
}

# ── Key Vault for Ed25519 signing key ─────────────────────────────────────────

resource "random_string" "kv_suffix" {
  length  = 4
  special = false
  upper   = false
}

resource "azurerm_key_vault" "this" {
  name                       = "${substr(local.name_prefix, 0, 16)}kv${random_string.kv_suffix.result}"
  location                   = azurerm_resource_group.this.location
  resource_group_name        = azurerm_resource_group.this.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "premium"
  purge_protection_enabled   = var.environment == "prod"
  soft_delete_retention_days = var.environment == "prod" ? 90 : 7
  enable_rbac_authorization  = true

  network_acls {
    default_action             = "Deny"
    bypass                     = "AzureServices"
    virtual_network_subnet_ids = [azurerm_subnet.agents.id]
  }

  tags = local.common_tags
}

resource "azurerm_role_assignment" "agent_kv_secrets" {
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.agent.principal_id
}

resource "azurerm_role_assignment" "agent_kv_crypto" {
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Crypto User"
  principal_id         = azurerm_user_assigned_identity.agent.principal_id
}

# Placeholder secret — populate via CI bootstrap or key rotation script.
resource "azurerm_key_vault_secret" "signing_key" {
  name         = "agt-signing-key"
  value        = "PLACEHOLDER-replace-with-Ed25519-PEM-via-CI-or-bootstrap-script"
  key_vault_id = azurerm_key_vault.this.id

  lifecycle {
    ignore_changes = [value]
  }

  tags = local.common_tags
}

# ── Storage Account for immutable audit logs ──────────────────────────────────

resource "random_string" "sa_suffix" {
  length  = 6
  special = false
  upper   = false
}

resource "azurerm_storage_account" "audit_logs" {
  name                            = "${substr(replace(local.name_prefix, "-", ""), 0, 16)}${random_string.sa_suffix.result}"
  resource_group_name             = azurerm_resource_group.this.name
  location                        = azurerm_resource_group.this.location
  account_tier                    = "Standard"
  account_replication_type        = var.environment == "prod" ? "GRS" : "LRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  https_traffic_only_enabled      = true

  blob_properties {
    versioning_enabled = true

    delete_retention_policy {
      days = 30
    }

    container_delete_retention_policy {
      days = 30
    }
  }

  network_rules {
    default_action             = "Deny"
    bypass                     = ["AzureServices"]
    virtual_network_subnet_ids = [azurerm_subnet.agents.id]
  }

  tags = local.common_tags
}

resource "azurerm_storage_container" "audit_logs" {
  name                  = "agt-audit-logs"
  storage_account_id    = azurerm_storage_account.audit_logs.id
  container_access_type = "private"
}

resource "azurerm_storage_management_policy" "audit_logs" {
  storage_account_id = azurerm_storage_account.audit_logs.id

  rule {
    name    = "audit-retention"
    enabled = true

    filters {
      blob_types   = ["blockBlob"]
      prefix_match = ["agt-audit-logs/"]
    }

    actions {
      base_blob {
        tier_to_cool_after_days_since_modification_greater_than    = 90
        tier_to_archive_after_days_since_modification_greater_than = 180
        delete_after_days_since_modification_greater_than          = var.retention_days
      }
    }
  }
}

resource "azurerm_role_assignment" "agent_storage" {
  scope                = azurerm_storage_account.audit_logs.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.agent.principal_id
}

# ── App Configuration — AGT governance parameters ────────────────────────────
# Mirrors SSM parameters on AWS. Agents read these at startup so governance
# config is version-controlled and not baked into container images.

resource "azurerm_app_configuration" "governance" {
  name                = "${local.name_prefix}-appconfig"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  sku                 = var.environment == "prod" ? "standard" : "free"
  tags                = local.common_tags
}

resource "azurerm_role_assignment" "agent_appconfig" {
  scope                = azurerm_app_configuration.governance.id
  role_definition_name = "App Configuration Data Reader"
  principal_id         = azurerm_user_assigned_identity.agent.principal_id
}

resource "azurerm_app_configuration_key" "trust_level" {
  configuration_store_id = azurerm_app_configuration.governance.id
  key                    = "agt:trust-level"
  value                  = var.trust_level
  label                  = var.environment
}

resource "azurerm_app_configuration_key" "max_tool_calls" {
  configuration_store_id = azurerm_app_configuration.governance.id
  key                    = "agt:max-tool-calls"
  value                  = tostring(var.max_tool_calls)
  label                  = var.environment
}

resource "azurerm_app_configuration_key" "rate_limit_rpm" {
  configuration_store_id = azurerm_app_configuration.governance.id
  key                    = "agt:rate-limit-rpm"
  value                  = tostring(var.rate_limit_rpm)
  label                  = var.environment
}

resource "azurerm_app_configuration_key" "audit_enabled" {
  configuration_store_id = azurerm_app_configuration.governance.id
  key                    = "agt:audit-enabled"
  value                  = tostring(var.audit_enabled)
  label                  = var.environment
}

resource "azurerm_app_configuration_key" "kill_switch_enabled" {
  configuration_store_id = azurerm_app_configuration.governance.id
  key                    = "agt:kill-switch-enabled"
  value                  = tostring(var.kill_switch_enabled)
  label                  = var.environment
}

resource "azurerm_app_configuration_key" "audit_container" {
  configuration_store_id = azurerm_app_configuration.governance.id
  key                    = "agt:audit-container"
  value                  = "${azurerm_storage_account.audit_logs.name}/${azurerm_storage_container.audit_logs.name}"
  label                  = var.environment
}

# ── Log Analytics Workspace for governance events ─────────────────────────────

resource "azurerm_log_analytics_workspace" "governance" {
  name                = "${local.name_prefix}-governance-logs"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  sku                 = "PerGB2018"
  retention_in_days   = min(var.retention_days, 730)
  tags                = local.common_tags
}
