# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

output "resource_group_name" {
  description = "Name of the Azure resource group."
  value       = azurerm_resource_group.this.name
}

output "vnet_id" {
  description = "ID of the agent governance VNet."
  value       = azurerm_virtual_network.this.id
}

output "agent_subnet_id" {
  description = "ID of the private subnet where agent workloads run."
  value       = azurerm_subnet.agents.id
}

output "managed_identity_id" {
  description = "Resource ID of the user-assigned managed identity for agent workloads."
  value       = azurerm_user_assigned_identity.agent.id
}

output "managed_identity_client_id" {
  description = "Client ID of the managed identity — set as AZURE_CLIENT_ID in agent containers."
  value       = azurerm_user_assigned_identity.agent.client_id
}

output "key_vault_uri" {
  description = "URI of the Key Vault holding the Ed25519 signing key."
  value       = azurerm_key_vault.this.vault_uri
}

output "key_vault_id" {
  description = "Resource ID of the Key Vault."
  value       = azurerm_key_vault.this.id
}

output "signing_key_secret_id" {
  description = "Key Vault secret ID for the Ed25519 governance receipt signing key."
  value       = azurerm_key_vault_secret.signing_key.id
}

output "audit_storage_account_name" {
  description = "Name of the Storage Account for governance audit logs."
  value       = azurerm_storage_account.audit_logs.name
}

output "audit_container_name" {
  description = "Name of the Blob container for governance audit logs."
  value       = azurerm_storage_container.audit_logs.name
}

output "app_configuration_endpoint" {
  description = "Endpoint of the App Configuration store. Agents read AGT_* config from here."
  value       = azurerm_app_configuration.governance.endpoint
}

output "log_analytics_workspace_id" {
  description = "Resource ID of the Log Analytics workspace for governance events."
  value       = azurerm_log_analytics_workspace.governance.id
}
