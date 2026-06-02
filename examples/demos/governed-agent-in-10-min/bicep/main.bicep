// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// ============================================================================
// AGT Reference Architecture: Governed Agent Environment
// ============================================================================
//
// Deploys the infrastructure for a governed AI agent environment:
//   - Azure Container App (agent runtime)
//   - Azure Key Vault (secrets, agent credentials)
//   - Azure Log Analytics (observability, audit trail)
//   - Azure Container Registry (agent images)
//   - Managed Identity (zero-trust, no shared secrets)
//
// Usage:
//   az deployment group create \
//     --resource-group rg-agt-demo \
//     --template-file main.bicep \
//     --parameters environmentName=agt-demo
//
// This is a reference architecture for demonstration. Review and customize
// security settings, SKUs, and networking for production use.
// ============================================================================

@description('Environment name prefix for all resources')
param environmentName string

@description('Azure region for deployment')
param location string = resourceGroup().location

@description('Container image for the governed agent')
param agentImage string = 'mcr.microsoft.com/agent-governance-toolkit/agent-runtime:latest'

// --- Variables ---
var prefix = toLower(environmentName)
var uniqueSuffix = uniqueString(resourceGroup().id, prefix)

// --- Log Analytics Workspace (Observability + Audit) ---
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${prefix}-logs-${uniqueSuffix}'
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 90
  }
}

// --- Container Registry ---
resource acr 'Microsoft.ContainerRegistry/registries@2023-11-01-preview' = {
  name: '${prefix}acr${uniqueSuffix}'
  location: location
  sku: {
    name: 'Basic'
  }
  properties: {
    adminUserEnabled: false
  }
}

// --- Key Vault (Agent Credentials, Policy Signing Keys) ---
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: '${prefix}-kv-${uniqueSuffix}'
  location: location
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 30
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
    }
  }
}

// --- Managed Identity (Zero-Trust Agent Identity) ---
resource managedIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${prefix}-agent-id'
  location: location
}

// --- Container Apps Environment ---
resource containerAppEnv 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: '${prefix}-env'
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalytics.properties.customerId
        sharedKey: logAnalytics.listKeys().primarySharedKey
      }
    }
  }
}

// --- Governed Agent Container App ---
resource agentApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: '${prefix}-agent'
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentity.id}': {}
    }
  }
  properties: {
    managedEnvironmentId: containerAppEnv.id
    configuration: {
      ingress: {
        external: false
        targetPort: 8080
        transport: 'http'
      }
    }
    template: {
      containers: [
        {
          name: 'agent-runtime'
          image: agentImage
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          env: [
            {
              name: 'AGT_POLICY_PATH'
              value: '/policies/contoso-bank.yaml'
            }
            {
              name: 'AGT_AUDIT_ENABLED'
              value: 'true'
            }
            {
              name: 'AGT_TRUST_LEVEL'
              value: 'zero-trust'
            }
            {
              name: 'AZURE_CLIENT_ID'
              value: managedIdentity.properties.clientId
            }
          ]
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 5
        rules: [
          {
            name: 'cpu-scaling'
            custom: {
              type: 'cpu'
              metadata: {
                type: 'Utilization'
                value: '70'
              }
            }
          }
        ]
      }
    }
  }
}

// --- Outputs ---
output agentFqdn string = agentApp.properties.configuration.ingress.fqdn
output keyVaultName string = keyVault.name
output logAnalyticsWorkspaceId string = logAnalytics.id
output managedIdentityClientId string = managedIdentity.properties.clientId
output acrLoginServer string = acr.properties.loginServer
