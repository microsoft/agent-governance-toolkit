// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// Reference deployment for the Foundry AI Gateway + Functions PDP sample.
// Provisions:
//   - Storage account (Function runtime)
//   - App Insights + Log Analytics
//   - Linux Consumption Function App (system-assigned managed identity)
//   - API Management (Developer SKU) with a named-value pointing at the PDP
//
// This is a *reference* template intended for evaluation, not production.
// Production deployments should:
//   - use Premium / Elastic Premium plan for predictable PDP latency,
//   - enable VNet integration and private endpoints,
//   - front the Function with Easy Auth (Entra ID) — wired via portal /
//     azd post-provision hook in this sample to keep the Bicep small.

targetScope = 'resourceGroup'

@description('Base name used for all resources. Keep short; APIM appends suffixes.')
param baseName string = 'agtpdp${uniqueString(resourceGroup().id)}'

@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('Publisher email for APIM. Required by the API Management resource.')
param apimPublisherEmail string

@description('Publisher org name for APIM.')
param apimPublisherName string = 'Agent Governance Toolkit (sample)'

@description('Environment tag value sent in the PDP request envelope.')
@allowed(['dev', 'test', 'prod'])
param pdpEnvironment string = 'dev'

@description('Application (client) ID of the Entra ID app registration that fronts the PDP Function via Easy Auth. APIM acquires a token for `api://<this>` using its managed identity. Required.')
param pdpAadAppId string

@description('Tenant ID for Easy Auth issuer. Defaults to the deploying tenant.')
param pdpAadTenantId string = subscription().tenantId

var storageName = toLower(replace('${baseName}st', '-', ''))
var functionAppName = '${baseName}-fn'
var planName = '${baseName}-plan'
var apimName = '${baseName}-apim'
var logName = '${baseName}-log'
var aiName = '${baseName}-ai'

resource log 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: logName
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

resource ai 'Microsoft.Insights/components@2020-02-02' = {
  name: aiName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: log.id
  }
}

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
  }
}

resource plan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: planName
  location: location
  sku: {
    name: 'Y1'
    tier: 'Dynamic'
  }
  properties: {
    reserved: true
  }
}

resource functionApp 'Microsoft.Web/sites@2023-12-01' = {
  name: functionAppName
  location: location
  kind: 'functionapp,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'Python|3.11'
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      appSettings: [
        { name: 'AzureWebJobsStorage', value: 'DefaultEndpointsProtocol=https;AccountName=${storage.name};AccountKey=${storage.listKeys().keys[0].value};EndpointSuffix=${environment().suffixes.storage}' }
        { name: 'FUNCTIONS_EXTENSION_VERSION', value: '~4' }
        { name: 'FUNCTIONS_WORKER_RUNTIME', value: 'python' }
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: ai.properties.ConnectionString }
        { name: 'PDP_ENVIRONMENT', value: pdpEnvironment }
      ]
    }
  }
}

// Easy Auth (authsettingsV2) — require Entra ID on every call. Combined
// with function-level authLevel, this is defence in depth: even if the
// host key leaks, the request still needs a valid Entra token whose
// audience matches `api://<pdpAadAppId>`.
resource functionAuth 'Microsoft.Web/sites/config@2023-12-01' = {
  parent: functionApp
  name: 'authsettingsV2'
  properties: {
    globalValidation: {
      requireAuthentication: true
      unauthenticatedClientAction: 'Return401'
    }
    identityProviders: {
      azureActiveDirectory: {
        enabled: true
        registration: {
          openIdIssuer: '${environment().authentication.loginEndpoint}${pdpAadTenantId}/v2.0'
          clientId: pdpAadAppId
        }
        validation: {
          allowedAudiences: [
            'api://${pdpAadAppId}'
          ]
        }
      }
    }
    platform: {
      enabled: true
    }
  }
}

resource apim 'Microsoft.ApiManagement/service@2023-09-01-preview' = {
  name: apimName
  location: location
  sku: {
    name: 'Developer'
    capacity: 1
  }
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    publisherEmail: apimPublisherEmail
    publisherName: apimPublisherName
  }
}

resource pdpBaseUrlNv 'Microsoft.ApiManagement/service/namedValues@2023-09-01-preview' = {
  parent: apim
  name: 'pdp-base-url'
  properties: {
    displayName: 'pdp-base-url'
    value: 'https://${functionApp.properties.defaultHostName}'
    secret: false
  }
}

resource pdpAudienceNv 'Microsoft.ApiManagement/service/namedValues@2023-09-01-preview' = {
  parent: apim
  name: 'pdp-aad-audience'
  properties: {
    displayName: 'pdp-aad-audience'
    value: 'api://${pdpAadAppId}'
    secret: false
  }
}

resource pdpEnvNv 'Microsoft.ApiManagement/service/namedValues@2023-09-01-preview' = {
  parent: apim
  name: 'pdp-environment'
  properties: {
    displayName: 'pdp-environment'
    value: pdpEnvironment
    secret: false
  }
}

resource pdpFailOpenNv 'Microsoft.ApiManagement/service/namedValues@2023-09-01-preview' = {
  parent: apim
  name: 'pdp-fail-open'
  properties: {
    displayName: 'pdp-fail-open'
    value: 'false'
    secret: false
  }
}

output functionAppName string = functionApp.name
output functionAppHostname string = functionApp.properties.defaultHostName
output apimName string = apim.name
output apimGatewayUrl string = apim.properties.gatewayUrl
