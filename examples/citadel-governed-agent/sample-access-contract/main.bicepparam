// Sample Citadel Access Contract with AGT Policy Bundle Binding
//
// This file extends a standard Citadel Access Contract to include
// an AGT policy bundle reference. When the agent environment is
// deployed, the policy bundle is fetched and injected into the
// agent runtime configuration.
//
// See: https://github.com/Azure-Samples/ai-hub-gateway-solution-accelerator/tree/citadel-v1/bicep/infra/citadel-access-contracts

using 'main.bicep'

// ── Standard Citadel parameters ──

param apim = {
  subscriptionId: '<your-subscription-id>'
  resourceGroupName: '<your-apim-rg>'
  name: '<your-apim-instance>'
}

param keyVault = {
  subscriptionId: '<your-subscription-id>'
  resourceGroupName: '<your-kv-rg>'
  name: '<your-kv-name>'
}

param useTargetAzureKeyVault = true

param useCase = {
  businessUnit: 'customer-support'
  useCaseName: 'governed-agent'
  environment: 'dev'
}

param apiNameMapping = {
  LLM: ['azure-openai-service-api']
}

param services = [
  {
    code: 'LLM'
    displayName: 'Azure OpenAI for Customer Support Agent'
    description: 'LLM access for AGT-governed customer support agent'
    policies: {
      jwtAuth: {
        enabled: true
      }
    }
  }
]

// ── AGT Policy Bundle Binding ──
//
// This parameter references an AGT policy bundle that will be
// injected into the agent runtime at deployment time. The bundle
// defines agent-level governance rules (per-action allow/deny,
// trust scoring, audit settings) that complement the gateway-level
// controls defined in this Access Contract.
//
// The bundle can be stored in:
// - Azure Key Vault (recommended for production)
// - A file in the agent environment (for development)
// - A URL (for centralized policy management)

param agtPolicyBundle = {
  bundleId: 'customer-support-v2'
  version: '1.3.0'
  source: 'keyvault'  // 'keyvault' | 'file' | 'url'
  secretName: 'agt-policy-bundle-customer-support'
  // For 'file' source: filePath: './policies/agent-policy.yaml'
  // For 'url' source: url: 'https://policy-store.example.com/bundles/customer-support-v2'
}
