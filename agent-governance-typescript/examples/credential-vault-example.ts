// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Example: credential offload and injection for an agent tool call.
 *
 * Run with: `npx ts-node examples/credential-vault-example.ts`
 *
 * TypeScript port of the Python example for issue #2481 / #2535.
 */

import {
  CredentialInjector,
  CredentialProfile,
  CredentialVault,
  InjectionContext,
  PolicyOutcome,
} from '../src/credential-vault';

async function main(): Promise<void> {
  // 1. Operator provisions the credential.
  const vault = new CredentialVault();
  await vault.put('github_pat', 'ghp_real_token_value', 'bearer_token');

  // 2. Bind agent identity to action capability -> handle.
  vault.registerProfile(
    new CredentialProfile('did:web:agent-ci', { 'github:read_issues': 'github_pat' }),
  );

  // 3. The agent's saved tool-call template uses only the placeholder.
  const headers = { Authorization: 'Bearer {{cred:github_pat}}' };

  // 4. Workflow policy decides whether the call is allowed at all,
  //    before the injector ever reads the value.
  const policy = (ctx: InjectionContext): PolicyOutcome => ({
    allow: ctx.actionClass === 'github:read_issues',
    reason: 'only read-only github calls permitted in this workflow',
  });

  const injector = new CredentialInjector(vault);
  const result = await injector.injectHeaders('did:web:agent-ci', headers, {
    actionClass: 'github:read_issues',
    targetService: 'api.github.com',
    allowedHandles: ['github_pat'],
    policyCheck: policy,
    policyVersion: 'v1',
  });

  console.log('allowed:', result.allowed);
  if (result.allowed && typeof result.payload === 'object') {
    const rendered = result.payload as Record<string, string>;
    console.log('rendered Authorization length:', rendered.Authorization.length);
  }

  // 5. Audit log has no value, only the handle name and decision.
  for (const ev of vault.auditLog()) {
    console.log('audit:', ev);
  }
}

void main();
