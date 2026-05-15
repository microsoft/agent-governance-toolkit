// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { AgentMeshClient } from '@microsoft/agent-governance-sdk';

async function main() {
  const client = AgentMeshClient.create('quickstart-agent', {
    capabilities: ['data.read'],
    policyRules: [
      { action: 'data.read', effect: 'allow' },
      { action: '*', effect: 'deny' },
    ],
  });

  const result = await client.executeWithGovernance('data.read', {
    resource: 'customer-profile',
  });

  console.log(`Decision: ${result.decision}`);
  console.log(`Trust tier: ${result.trustScore.tier}`);
  console.log(`Audit chain valid: ${client.audit.verify()}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
