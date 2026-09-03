// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Example: governing the backend action behind a WebMCP tool call.
 *
 * Run with: `npx ts-node examples/webmcp-tool-governance.ts`
 *
 * WebMCP (https://github.com/webmachinelearning/webmcp) lets a page
 * register a client-side tool for a browser agent to call:
 *
 *   await document.modelContext.registerTool({
 *     name: 'email.createDraft',
 *     annotations: { readOnlyHint: false },
 *     inputSchema: { ... },
 *     async execute(input) {
 *       // The page's own script calls back into its backend to do the
 *       // real work (webmachinelearning/webmcp#105, "Server-Side
 *       // Verification"). That backend call is what this example governs
 *       // -- AGT does not run inside the browser page itself.
 *       return fetch('/api/draft', { method: 'POST', body: JSON.stringify(input) });
 *     },
 *   });
 *
 * The snippet below is the backend side of `POST /api/draft`: it maps the
 * incoming WebMCP tool call onto a `FrameworkInvocation` and runs it
 * through the same `GenericFrameworkAdapter` used for any other framework
 * integration, so the call is policy-checked, trust-scored, and
 * audit-logged before the handler executes.
 */

import { AgentMeshClient } from '../src/client';
import { GenericFrameworkAdapter } from '../src/framework-adapter';
import { toFrameworkInvocation } from '../src/webmcp';

async function handleCreateDraftRequest(input: { to: string; body: string }): Promise<unknown> {
  const client = AgentMeshClient.create('site-webmcp-agent', {
    policyRules: [
      { action: 'webmcp.email.createDraft', effect: 'allow' },
      { action: '*', effect: 'deny' },
    ],
  });
  const adapter = new GenericFrameworkAdapter(client);

  const invocation = toFrameworkInvocation(
    { name: 'email.createDraft', annotations: { readOnlyHint: false } },
    input,
  );

  const result = await adapter.run(invocation, async () => {
    // The tool's actual side effect, only reached if governance allows it.
    return { draftId: 'draft-1', to: input.to };
  });

  if (!result.allowed) {
    throw new Error(`WebMCP tool call denied: ${result.reason}`);
  }

  return result.output;
}

async function main(): Promise<void> {
  const output = await handleCreateDraftRequest({ to: 'someone@example.com', body: 'Hi!' });
  console.log('draft created:', output);
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}

export { handleCreateDraftRequest };
