// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { ConflictResolutionStrategy, PolicyEngine } from '../src';

const agentDid = 'did:agentmesh:assistant-01';

// Legacy flat rules are useful for quick action checks.
const legacyEngine = new PolicyEngine([
  { action: 'data.read', effect: 'allow' },
  { action: 'data.export', effect: 'review', conditions: { role: 'analyst' } },
  { action: '*', effect: 'deny' },
]);

console.log('legacy:data.read', legacyEngine.evaluate('data.read'));
console.log(
  'legacy:data.export',
  legacyEngine.evaluate('data.export', { role: 'analyst' }),
);

// Rich policy documents support named rules, conditions, priority, and approval.
const richEngine = new PolicyEngine(
  undefined,
  ConflictResolutionStrategy.DenyOverrides,
);

richEngine.loadYaml(`
apiVersion: governance.toolkit/v1
name: production-access
scope: agent
agents:
  - ${agentDid}
default_action: deny
rules:
  - name: allow-read-tools
    description: Low-risk read-only tool calls are allowed.
    condition: "action == 'tool.read' and environment == 'production'"
    ruleAction: allow
    priority: 10
  - name: review-deployments
    description: Production deployments require a human reviewer.
    condition: "action == 'deploy.release' and environment == 'production'"
    ruleAction: require_approval
    approvers:
      - sre-oncall
    priority: 20
  - name: deny-dangerous-tools
    description: Shell access is blocked in production.
    condition: "action == 'tool.shell' and environment == 'production'"
    ruleAction: deny
    priority: 30
`);

const actionContext = {
  action: 'deploy.release',
  environment: 'production',
  actor: 'release-bot',
};

const decision = richEngine.evaluatePolicy(agentDid, actionContext);

console.log('rich:action', decision.action);
console.log('rich:allowed', decision.allowed);
console.log('rich:matchedRule', decision.matchedRule);
console.log('rich:approvers', decision.approvers.join(', ') || 'none');
