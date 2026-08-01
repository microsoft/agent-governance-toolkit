// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import {
  ApprovalCoordinator,
  ApprovalProtocolError,
  InMemoryApprovalStore,
  ReasonCode,
  bindingDigest,
  canonicalize,
  getStage,
  makeActionBinding,
  makeActionTarget,
  makeApprovalStage,
  sha256Jcs,
  stageAuthorizes,
  verifyEntryDigest,
} from '../src/approval-protocol';
import type { ApprovalChain } from '../src/approval-protocol';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const ALICE = 'alice';
const BOB = 'bob';

function makeChain(id = 'default', identities: string[] = [ALICE]): ApprovalChain {
  return {
    chainId: id,
    version: '1',
    stages: [makeApprovalStage({ stageIndex: 0, allowedIdentities: identities })],
  };
}

function makeCoordinator(chain = makeChain()) {
  const store = new InMemoryApprovalStore();
  const chains = new Map([[chain.chainId, chain]]);
  return new ApprovalCoordinator(store, chains);
}

function makeBinding(params: Record<string, unknown> = {}) {
  return makeActionBinding({
    operation: 'tool.invoke',
    agentId: 'agent-1',
    target: makeActionTarget({ toolName: 'transfer', toolSchemaVersion: '1.0' }),
    parameters: params,
  });
}

// ---------------------------------------------------------------------------
// JCS canonicalization + digest
// ---------------------------------------------------------------------------

describe('canonicalize / sha256Jcs', () => {
  it('sorts object keys by UTF-16 code unit order', () => {
    const obj = { z: 1, a: 2, m: 3 };
    const canonical = canonicalize(obj).toString('utf8');
    expect(canonical).toBe('{"a":2,"m":3,"z":1}');
  });

  it('serializes null', () => {
    expect(canonicalize(null).toString()).toBe('null');
  });

  it('serializes booleans', () => {
    expect(canonicalize(true).toString()).toBe('true');
    expect(canonicalize(false).toString()).toBe('false');
  });

  it('serializes integers without decimal', () => {
    expect(canonicalize(42).toString()).toBe('42');
    expect(canonicalize(-7).toString()).toBe('-7');
  });

  it('serializes arrays', () => {
    expect(canonicalize([1, 'two', null]).toString()).toBe('[1,"two",null]');
  });

  it('rejects NaN', () => {
    expect(() => canonicalize(NaN)).toThrow();
  });

  it('rejects Infinity', () => {
    expect(() => canonicalize(Infinity)).toThrow();
  });

  it('sha256Jcs returns sha256: prefix', () => {
    const d = sha256Jcs({ foo: 'bar' });
    expect(d.startsWith('sha256:')).toBe(true);
    expect(d).toHaveLength(7 + 64);
  });

  it('sha256Jcs is deterministic', () => {
    expect(sha256Jcs({ b: 2, a: 1 })).toBe(sha256Jcs({ a: 1, b: 2 }));
  });
});

// ---------------------------------------------------------------------------
// ActionBinding / bindingDigest
// ---------------------------------------------------------------------------

describe('bindingDigest', () => {
  it('different parameters produce different digests', () => {
    const b1 = makeBinding({ amount: 100 });
    const b2 = makeBinding({ amount: 999 });
    expect(bindingDigest(b1)).not.toBe(bindingDigest(b2));
  });

  it('same parameters produce same digest', () => {
    const b1 = makeBinding({ amount: 100 });
    const b2 = makeBinding({ amount: 100 });
    expect(bindingDigest(b1)).toBe(bindingDigest(b2));
  });
});

// ---------------------------------------------------------------------------
// ApprovalCoordinator — openRequest
// ---------------------------------------------------------------------------

describe('ApprovalCoordinator.openRequest', () => {
  it('opens a pending request', () => {
    const coord = makeCoordinator();
    const binding = makeBinding({ amount: 100 });
    const { request } = coord.openRequest(binding, {
      policyRuleId: 'rule-1',
      policyVersion: 'v1',
      chainId: 'default',
      ttlSeconds: 300,
    });
    expect(request.status).toBe('pending');
    expect(request.actionDigest).toBe(bindingDigest(binding));
  });

  it('throws on unknown chain', () => {
    const coord = makeCoordinator();
    expect(() =>
      coord.openRequest(makeBinding(), {
        policyRuleId: 'r',
        policyVersion: 'v1',
        chainId: 'nonexistent',
        ttlSeconds: 300,
      }),
    ).toThrow(ApprovalProtocolError);
  });
});

// ---------------------------------------------------------------------------
// ApprovalCoordinator — submitEntry
// ---------------------------------------------------------------------------

describe('ApprovalCoordinator.submitEntry', () => {
  it('allowed entry resolves request to allowed', () => {
    const store = new InMemoryApprovalStore();
    const chain = makeChain();
    const coord = new ApprovalCoordinator(store, new Map([[chain.chainId, chain]]));
    const { request } = coord.openRequest(makeBinding(), {
      policyRuleId: 'r',
      policyVersion: 'v1',
      chainId: 'default',
      ttlSeconds: 300,
    });
    coord.submitEntry(request.approvalRequestId, {
      stageIndex: 0,
      approverKind: 'human',
      approverIdentity: ALICE,
      identityAssurance: 'session',
      decision: 'allow',
    });
    expect(store.getRequest(request.approvalRequestId)!.status).toBe('allowed');
    expect(store.getResolution(request.approvalRequestId)!.outcome).toBe('allow');
  });

  it('deny entry resolves request to denied immediately', () => {
    const store = new InMemoryApprovalStore();
    const chain = makeChain();
    const coord = new ApprovalCoordinator(store, new Map([[chain.chainId, chain]]));
    const { request } = coord.openRequest(makeBinding(), {
      policyRuleId: 'r',
      policyVersion: 'v1',
      chainId: 'default',
      ttlSeconds: 300,
    });
    coord.submitEntry(request.approvalRequestId, {
      stageIndex: 0,
      approverKind: 'human',
      approverIdentity: ALICE,
      identityAssurance: 'session',
      decision: 'deny',
    });
    expect(store.getRequest(request.approvalRequestId)!.status).toBe('denied');
  });

  it('unpermitted identity throws', () => {
    const coord = makeCoordinator();
    const { request } = coord.openRequest(makeBinding(), {
      policyRuleId: 'r',
      policyVersion: 'v1',
      chainId: 'default',
      ttlSeconds: 300,
    });
    expect(() =>
      coord.submitEntry(request.approvalRequestId, {
        stageIndex: 0,
        approverKind: 'human',
        approverIdentity: 'mallory',
        identityAssurance: 'session',
        decision: 'allow',
      }),
    ).toThrow(ApprovalProtocolError);
  });

  it('llm_advisory entry does not satisfy stage', () => {
    const store = new InMemoryApprovalStore();
    const chain = makeChain();
    const coord = new ApprovalCoordinator(store, new Map([[chain.chainId, chain]]));
    const { request } = coord.openRequest(makeBinding(), {
      policyRuleId: 'r',
      policyVersion: 'v1',
      chainId: 'default',
      ttlSeconds: 300,
    });
    coord.submitEntry(request.approvalRequestId, {
      stageIndex: 0,
      approverKind: 'llm_advisory',
      approverIdentity: 'model-x',
      identityAssurance: 'advisory',
      decision: 'allow',
    });
    // Advisory vote alone must not resolve the request.
    expect(store.getRequest(request.approvalRequestId)!.status).toBe('pending');
  });

  it('idempotent resubmission by chainEntryId returns existing entry', () => {
    const coord = makeCoordinator();
    const { request } = coord.openRequest(makeBinding(), {
      policyRuleId: 'r',
      policyVersion: 'v1',
      chainId: 'default',
      ttlSeconds: 300,
    });
    const e1 = coord.submitEntry(request.approvalRequestId, {
      stageIndex: 0,
      approverKind: 'human',
      approverIdentity: ALICE,
      identityAssurance: 'session',
      decision: 'allow',
      chainEntryId: 'eid-1',
    });
    const e2 = coord.submitEntry(request.approvalRequestId, {
      stageIndex: 0,
      approverKind: 'human',
      approverIdentity: ALICE,
      identityAssurance: 'session',
      decision: 'allow',
      chainEntryId: 'eid-1',
    });
    expect(e1.chainEntryId).toBe(e2.chainEntryId);
  });

  it('throws on expired request', () => {
    // Use TTL=0 so the request expires the instant the clock ticks
    const store = new InMemoryApprovalStore();
    const chain = makeChain();
    let tick = 0;
    const ticking = () => new Date(Date.now() + tick * 1000);
    const coord = new ApprovalCoordinator(store, new Map([[chain.chainId, chain]]), ticking);
    const { request } = coord.openRequest(makeBinding(), {
      policyRuleId: 'r',
      policyVersion: 'v1',
      chainId: 'default',
      ttlSeconds: 0,
    });
    tick = 1; // advance clock past expiry
    expect(() =>
      coord.submitEntry(request.approvalRequestId, {
        stageIndex: 0,
        approverKind: 'human',
        approverIdentity: ALICE,
        identityAssurance: 'session',
        decision: 'allow',
      }),
    ).toThrow(ApprovalProtocolError);
  });
});

// ---------------------------------------------------------------------------
// ApprovalCoordinator — validateForExecution
// ---------------------------------------------------------------------------

describe('ApprovalCoordinator.validateForExecution', () => {
  function setupApproved() {
    const store = new InMemoryApprovalStore();
    const chain = makeChain();
    const coord = new ApprovalCoordinator(store, new Map([[chain.chainId, chain]]));
    const binding = makeBinding({ amount: 100 });
    const { request } = coord.openRequest(binding, {
      policyRuleId: 'r',
      policyVersion: 'v1',
      chainId: 'default',
      ttlSeconds: 300,
    });
    coord.submitEntry(request.approvalRequestId, {
      stageIndex: 0,
      approverKind: 'human',
      approverIdentity: ALICE,
      identityAssurance: 'session',
      decision: 'allow',
    });
    return { coord, store, request, binding, chain };
  }

  it('returns OK and allows execution for an approved request', () => {
    const { coord, request, chain } = setupApproved();
    const result = coord.validateForExecution(request.approvalRequestId, {
      currentActionDigest: request.actionDigest,
      currentPolicyVersion: 'v1',
      currentChainVersion: chain.version,
    });
    expect(result.allowed).toBe(true);
    expect(result.reasonCode).toBe(ReasonCode.OK);
  });

  it('consumes the approval exactly once', () => {
    const { coord, store, request, chain } = setupApproved();
    coord.validateForExecution(request.approvalRequestId, {
      currentActionDigest: request.actionDigest,
      currentPolicyVersion: 'v1',
      currentChainVersion: chain.version,
    });
    expect(store.getRequest(request.approvalRequestId)!.status).toBe('consumed');
    const second = coord.validateForExecution(request.approvalRequestId, {
      currentActionDigest: request.actionDigest,
      currentPolicyVersion: 'v1',
      currentChainVersion: chain.version,
    });
    expect(second.allowed).toBe(false);
    expect(second.reasonCode).toBe(ReasonCode.ALREADY_CONSUMED);
  });

  it('rejects on action digest mismatch', () => {
    const { coord, request, chain } = setupApproved();
    const result = coord.validateForExecution(request.approvalRequestId, {
      currentActionDigest: 'sha256:deadbeef',
      currentPolicyVersion: 'v1',
      currentChainVersion: chain.version,
    });
    expect(result.allowed).toBe(false);
    expect(result.reasonCode).toBe(ReasonCode.ACTION_DIGEST_MISMATCH);
  });

  it('rejects on policy version mismatch', () => {
    const { coord, request, chain } = setupApproved();
    const result = coord.validateForExecution(request.approvalRequestId, {
      currentActionDigest: request.actionDigest,
      currentPolicyVersion: 'v2',
      currentChainVersion: chain.version,
    });
    expect(result.allowed).toBe(false);
    expect(result.reasonCode).toBe(ReasonCode.POLICY_VERSION_MISMATCH);
  });

  it('rejects on chain version mismatch', () => {
    const { coord, request } = setupApproved();
    const result = coord.validateForExecution(request.approvalRequestId, {
      currentActionDigest: request.actionDigest,
      currentPolicyVersion: 'v1',
      currentChainVersion: 'v99',
    });
    expect(result.allowed).toBe(false);
    expect(result.reasonCode).toBe(ReasonCode.CHAIN_VERSION_MISMATCH);
  });

  it('rejects unknown request', () => {
    const coord = makeCoordinator();
    const result = coord.validateForExecution('nonexistent', {
      currentActionDigest: 'sha256:abc',
      currentPolicyVersion: 'v1',
      currentChainVersion: '1',
    });
    expect(result.allowed).toBe(false);
    expect(result.reasonCode).toBe(ReasonCode.UNKNOWN_REQUEST);
  });

  it('rejects expired request (TTL=0)', () => {
    const store = new InMemoryApprovalStore();
    const chain = makeChain();
    let tick = 0;
    const ticking = () => new Date(Date.now() + tick * 1000);
    const coord = new ApprovalCoordinator(store, new Map([[chain.chainId, chain]]), ticking);
    const binding = makeBinding({ amount: 100 });
    const { request } = coord.openRequest(binding, {
      policyRuleId: 'r',
      policyVersion: 'v1',
      chainId: 'default',
      ttlSeconds: 0,
    });
    tick = 1; // advance clock past expiry
    const result = coord.validateForExecution(request.approvalRequestId, {
      currentActionDigest: request.actionDigest,
      currentPolicyVersion: 'v1',
      currentChainVersion: chain.version,
    });
    expect(result.allowed).toBe(false);
    expect(result.reasonCode).toBe(ReasonCode.EXPIRED);
  });
});

// ---------------------------------------------------------------------------
// _maybeResolve — zero required stages (fail-closed)
// ---------------------------------------------------------------------------

describe('ApprovalCoordinator zero-required-stages guard', () => {
  it('denies immediately when chain has no required stages (vacuous allow is unsafe)', () => {
    const store = new InMemoryApprovalStore();
    // All stages are advisory-only (required: false) → zero required stages
    const chain: ApprovalChain = {
      chainId: 'no-required',
      version: '1',
      stages: [makeApprovalStage({ stageIndex: 0, allowedIdentities: [ALICE], required: false })],
    };
    const coord = new ApprovalCoordinator(store, new Map([[chain.chainId, chain]]));
    const { request } = coord.openRequest(makeBinding(), {
      policyRuleId: 'r',
      policyVersion: 'v1',
      chainId: 'no-required',
      ttlSeconds: 300,
    });
    coord.submitEntry(request.approvalRequestId, {
      stageIndex: 0,
      approverKind: 'human',
      approverIdentity: ALICE,
      identityAssurance: 'session',
      decision: 'allow',
    });
    // A chain with zero required stages must not vacuously resolve to allow.
    const req = store.getRequest(request.approvalRequestId)!;
    expect(req.status).toBe('denied');
    expect(store.getResolution(request.approvalRequestId)!.outcome).toBe('deny');
  });
});

// ---------------------------------------------------------------------------
// Chain integrity
// ---------------------------------------------------------------------------

describe('chain integrity', () => {
  it('verifyEntryDigest returns true for a sealed entry', () => {
    const coord = makeCoordinator();
    const { request } = coord.openRequest(makeBinding(), {
      policyRuleId: 'r',
      policyVersion: 'v1',
      chainId: 'default',
      ttlSeconds: 300,
    });
    const entry = coord.submitEntry(request.approvalRequestId, {
      stageIndex: 0,
      approverKind: 'human',
      approverIdentity: ALICE,
      identityAssurance: 'session',
      decision: 'allow',
    });
    expect(verifyEntryDigest(entry)).toBe(true);
  });

  it('rejects tampered chain', () => {
    const store = new InMemoryApprovalStore();
    const chain = makeChain();
    const coord = new ApprovalCoordinator(store, new Map([[chain.chainId, chain]]));
    const { request } = coord.openRequest(makeBinding(), {
      policyRuleId: 'r',
      policyVersion: 'v1',
      chainId: 'default',
      ttlSeconds: 300,
    });
    const entry = coord.submitEntry(request.approvalRequestId, {
      stageIndex: 0,
      approverKind: 'human',
      approverIdentity: ALICE,
      identityAssurance: 'session',
      decision: 'allow',
    });
    // Tamper with the entry digest
    entry.entryDigest = 'sha256:' + '0'.repeat(64);
    const result = coord.validateForExecution(request.approvalRequestId, {
      currentActionDigest: request.actionDigest,
      currentPolicyVersion: 'v1',
      currentChainVersion: chain.version,
    });
    expect(result.allowed).toBe(false);
    expect(result.reasonCode).toBe(ReasonCode.CHAIN_TAMPERED);
  });
});

// ---------------------------------------------------------------------------
// InMemoryApprovalStore
// ---------------------------------------------------------------------------

describe('InMemoryApprovalStore', () => {
  it('consume returns true once, then false', () => {
    const coord = makeCoordinator();
    const { request } = coord.openRequest(makeBinding(), {
      policyRuleId: 'r',
      policyVersion: 'v1',
      chainId: 'default',
      ttlSeconds: 300,
    });
    coord.submitEntry(request.approvalRequestId, {
      stageIndex: 0,
      approverKind: 'human',
      approverIdentity: ALICE,
      identityAssurance: 'session',
      decision: 'allow',
    });
    const store = new InMemoryApprovalStore();
    // Direct store test
    const store2 = new InMemoryApprovalStore();
    const chain = makeChain();
    const coord2 = new ApprovalCoordinator(store2, new Map([[chain.chainId, chain]]));
    const { request: r2 } = coord2.openRequest(makeBinding(), {
      policyRuleId: 'r',
      policyVersion: 'v1',
      chainId: 'default',
      ttlSeconds: 300,
    });
    coord2.submitEntry(r2.approvalRequestId, {
      stageIndex: 0,
      approverKind: 'human',
      approverIdentity: ALICE,
      identityAssurance: 'session',
      decision: 'allow',
    });
    expect(store2.consume(r2.approvalRequestId)).toBe(true);
    expect(store2.consume(r2.approvalRequestId)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// makeApprovalStage / stageAuthorizes / getStage
// ---------------------------------------------------------------------------

describe('ApprovalStage', () => {
  it('authorizes by identity', () => {
    const stage = makeApprovalStage({ stageIndex: 0, allowedIdentities: ['alice'] });
    expect(stageAuthorizes(stage, 'alice', [])).toBe(true);
    expect(stageAuthorizes(stage, 'bob', [])).toBe(false);
  });

  it('authorizes by role', () => {
    const stage = makeApprovalStage({ stageIndex: 0, allowedRoles: ['approver'] });
    expect(stageAuthorizes(stage, 'unknown', ['approver'])).toBe(true);
    expect(stageAuthorizes(stage, 'unknown', ['other'])).toBe(false);
  });
});
