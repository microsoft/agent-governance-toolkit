// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { AgentIdentity, IdentityRegistry } from '../src/identity';

describe('AgentIdentity — Parity Features', () => {
  let identity: AgentIdentity;

  beforeEach(() => {
    identity = AgentIdentity.generate('test-agent', ['read', 'write', 'read:data', 'read:logs'], {
      name: 'Test Agent',
      description: 'A test agent',
      sponsor: 'alice@org.com',
      organization: 'TestOrg',
    });
  });

  // ── Metadata ──

  describe('metadata', () => {
    it('stores name and description', () => {
      expect(identity.name).toBe('Test Agent');
      expect(identity.description).toBe('A test agent');
    });

    it('stores sponsor and organization', () => {
      expect(identity.sponsor).toBe('alice@org.com');
      expect(identity.organization).toBe('TestOrg');
    });

    it('sets createdAt', () => {
      expect(identity.createdAt).toBeInstanceOf(Date);
      expect(identity.createdAt.getTime()).toBeLessThanOrEqual(Date.now());
    });

    it('defaults expiresAt to null', () => {
      expect(identity.expiresAt).toBeNull();
    });

    it('supports expiresAt', () => {
      const future = new Date(Date.now() + 86400000);
      const id = AgentIdentity.generate('expiring', [], { expiresAt: future });
      expect(id.expiresAt).toEqual(future);
    });
  });

  // ── Lifecycle ──

  describe('lifecycle', () => {
    it('starts as active', () => {
      expect(identity.status).toBe('active');
      expect(identity.isActive()).toBe(true);
    });

    it('can be suspended', () => {
      identity.suspend('maintenance');
      expect(identity.status).toBe('suspended');
      expect(identity.isActive()).toBe(false);
    });

    it('can be reactivated from suspended', () => {
      identity.suspend('temp');
      identity.reactivate();
      expect(identity.status).toBe('active');
      expect(identity.isActive()).toBe(true);
    });

    it('can be revoked', () => {
      identity.revoke('compromised');
      expect(identity.status).toBe('revoked');
      expect(identity.isActive()).toBe(false);
    });

    it('cannot reactivate a revoked identity', () => {
      identity.revoke('done');
      expect(() => identity.reactivate()).toThrow('Cannot reactivate a revoked identity');
    });

    it('cannot suspend a revoked identity', () => {
      identity.revoke('done');
      expect(() => identity.suspend('test')).toThrow('Cannot suspend a revoked identity');
    });

    it('detects expired identity', () => {
      const past = new Date(Date.now() - 1000);
      const id = AgentIdentity.generate('expired', [], { expiresAt: past });
      expect(id.isActive()).toBe(false);
    });
  });

  // ── Capabilities ──

  describe('hasCapability()', () => {
    it('matches exact capability', () => {
      expect(identity.hasCapability('read')).toBe(true);
      expect(identity.hasCapability('delete')).toBe(false);
    });

    it('matches wildcard (*)', () => {
      const admin = AgentIdentity.generate('admin', ['*']);
      expect(admin.hasCapability('anything')).toBe(true);
      expect(admin.hasCapability('read:data')).toBe(true);
    });

    it('matches prefix wildcard (read:*)', () => {
      const id = AgentIdentity.generate('reader', ['read:*']);
      expect(id.hasCapability('read:data')).toBe(true);
      expect(id.hasCapability('read:logs')).toBe(true);
      expect(id.hasCapability('write:data')).toBe(false);
    });

    it('does not false-match similar prefixes', () => {
      const id = AgentIdentity.generate('agent', ['read:data']);
      expect(id.hasCapability('read:data')).toBe(true);
      expect(id.hasCapability('read:data:sub')).toBe(false);
      expect(id.hasCapability('read')).toBe(false);
    });
  });

  // ── Delegation ──

  describe('delegation', () => {
    it('creates a child with narrowed capabilities', () => {
      const child = identity.delegate('child-agent', ['read'], {
        description: 'A child agent',
      });
      expect(child.parentDid).toBe(identity.did);
      expect(child.delegationDepth).toBe(1);
      expect(child.capabilities).toEqual(['read']);
    });

    it('rejects capabilities not in parent', () => {
      expect(() => identity.delegate('bad', ['delete'])).toThrow(
        "Cannot delegate capability 'delete'",
      );
    });

    it('supports multi-level delegation', () => {
      const child = identity.delegate('l1', ['read', 'read:data']);
      const grandchild = child.delegate('l2', ['read']);
      expect(grandchild.delegationDepth).toBe(2);
      expect(grandchild.parentDid).toBe(child.did);
    });

    it('inherits sponsor/organization from parent', () => {
      const child = identity.delegate('child', ['read']);
      expect(child.sponsor).toBe('alice@org.com');
      expect(child.organization).toBe('TestOrg');
    });
  });

  // ── JWK / JWKS ──

  describe('JWK', () => {
    it('exports a valid JWK', () => {
      const jwk = identity.toJWK();
      expect(jwk.kty).toBe('OKP');
      expect(jwk.crv).toBe('Ed25519');
      expect(jwk.x).toBeTruthy();
      expect(jwk.kid).toBe(identity.did);
      expect(jwk.d).toBeUndefined();
    });

    it('includes private key when requested', () => {
      const jwk = identity.toJWK(true);
      expect(jwk.d).toBeTruthy();
    });

    it('round-trips through JWK (public only)', () => {
      const jwk = identity.toJWK();
      const restored = AgentIdentity.fromJWK(jwk);
      expect(restored.did).toBe(identity.did);

      // Public-only cannot sign, but can verify
      const data = new TextEncoder().encode('test');
      const sig = identity.sign(data);
      expect(restored.verify(data, sig)).toBe(true);
    });

    it('round-trips through JWK (with private key)', () => {
      const jwk = identity.toJWK(true);
      const restored = AgentIdentity.fromJWK(jwk);

      const data = new TextEncoder().encode('jwk roundtrip');
      const sig = restored.sign(data);
      expect(restored.verify(data, sig)).toBe(true);
    });

    it('rejects non-Ed25519 JWK', () => {
      expect(() =>
        AgentIdentity.fromJWK({ kty: 'RSA', crv: 'P-256', x: 'abc' }),
      ).toThrow('JWK must be Ed25519');
    });
  });

  describe('JWKS', () => {
    it('exports as JWK Set', () => {
      const jwks = identity.toJWKS();
      expect(jwks.keys).toHaveLength(1);
      expect(jwks.keys[0].kty).toBe('OKP');
    });

    it('imports from JWK Set', () => {
      const jwks = identity.toJWKS(true);
      const restored = AgentIdentity.fromJWKS(jwks);
      expect(restored.did).toBe(identity.did);
    });

    it('imports with kid filter', () => {
      const jwks = identity.toJWKS(true);
      const restored = AgentIdentity.fromJWKS(jwks, identity.did);
      expect(restored.did).toBe(identity.did);
    });

    it('throws on empty JWKS', () => {
      expect(() => AgentIdentity.fromJWKS({ keys: [] })).toThrow('contains no keys');
    });

    it('throws on missing kid', () => {
      const jwks = identity.toJWKS();
      expect(() => AgentIdentity.fromJWKS(jwks, 'nonexistent')).toThrow('No key with kid');
    });
  });

  // ── DID Document ──

  describe('DID Document', () => {
    it('produces a valid W3C DID Document', () => {
      const doc = identity.toDIDDocument();
      expect(doc['@context']).toEqual(['https://www.w3.org/ns/did/v1']);
      expect(doc.id).toBe(identity.did);
      expect(Array.isArray(doc.verificationMethod)).toBe(true);
      expect((doc.verificationMethod as any[]).length).toBe(1);
      expect((doc.verificationMethod as any[])[0].type).toBe('Ed25519VerificationKey2020');
      expect((doc.verificationMethod as any[])[0].controller).toBe(identity.did);
      expect(doc.authentication).toBeTruthy();
      expect((doc.service as any[])[0].type).toBe('AgentMeshIdentity');
    });
  });

  // ── JSON serialization with new fields ──

  describe('JSON serialization (extended)', () => {
    it('round-trips with metadata fields', () => {
      identity.suspend('test');
      const json = identity.toJSON();
      expect(json.name).toBe('Test Agent');
      expect(json.sponsor).toBe('alice@org.com');
      expect(json.status).toBe('suspended');

      const restored = AgentIdentity.fromJSON(json);
      expect(restored.name).toBe('Test Agent');
      expect(restored.sponsor).toBe('alice@org.com');
      expect(restored.status).toBe('suspended');
    });

    it('round-trips delegation metadata', () => {
      const child = identity.delegate('child', ['read']);
      const json = child.toJSON();
      expect(json.parentDid).toBe(identity.did);
      expect(json.delegationDepth).toBe(1);

      const restored = AgentIdentity.fromJSON(json);
      expect(restored.parentDid).toBe(identity.did);
      expect(restored.delegationDepth).toBe(1);
    });
  });
});

// ── Identity Registry ──

describe('IdentityRegistry', () => {
  let registry: IdentityRegistry;
  let id1: AgentIdentity;
  let id2: AgentIdentity;

  beforeEach(() => {
    registry = new IdentityRegistry();
    id1 = AgentIdentity.generate('agent-1', ['read'], { sponsor: 'alice@org.com' });
    id2 = AgentIdentity.generate('agent-2', ['write'], { sponsor: 'alice@org.com' });
  });

  it('registers and retrieves identities', () => {
    registry.register(id1);
    expect(registry.get(id1.did)).toBe(id1);
    expect(registry.size).toBe(1);
  });

  it('rejects duplicate registration', () => {
    registry.register(id1);
    expect(() => registry.register(id1)).toThrow('already registered');
  });

  it('revokes an identity', () => {
    registry.register(id1);
    expect(registry.revoke(id1.did, 'compromised')).toBe(true);
    expect(id1.status).toBe('revoked');
  });

  it('cascades revocation to children', () => {
    const child = id1.delegate('child', ['read']);
    registry.register(id1);
    registry.register(child);

    registry.revoke(id1.did, 'parent compromised');
    expect(child.status).toBe('revoked');
  });

  it('terminates revocation even when parentDid forms a cycle', () => {
    // A legitimate `delegate()` call cannot create a parentDid cycle, but a
    // corrupted persistence store, a custom builder, or a future bug could.
    // The cascade walks all reachable children, so without a visited-set
    // guard a cycle would recurse forever and overflow the JS call stack.
    const child = id1.delegate('child', ['read']);
    registry.register(id1);
    registry.register(child);

    // Force the cycle: id1.parentDid -> child.did, child.parentDid -> id1.did.
    (id1 as unknown as { _parentDid: string | null })._parentDid = child.did;

    expect(registry.revoke(id1.did, 'cycle test')).toBe(true);
    expect(id1.status).toBe('revoked');
    expect(child.status).toBe('revoked');
  });

  it('returns false revoking unknown DID', () => {
    expect(registry.revoke('did:nonexistent', 'reason')).toBe(false);
  });

  it('queries by sponsor', () => {
    registry.register(id1);
    registry.register(id2);
    const results = registry.getBySponsor('alice@org.com');
    expect(results).toHaveLength(2);
  });

  it('lists active identities', () => {
    registry.register(id1);
    registry.register(id2);
    id2.revoke('done');
    const active = registry.listActive();
    expect(active).toHaveLength(1);
    expect(active[0].did).toBe(id1.did);
  });
});
