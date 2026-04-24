// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { AgentIdentity } from '../src/identity';

describe('AgentIdentity', () => {
  let identity: AgentIdentity;

  beforeEach(() => {
    identity = AgentIdentity.generate('test-agent', ['read', 'write']);
  });

  describe('generate()', () => {
    it('creates an identity with a valid DID', () => {
      expect(identity.did).toMatch(/^did:agentmesh:test-agent:[0-9a-f]{16}$/);
    });

    it('creates an identity with a public key', () => {
      expect(identity.publicKey).toBeInstanceOf(Uint8Array);
      expect(identity.publicKey.length).toBeGreaterThan(0);
    });

    it('assigns capabilities', () => {
      expect(identity.capabilities).toEqual(['read', 'write']);
    });

    it('defaults to empty capabilities', () => {
      const id = AgentIdentity.generate('bare-agent');
      expect(id.capabilities).toEqual([]);
    });

    it('produces unique DIDs for different agents', () => {
      const other = AgentIdentity.generate('other-agent');
      expect(other.did).not.toEqual(identity.did);
    });
  });

  describe('sign() / verify()', () => {
    it('signs and verifies data correctly', () => {
      const data = new TextEncoder().encode('hello agentmesh');
      const signature = identity.sign(data);

      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBeGreaterThan(0);
      expect(identity.verify(data, signature)).toBe(true);
    });

    it('rejects tampered data', () => {
      const data = new TextEncoder().encode('original');
      const signature = identity.sign(data);
      const tampered = new TextEncoder().encode('tampered');

      expect(identity.verify(tampered, signature)).toBe(false);
    });

    it('rejects invalid signature', () => {
      const data = new TextEncoder().encode('test');
      const badSig = new Uint8Array(64).fill(0);

      expect(identity.verify(data, badSig)).toBe(false);
    });
  });

  describe('toJSON() / fromJSON()', () => {
    it('round-trips through JSON serialization', () => {
      const json = identity.toJSON();
      const restored = AgentIdentity.fromJSON(json);

      expect(restored.did).toEqual(identity.did);
      expect(restored.capabilities).toEqual(identity.capabilities);
    });

    it('produces valid JSON fields', () => {
      const json = identity.toJSON();
      expect(json).toHaveProperty('did');
      expect(json).toHaveProperty('publicKey');
      expect(json).toHaveProperty('privateKey');
      expect(json).toHaveProperty('capabilities');
      expect(typeof json.publicKey).toBe('string');
    });

    it('restored identity can sign and verify', () => {
      const json = identity.toJSON();
      const restored = AgentIdentity.fromJSON(json);
      const data = new TextEncoder().encode('roundtrip test');
      const sig = restored.sign(data);

      expect(restored.verify(data, sig)).toBe(true);
    });
  });
});
