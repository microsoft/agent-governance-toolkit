// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { OciManifestAdapter } from '../src/oci-manifest';
import type { AgentIdentityJSON, PolicyRule } from '../src/types';

const SAMPLE_IDENTITY: AgentIdentityJSON = {
  did: 'did:agent:weather-bot',
  publicKey: 'dGVzdC1rZXk=',
  capabilities: ['weather', 'forecasting'],
  name: 'weather-bot',
  description: 'Provides weather updates',
  organization: 'Contoso',
  status: 'active',
  createdAt: '2026-01-01T00:00:00Z',
  expiresAt: '2027-01-01T00:00:00Z',
};

const SAMPLE_RULES: PolicyRule[] = [
  { name: 'block-external', condition: "agent.type == 'external'", ruleAction: 'deny' },
  { name: 'rate-limit', condition: 'true', ruleAction: 'allow', limit: '100/hour' },
];

describe('OciManifestAdapter', () => {
  let adapter: OciManifestAdapter;

  beforeEach(() => {
    adapter = new OciManifestAdapter();
  });

  describe('identityToAICard()', () => {
    it('converts AGT identity to AI Card', () => {
      const card = adapter.identityToAICard(SAMPLE_IDENTITY);
      expect(card.name).toBe('weather-bot');
      expect(card.description).toBe('Provides weather updates');
      expect(card.author).toBe('Contoso');
      expect(card.capabilities?.domains).toEqual(['weather', 'forecasting']);
    });

    it('uses DID as name fallback', () => {
      const identity = { ...SAMPLE_IDENTITY, name: undefined };
      const card = adapter.identityToAICard(identity);
      expect(card.name).toBe('did:agent:weather-bot');
    });

    it('preserves DID in metadata', () => {
      const card = adapter.identityToAICard(SAMPLE_IDENTITY);
      expect((card.metadata as Record<string, unknown>).did).toBe('did:agent:weather-bot');
    });

    it('includes delegation info in metadata', () => {
      const identity = { ...SAMPLE_IDENTITY, parentDid: 'did:agent:parent', delegationDepth: 2 };
      const card = adapter.identityToAICard(identity);
      expect((card.metadata as Record<string, unknown>).parentDid).toBe('did:agent:parent');
      expect((card.metadata as Record<string, unknown>).delegationDepth).toBe(2);
    });

    it('merges extra fields', () => {
      const card = adapter.identityToAICard(SAMPLE_IDENTITY, {
        version: '2.0.0',
        license: 'MIT',
        homepage: 'https://contoso.com',
      });
      expect(card.version).toBe('2.0.0');
      expect(card.license).toBe('MIT');
      expect(card.homepage).toBe('https://contoso.com');
    });
  });

  describe('aiCardToIdentity()', () => {
    it('converts AI Card back to AGT identity', () => {
      const card = adapter.identityToAICard(SAMPLE_IDENTITY);
      const identity = adapter.aiCardToIdentity(card, 'dGVzdC1rZXk=');
      expect(identity.did).toBe('did:agent:weather-bot');
      expect(identity.name).toBe('weather-bot');
      expect(identity.publicKey).toBe('dGVzdC1rZXk=');
      expect(identity.capabilities).toEqual(['weather', 'forecasting']);
      expect(identity.organization).toBe('Contoso');
    });

    it('generates DID from name if not in metadata', () => {
      const card = { name: 'my-agent', version: '1.0.0' };
      const identity = adapter.aiCardToIdentity(card, 'key');
      expect(identity.did).toBe('did:agent:my-agent');
    });
  });

  describe('package()', () => {
    it('creates valid OCI manifest with AI Card layer', () => {
      const result = adapter.package(SAMPLE_IDENTITY);
      expect(result.manifest.schemaVersion).toBe(2);
      expect(result.manifest.layers).toHaveLength(1);
      expect(result.manifest.layers[0].mediaType).toBe('application/vnd.ai-card.agent.v1+json');
    });

    it('includes policy layer when rules provided', () => {
      const result = adapter.package(SAMPLE_IDENTITY, SAMPLE_RULES);
      expect(result.manifest.layers).toHaveLength(2);
      expect(result.manifest.layers[1].mediaType).toBe('application/vnd.agt.policy.v1+json');
    });

    it('populates OCI annotations', () => {
      const result = adapter.package(SAMPLE_IDENTITY);
      const annotations = result.manifest.annotations!;
      expect(annotations['org.opencontainers.image.title']).toBe('weather-bot');
      expect(annotations['dev.agt.did']).toBe('did:agent:weather-bot');
      expect(annotations['org.opencontainers.image.vendor']).toBe('Contoso');
    });

    it('produces valid digests for all layers', () => {
      const result = adapter.package(SAMPLE_IDENTITY, SAMPLE_RULES);
      for (const layer of result.layers) {
        expect(layer.descriptor.digest).toMatch(/^sha256:[0-9a-f]{64}$/);
        expect(layer.descriptor.size).toBeGreaterThan(0);
      }
    });

    it('round-trips identity through package/unpack', () => {
      const result = adapter.package(SAMPLE_IDENTITY);
      const unpacked = adapter.unpackAICard(result.layers);
      expect(unpacked).not.toBeNull();
      expect(unpacked!.name).toBe('weather-bot');
      expect(unpacked!.description).toBe('Provides weather updates');
    });

    it('round-trips policy rules through package/unpack', () => {
      const result = adapter.package(SAMPLE_IDENTITY, SAMPLE_RULES);
      const rules = adapter.unpackPolicies(result.layers);
      expect(rules).toHaveLength(2);
      expect(rules[0].name).toBe('block-external');
      expect(rules[1].limit).toBe('100/hour');
    });
  });

  describe('unpackAICard()', () => {
    it('returns null for empty layers', () => {
      expect(adapter.unpackAICard([])).toBeNull();
    });

    it('returns null for invalid JSON', () => {
      const layers = [{
        descriptor: { mediaType: 'application/vnd.ai-card.agent.v1+json', digest: 'sha256:abc', size: 3 },
        content: '{{{invalid',
      }];
      expect(adapter.unpackAICard(layers)).toBeNull();
    });
  });

  describe('unpackPolicies()', () => {
    it('returns empty array for layers without policy', () => {
      expect(adapter.unpackPolicies([])).toEqual([]);
    });
  });

  describe('verifyManifest()', () => {
    it('validates a correctly packaged manifest', () => {
      const result = adapter.package(SAMPLE_IDENTITY, SAMPLE_RULES);
      const verification = adapter.verifyManifest(result.manifest, result.layers, result.configBlob);
      expect(verification.valid).toBe(true);
      expect(verification.errors).toHaveLength(0);
    });

    it('detects tampered layer content', () => {
      const result = adapter.package(SAMPLE_IDENTITY);
      result.layers[0].content = '{"name": "tampered"}';
      const verification = adapter.verifyManifest(result.manifest, result.layers, result.configBlob);
      expect(verification.valid).toBe(false);
      expect(verification.errors.length).toBeGreaterThan(0);
    });

    it('detects tampered config', () => {
      const result = adapter.package(SAMPLE_IDENTITY);
      const verification = adapter.verifyManifest(result.manifest, result.layers, 'tampered config');
      expect(verification.valid).toBe(false);
      expect(verification.errors.some((e) => e.includes('Config digest'))).toBe(true);
    });

    it('detects size mismatch', () => {
      const result = adapter.package(SAMPLE_IDENTITY);
      result.layers[0].descriptor.size = 999999;
      const verification = adapter.verifyManifest(result.manifest, result.layers, result.configBlob);
      expect(verification.valid).toBe(false);
      expect(verification.errors.some((e) => e.includes('size mismatch'))).toBe(true);
    });
  });
});
