// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { AgentIdentity, stripKeyPrefix, safeBase64Decode } from '../src/identity';

describe('stripKeyPrefix', () => {
  it('strips the expected ed25519: prefix', () => {
    const raw = 'AAAA';
    expect(stripKeyPrefix(`ed25519:${raw}`, 'ed25519:')).toBe(raw);
  });

  it('strips the expected x25519: prefix', () => {
    const raw = 'BBBB';
    expect(stripKeyPrefix(`x25519:${raw}`, 'x25519:')).toBe(raw);
  });

  it('strips an unexpected prefix with a warning', () => {
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation();
    const result = stripKeyPrefix('x25519:CCCC', 'ed25519:');
    expect(result).toBe('CCCC');
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("expected 'ed25519:'"),
    );
    warnSpy.mockRestore();
  });

  it('returns unprefixed keys as-is', () => {
    expect(stripKeyPrefix('DDDD', 'ed25519:')).toBe('DDDD');
  });

  it('handles empty string', () => {
    expect(stripKeyPrefix('', 'ed25519:')).toBe('');
  });
});

describe('safeBase64Decode', () => {
  const sampleBytes = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
  const sampleB64 = sampleBytes.toString('base64'); // "3q2+7w=="

  it('decodes plain base64', () => {
    expect(safeBase64Decode(sampleB64)).toEqual(sampleBytes);
  });

  it('strips ed25519: prefix before decoding', () => {
    expect(safeBase64Decode(`ed25519:${sampleB64}`)).toEqual(sampleBytes);
  });

  it('strips x25519: prefix before decoding', () => {
    expect(safeBase64Decode(`x25519:${sampleB64}`)).toEqual(sampleBytes);
  });

  it('returns empty buffer for empty string', () => {
    expect(safeBase64Decode('')).toEqual(Buffer.alloc(0));
  });
});

describe('AgentIdentity.fromJSON with prefixed keys', () => {
  let identity: AgentIdentity;
  let json: ReturnType<AgentIdentity['toJSON']>;

  beforeEach(() => {
    identity = AgentIdentity.generate('prefix-test', ['read']);
    json = identity.toJSON();
  });

  it('round-trips with plain (unprefixed) base64 keys', () => {
    const restored = AgentIdentity.fromJSON(json);
    expect(restored.did).toBe(identity.did);

    const data = new TextEncoder().encode('round-trip');
    const sig = restored.sign(data);
    expect(restored.verify(data, sig)).toBe(true);
  });

  it('deserializes keys that carry an ed25519: prefix', () => {
    // Simulate a serialized identity whose keys were stored with prefix
    const prefixed = {
      ...json,
      publicKey: `ed25519:${json.publicKey}`,
      privateKey: json.privateKey ? `ed25519:${json.privateKey}` : undefined,
    };

    const restored = AgentIdentity.fromJSON(prefixed);
    expect(restored.did).toBe(identity.did);

    const data = new TextEncoder().encode('prefixed-key test');
    const sig = restored.sign(data);
    expect(restored.verify(data, sig)).toBe(true);
  });

  it('deserializes keys that carry an x25519: prefix', () => {
    // x25519 prefix on ed25519 DER bytes is unusual but stripKeyPrefix
    // handles "wrong prefix" gracefully.
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation();

    const prefixed = {
      ...json,
      publicKey: `x25519:${json.publicKey}`,
      privateKey: json.privateKey ? `x25519:${json.privateKey}` : undefined,
    };

    const restored = AgentIdentity.fromJSON(prefixed);
    expect(restored.did).toBe(identity.did);

    const data = new TextEncoder().encode('wrong-prefix test');
    const sig = restored.sign(data);
    expect(restored.verify(data, sig)).toBe(true);

    warnSpy.mockRestore();
  });

  it('handles missing privateKey gracefully', () => {
    const pubOnly = { ...json, privateKey: undefined };
    const restored = AgentIdentity.fromJSON(pubOnly);
    expect(restored.did).toBe(identity.did);
  });
});
