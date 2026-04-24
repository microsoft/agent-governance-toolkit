// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as crypto from 'crypto';
import { TrustManager } from '../src/trust';

function tempFilePath(): string {
  return path.join(os.tmpdir(), `trust-${crypto.randomUUID()}.json`);
}

afterEach(() => {
  // cleanup is best-effort; individual tests also clean up
});

describe('TrustManager persistence', () => {
  it('persists scores across instances', () => {
    const file = tempFilePath();
    try {
      const tm1 = new TrustManager({ initialScore: 0.5, persistPath: file });
      tm1.recordSuccess('agent-a', 0.1);
      tm1.recordFailure('agent-b', 0.2);

      // Second instance should load persisted state
      const tm2 = new TrustManager({ initialScore: 0.5, persistPath: file });
      expect(tm2.getTrustScore('agent-a').overall).toBeGreaterThan(0.5);
      expect(tm2.getTrustScore('agent-b').overall).toBeLessThan(0.5);
    } finally {
      try { fs.unlinkSync(file); } catch { /* ignore */ }
    }
  });

  it('handles missing file gracefully', () => {
    const file = tempFilePath(); // does not exist
    expect(() => {
      const tm = new TrustManager({ initialScore: 0.5, persistPath: file });
      expect(tm.getTrustScore('agent-x').overall).toBe(0.5);
    }).not.toThrow();
  });

  it('handles corrupt file gracefully', () => {
    const file = tempFilePath();
    try {
      fs.writeFileSync(file, '<<<not json>>>', 'utf-8');
      expect(() => {
        const tm = new TrustManager({ initialScore: 0.5, persistPath: file });
        expect(tm.getTrustScore('agent-x').overall).toBe(0.5);
      }).not.toThrow();
    } finally {
      try { fs.unlinkSync(file); } catch { /* ignore */ }
    }
  });

  it('does not persist when persistPath is not set', () => {
    const tm = new TrustManager({ initialScore: 0.5 });
    tm.recordSuccess('agent-a', 0.1);
    // No error, no file created — just verifying the code path works
    expect(tm.getTrustScore('agent-a').overall).toBeGreaterThan(0.5);
  });
});
