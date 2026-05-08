// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { mkdtempSync, rmSync, writeFileSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { GovernanceVerifier } from '../src/verify';

describe('GovernanceVerifier', () => {
  const tempDirs: string[] = [];

  afterEach(() => {
    while (tempDirs.length > 0) {
      rmSync(tempDirs.pop() as string, { recursive: true, force: true });
    }
  });

  it('produces a passing attestation for the default SDK controls', () => {
    const verifier = new GovernanceVerifier();
    const attestation = verifier.verify();

    expect(attestation.passed).toBe(true);
    expect(attestation.controlsPassed).toBe(attestation.controlsTotal);
    expect(attestation.coveragePct()).toBe(100);
    expect(attestation.complianceGrade()).toBe('A');
    expect(attestation.attestationHash).toHaveLength(64);
    expect(attestation.summary()).toContain('component attestation');
  });

  it('reports missing controls', () => {
    const verifier = new GovernanceVerifier({
      'ASI-01': {
        name: 'Prompt Injection',
        component: undefined,
      },
      'ASI-02': {
        name: 'Insecure Tool Use',
        component: class PresentControl {},
      },
    });

    const attestation = verifier.verify();
    expect(attestation.passed).toBe(false);
    expect(attestation.controlsPassed).toBe(1);
    expect(attestation.controls.find((control) => control.controlId === 'ASI-01')?.error).toBe('Component missing');
  });

  it('verifies runtime evidence from a YAML manifest', () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'agt-verify-'));
    tempDirs.push(tempDir);
    const evidencePath = join(tempDir, 'runtime-evidence.yaml');
    writeFileSync(evidencePath, [
      'schema: agt-runtime-evidence/v1',
      'generatedAt: 2026-04-24T00:00:00.000Z',
      'toolkitVersion: 3.5.0',
      'deployment:',
      '  agentId: ts-agent',
      '  identity:',
      '    enabled: true',
      '    did: did:mesh:ts-agent',
      '  policy:',
      '    failClosed: true',
      '    defaultAction: deny',
      '    backends:',
      '      - opa',
      '      - cedar',
      '  audit:',
      '    enabled: true',
      '    destination: audit-chain',
      '  execution:',
      '    rings: true',
      '    killSwitch: true',
      '  promptDefense:',
      '    enabled: true',
      '    vectorsCovered:',
      '      - direct-instruction-override',
      '      - tool-output-poisoning',
      '  sre:',
      '    metrics: true',
      '    traces: true',
      '    sloTargets:',
      '      - governance-availability',
      '  discovery:',
      '    enabled: true',
      '    shadowAgents: 0',
    ].join('\n'));

    const attestation = new GovernanceVerifier().verify({ evidencePath, strict: true });

    expect(attestation.passed).toBe(true);
    expect(attestation.mode).toBe('runtime-evidence');
    expect(attestation.evidenceChecks).toHaveLength(10);
    expect(attestation.evidenceChecks.every((check) => check.status === 'pass')).toBe(true);
    expect(attestation.summary()).toContain('Runtime evidence');
  });

  it('fails when runtime evidence is required but missing', () => {
    const attestation = new GovernanceVerifier().verify({ requireRuntimeEvidence: true });

    expect(attestation.passed).toBe(false);
    expect(attestation.failures).toContain('Runtime evidence is required but was not provided.');
  });

  it('detects integrity manifest tampering', () => {
    const verifier = new GovernanceVerifier();
    const manifest = verifier.generateIntegrityManifest();
    manifest.files[0] = { ...manifest.files[0], sha256: '0'.repeat(64) };

    const attestation = verifier.verify({ integrityManifest: manifest, strict: true });

    expect(attestation.passed).toBe(false);
    expect(attestation.mode).toBe('integrity');
    expect(attestation.fileIntegrityResults.some((result) => !result.passed)).toBe(true);
    expect(attestation.failures.some((failure) => failure.includes('hash mismatch'))).toBe(true);
  });
});
