// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { createHash } from 'crypto';
import { readFileSync } from 'fs';
import { load as loadYaml } from 'js-yaml';
import { AuditLogger } from './audit';
import { AgentIdentity } from './identity';
import { KillSwitch } from './kill-switch';
import { LifecycleManager } from './lifecycle';
import { McpSecurityScanner } from './mcp';
import { PolicyConflictResolver, PolicyEngine } from './policy';
import { PromptDefenseEvaluator } from './prompt-defense';
import { RingEnforcer } from './rings';
import { ShadowDiscovery } from './discovery';
import { TrustManager } from './trust';

export interface ControlResult {
  controlId: string;
  name: string;
  present: boolean;
  component: string;
  error?: string;
}

export interface RuntimeEvidenceDeployment {
  agentId?: string;
  identity?: {
    enabled?: boolean;
    did?: string;
    spiffeId?: string;
  };
  policy?: {
    failClosed?: boolean;
    defaultAction?: string;
    backends?: string[];
  };
  audit?: {
    enabled?: boolean;
    destination?: string;
  };
  execution?: {
    rings?: boolean;
    killSwitch?: boolean;
  };
  promptDefense?: {
    enabled?: boolean;
    vectorsCovered?: string[];
  };
  sre?: {
    metrics?: boolean;
    traces?: boolean;
    sloTargets?: string[];
  };
  discovery?: {
    enabled?: boolean;
    lastScanAt?: string;
    shadowAgents?: number;
  };
}

export interface RuntimeEvidence {
  sourcePath?: string;
  schema: string;
  generatedAt: string;
  toolkitVersion: string;
  deployment: RuntimeEvidenceDeployment;
}

export interface RuntimeEvidenceCheck {
  checkId: string;
  title: string;
  status: 'pass' | 'fail';
  message: string;
  observed: Record<string, unknown>;
}

export interface IntegrityManifestFile {
  targetId: string;
  label: string;
  modulePath: string;
  filePath: string;
  sha256: string;
}

export interface IntegrityManifest {
  schema: string;
  generatedAt: string;
  toolkitVersion: string;
  files: IntegrityManifestFile[];
}

export interface FileIntegrityResult {
  targetId: string;
  label: string;
  modulePath: string;
  filePath: string;
  expectedHash?: string;
  actualHash: string;
  passed: boolean;
  error?: string;
}

export interface GovernanceVerificationOptions {
  strict?: boolean;
  runtimeEvidence?: RuntimeEvidence;
  evidencePath?: string;
  integrityManifest?: IntegrityManifest;
  requireRuntimeEvidence?: boolean;
  requireIntegrityManifest?: boolean;
}

export interface GovernanceAttestation {
  passed: boolean;
  controls: ControlResult[];
  toolkitVersion: string;
  runtime: string;
  verifiedAt: string;
  attestationHash: string;
  controlsPassed: number;
  controlsTotal: number;
  mode: 'components' | 'runtime-evidence' | 'integrity';
  strict: boolean;
  evidenceSource?: string;
  evidenceChecks: RuntimeEvidenceCheck[];
  fileIntegrityResults: FileIntegrityResult[];
  failures: string[];
  coveragePct(): number;
  complianceGrade(): string;
  summary(): string;
}

export interface VerifierControlSpec {
  name: string;
  component: unknown;
}

interface IntegrityTargetSpec {
  targetId: string;
  label: string;
  modulePath: string;
}

const RUNTIME_EVIDENCE_SCHEMA = 'agt-runtime-evidence/v1';
const INTEGRITY_MANIFEST_SCHEMA = 'agt-typescript-integrity/v1';

const DEFAULT_CONTROLS: Record<string, VerifierControlSpec> = {
  'ASI-01': { name: 'Prompt Injection', component: PromptDefenseEvaluator },
  'ASI-02': { name: 'Insecure Tool Use', component: McpSecurityScanner },
  'ASI-03': { name: 'Excessive Agency', component: RingEnforcer },
  'ASI-04': { name: 'Unauthorized Escalation', component: KillSwitch },
  'ASI-05': { name: 'Trust Boundary Violation', component: TrustManager },
  'ASI-06': { name: 'Insufficient Logging', component: AuditLogger },
  'ASI-07': { name: 'Insecure Identity', component: AgentIdentity },
  'ASI-08': { name: 'Policy Bypass', component: PolicyConflictResolver },
  'ASI-09': { name: 'Supply Chain Integrity', component: PolicyEngine },
  'ASI-10': { name: 'Behavioral Anomaly', component: LifecycleManager },
};

const DEFAULT_INTEGRITY_TARGETS: IntegrityTargetSpec[] = [
  { targetId: 'INT-01', label: 'Policy Engine', modulePath: './policy' },
  { targetId: 'INT-02', label: 'Audit Logger', modulePath: './audit' },
  { targetId: 'INT-03', label: 'Trust Manager', modulePath: './trust' },
  { targetId: 'INT-04', label: 'Agent Identity', modulePath: './identity' },
  { targetId: 'INT-05', label: 'Lifecycle Manager', modulePath: './lifecycle' },
  { targetId: 'INT-06', label: 'MCP Security Scanner', modulePath: './mcp' },
  { targetId: 'INT-07', label: 'Prompt Defense', modulePath: './prompt-defense' },
  { targetId: 'INT-08', label: 'Execution Rings', modulePath: './rings' },
  { targetId: 'INT-09', label: 'Kill Switch', modulePath: './kill-switch' },
  { targetId: 'INT-10', label: 'Shadow Discovery', modulePath: './discovery' },
  { targetId: 'INT-11', label: 'Governance Client', modulePath: './client' },
];

class GovernanceAttestationImpl implements GovernanceAttestation {
  constructor(
    readonly passed: boolean,
    readonly controls: ControlResult[],
    readonly toolkitVersion: string,
    readonly runtime: string,
    readonly verifiedAt: string,
    readonly attestationHash: string,
    readonly controlsPassed: number,
    readonly controlsTotal: number,
    readonly mode: 'components' | 'runtime-evidence' | 'integrity',
    readonly strict: boolean,
    readonly evidenceSource: string | undefined,
    readonly evidenceChecks: RuntimeEvidenceCheck[],
    readonly fileIntegrityResults: FileIntegrityResult[],
    readonly failures: string[],
  ) {}

  coveragePct(): number {
    if (this.controlsTotal === 0) {
      return 0;
    }

    return Math.round((this.controlsPassed / this.controlsTotal) * 100);
  }

  complianceGrade(): string {
    const pct = this.coveragePct();
    if (pct >= 90) return 'A';
    if (pct >= 80) return 'B';
    if (pct >= 70) return 'C';
    if (pct >= 60) return 'D';
    return 'F';
  }

  summary(): string {
    const headline = this.mode === 'components'
      ? `TypeScript governance component attestation ${this.passed ? 'PASSED' : 'FAILED'}`
      : `TypeScript governance verification ${this.passed ? 'PASSED' : 'FAILED'}`;
    const lines = [
      headline,
      `OWASP ASI coverage: ${this.controlsPassed}/${this.controlsTotal} (${this.coveragePct()}%)`,
      `Runtime: ${this.runtime}`,
      `Verified: ${this.verifiedAt}`,
      `Mode: ${this.mode}`,
    ];

    if (this.evidenceChecks.length > 0) {
      const passingChecks = this.evidenceChecks.filter((check) => check.status === 'pass').length;
      lines.push(`Runtime evidence: ${passingChecks}/${this.evidenceChecks.length} checks passed`);
      if (this.evidenceSource) {
        lines.push(`Evidence source: ${this.evidenceSource}`);
      }
    }

    if (this.fileIntegrityResults.length > 0) {
      const passingFiles = this.fileIntegrityResults.filter((result) => result.passed).length;
      lines.push(`Integrity manifest: ${passingFiles}/${this.fileIntegrityResults.length} files verified`);
    }

    if (this.failures.length > 0) {
      lines.push('Failures:');
      for (const failure of this.failures) {
        lines.push(`- ${failure}`);
      }
    }

    return lines.join('\n');
  }
}

export class GovernanceVerifier {
  constructor(
    private readonly controls: Record<string, VerifierControlSpec> = DEFAULT_CONTROLS,
    private readonly toolkitVersion: string = 'typescript-sdk',
    private readonly integrityTargets: IntegrityTargetSpec[] = DEFAULT_INTEGRITY_TARGETS,
  ) {}

  static loadRuntimeEvidence(evidencePath: string): RuntimeEvidence {
    const raw = readFileSync(evidencePath, 'utf-8');
    const parsed = evidencePath.endsWith('.yaml') || evidencePath.endsWith('.yml')
      ? loadYaml(raw)
      : JSON.parse(raw);

    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('Runtime evidence must contain a top-level object.');
    }

    const candidate = parsed as Record<string, unknown>;
    if (candidate.schema !== RUNTIME_EVIDENCE_SCHEMA) {
      throw new Error(`Unsupported runtime evidence schema ${String(candidate.schema)}.`);
    }

    if (!candidate.deployment || typeof candidate.deployment !== 'object' || Array.isArray(candidate.deployment)) {
      throw new Error("Runtime evidence missing required 'deployment' object.");
    }

    return {
      sourcePath: evidencePath,
      schema: String(candidate.schema),
      generatedAt: String(candidate.generatedAt ?? ''),
      toolkitVersion: String(candidate.toolkitVersion ?? ''),
      deployment: candidate.deployment as RuntimeEvidenceDeployment,
    };
  }

  generateIntegrityManifest(): IntegrityManifest {
    return {
      schema: INTEGRITY_MANIFEST_SCHEMA,
      generatedAt: new Date().toISOString(),
      toolkitVersion: this.toolkitVersion,
      files: this.integrityTargets.map((target) => {
        const filePath = this.resolveModuleFile(target.modulePath);
        return {
          targetId: target.targetId,
          label: target.label,
          modulePath: target.modulePath,
          filePath,
          sha256: this.hashFile(filePath),
        };
      }),
    };
  }

  verify(options: GovernanceVerificationOptions = {}): GovernanceAttestation {
    const strict = options.strict ?? false;
    const verifiedAt = new Date().toISOString();
    const failures: string[] = [];
    let runtimeEvidence = options.runtimeEvidence;

    if (!runtimeEvidence && options.evidencePath) {
      try {
        runtimeEvidence = GovernanceVerifier.loadRuntimeEvidence(options.evidencePath);
      } catch (error) {
        failures.push(error instanceof Error ? error.message : String(error));
      }
    }

    if (options.requireRuntimeEvidence && !runtimeEvidence) {
      failures.push('Runtime evidence is required but was not provided.');
    }

    if (options.requireIntegrityManifest && !options.integrityManifest) {
      failures.push('Integrity manifest is required but was not provided.');
    }

    const controls = Object.entries(this.controls).map(([controlId, spec]) => ({
      controlId,
      name: spec.name,
      present: spec.component !== undefined && spec.component !== null,
      component: this.componentName(spec.component),
      error: spec.component !== undefined && spec.component !== null ? undefined : 'Component missing',
    }));

    const evidenceChecks = runtimeEvidence ? this.evaluateRuntimeEvidence(runtimeEvidence) : [];
    const fileIntegrityResults = options.integrityManifest
      ? this.verifyIntegrityManifest(options.integrityManifest)
      : [];

    if (options.integrityManifest && options.integrityManifest.schema !== INTEGRITY_MANIFEST_SCHEMA) {
      failures.push(`Unsupported integrity manifest schema ${options.integrityManifest.schema}.`);
    }

    for (const check of evidenceChecks) {
      if (check.status === 'fail') {
        failures.push(`${check.title}: ${check.message}`);
      }
    }

    for (const result of fileIntegrityResults) {
      if (!result.passed) {
        failures.push(`${result.label}: ${result.error ?? 'hash mismatch'}`);
      }
    }

    const controlsPassed = controls.filter((control) => control.present).length;
    const controlsTotal = controls.length;
    const mode = runtimeEvidence
      ? 'runtime-evidence'
      : fileIntegrityResults.length > 0
        ? 'integrity'
        : 'components';
    const passed = controlsPassed === controlsTotal && failures.length === 0;

    const attestationHash = createHash('sha256')
      .update(JSON.stringify({
        verifiedAt,
        toolkitVersion: this.toolkitVersion,
        mode,
        strict,
        controls: controls.map((control) => ({
          id: control.controlId,
          present: control.present,
          component: control.component,
        })),
        evidenceChecks: evidenceChecks.map((check) => ({
          id: check.checkId,
          status: check.status,
          observed: check.observed,
        })),
        fileIntegrityResults: fileIntegrityResults.map((result) => ({
          id: result.targetId,
          passed: result.passed,
          actualHash: result.actualHash,
        })),
      }))
      .digest('hex');

    return new GovernanceAttestationImpl(
      passed,
      controls,
      this.toolkitVersion,
      `Node ${process.version}`,
      verifiedAt,
      attestationHash,
      controlsPassed,
      controlsTotal,
      mode,
      strict,
      runtimeEvidence?.sourcePath,
      evidenceChecks,
      fileIntegrityResults,
      failures,
    );
  }

  private evaluateRuntimeEvidence(evidence: RuntimeEvidence): RuntimeEvidenceCheck[] {
    const deployment = evidence.deployment;
    const identity = deployment.identity ?? {};
    const policy = deployment.policy ?? {};
    const audit = deployment.audit ?? {};
    const execution = deployment.execution ?? {};
    const promptDefense = deployment.promptDefense ?? {};
    const sre = deployment.sre ?? {};
    const discovery = deployment.discovery ?? {};

    return [
      this.makeEvidenceCheck(
        'EVI-01',
        'Runtime evidence schema',
        evidence.schema === RUNTIME_EVIDENCE_SCHEMA,
        evidence.schema === RUNTIME_EVIDENCE_SCHEMA
          ? 'Runtime evidence schema is recognized.'
          : 'Runtime evidence schema is unsupported.',
        { schema: evidence.schema },
      ),
      this.makeEvidenceCheck(
        'EVI-02',
        'Cryptographic identity',
        Boolean(identity.did || identity.spiffeId || identity.enabled === true),
        identity.did || identity.spiffeId || identity.enabled === true
          ? 'Identity evidence present.'
          : 'Missing DID, SPIFFE ID, or explicit identity enablement.',
        { did: identity.did, spiffeId: identity.spiffeId, enabled: identity.enabled ?? false },
      ),
      this.makeEvidenceCheck(
        'EVI-03',
        'Fail-closed policy',
        policy.failClosed === true || policy.defaultAction === 'deny',
        policy.failClosed === true || policy.defaultAction === 'deny'
          ? 'Policy evidence shows deny-by-default or fail-closed evaluation.'
          : 'Policy evidence does not demonstrate deny-by-default enforcement.',
        { failClosed: policy.failClosed ?? false, defaultAction: policy.defaultAction ?? 'unset' },
      ),
      this.makeEvidenceCheck(
        'EVI-04',
        'Policy backend coverage',
        Array.isArray(policy.backends) && policy.backends.length > 0,
        Array.isArray(policy.backends) && policy.backends.length > 0
          ? 'At least one policy backend is configured.'
          : 'No policy backends were recorded in runtime evidence.',
        { backends: policy.backends ?? [] },
      ),
      this.makeEvidenceCheck(
        'EVI-05',
        'Audit logging',
        audit.enabled === true,
        audit.enabled === true
          ? 'Audit evidence is enabled.'
          : 'Audit logging is not marked as enabled.',
        { enabled: audit.enabled ?? false, destination: audit.destination ?? 'unset' },
      ),
      this.makeEvidenceCheck(
        'EVI-06',
        'Execution rings',
        execution.rings === true,
        execution.rings === true
          ? 'Execution ring enforcement is enabled.'
          : 'Execution ring enforcement is missing from runtime evidence.',
        { rings: execution.rings ?? false },
      ),
      this.makeEvidenceCheck(
        'EVI-07',
        'Kill switch',
        execution.killSwitch === true,
        execution.killSwitch === true
          ? 'Kill switch evidence is present.'
          : 'Kill switch coverage is missing from runtime evidence.',
        { killSwitch: execution.killSwitch ?? false },
      ),
      this.makeEvidenceCheck(
        'EVI-08',
        'Prompt defense',
        promptDefense.enabled === true,
        promptDefense.enabled === true
          ? 'Prompt defense evidence is present.'
          : 'Prompt defense is not recorded as enabled.',
        { enabled: promptDefense.enabled ?? false, vectorsCovered: promptDefense.vectorsCovered ?? [] },
      ),
      this.makeEvidenceCheck(
        'EVI-09',
        'SRE telemetry',
        sre.metrics === true && sre.traces === true,
        sre.metrics === true && sre.traces === true
          ? 'Metrics and traces are enabled.'
          : 'Metrics and trace capture are not both enabled.',
        { metrics: sre.metrics ?? false, traces: sre.traces ?? false, sloTargets: sre.sloTargets ?? [] },
      ),
      this.makeEvidenceCheck(
        'EVI-10',
        'Shadow discovery',
        discovery.enabled === true,
        discovery.enabled === true
          ? 'Shadow discovery evidence is present.'
          : 'Shadow discovery is not recorded as enabled.',
        { enabled: discovery.enabled ?? false, shadowAgents: discovery.shadowAgents ?? 0 },
      ),
    ];
  }

  private verifyIntegrityManifest(manifest: IntegrityManifest): FileIntegrityResult[] {
    return manifest.files.map((file) => {
      try {
        const manifestPath = file.filePath || this.resolveModuleFile(file.modulePath);
        const actualHash = this.hashFile(manifestPath);
        const passed = file.sha256 === actualHash;
        return {
          targetId: file.targetId,
          label: file.label,
          modulePath: file.modulePath,
          filePath: manifestPath,
          expectedHash: file.sha256,
          actualHash,
          passed,
          error: passed ? undefined : 'hash mismatch',
        };
      } catch (error) {
        return {
          targetId: file.targetId,
          label: file.label,
          modulePath: file.modulePath,
          filePath: file.filePath,
          expectedHash: file.sha256,
          actualHash: '',
          passed: false,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    });
  }

  private makeEvidenceCheck(
    checkId: string,
    title: string,
    passed: boolean,
    message: string,
    observed: Record<string, unknown>,
  ): RuntimeEvidenceCheck {
    return {
      checkId,
      title,
      status: passed ? 'pass' : 'fail',
      message,
      observed,
    };
  }

  private resolveModuleFile(modulePath: string): string {
    return require.resolve(modulePath);
  }

  private hashFile(filePath: string): string {
    return createHash('sha256').update(readFileSync(filePath)).digest('hex');
  }

  private componentName(component: unknown): string {
    if (typeof component === 'function' && component.name) {
      return component.name;
    }

    if (typeof component === 'object' && component && 'constructor' in component) {
      const constructor = (component as { constructor?: { name?: string } }).constructor;
      if (constructor?.name) {
        return constructor.name;
      }
    }

    return 'unknown';
  }
}

export { RUNTIME_EVIDENCE_SCHEMA, INTEGRITY_MANIFEST_SCHEMA, ShadowDiscovery };
