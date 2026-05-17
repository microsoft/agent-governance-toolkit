// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { createHash } from 'crypto';
import { readFileSync, readdirSync, statSync } from 'fs';
import path from 'path';

export type DetectionBasis = 'config_file' | 'container_reference' | 'source_pattern' | 'manual';
export type DiscoveryStatus = 'registered' | 'unregistered' | 'shadow' | 'unknown';
export type DiscoveryRiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface DiscoveryEvidence {
  scanner: string;
  basis: DetectionBasis;
  source: string;
  detail: string;
  rawData: Record<string, unknown>;
  confidence: number;
  timestamp: string;
}

export interface DiscoveredAgent {
  fingerprint: string;
  name: string;
  agentType: string;
  description: string;
  did?: string;
  owner?: string;
  status: DiscoveryStatus;
  evidence: DiscoveryEvidence[];
  confidence: number;
  mergeKeys: Record<string, string>;
  firstSeenAt: string;
  lastSeenAt: string;
  tags: Record<string, string>;
}

export interface DiscoveryRiskAssessment {
  level: DiscoveryRiskLevel;
  score: number;
  factors: string[];
  assessedAt: string;
}

export interface ShadowAgentRecord {
  agent: DiscoveredAgent;
  risk: DiscoveryRiskAssessment;
  recommendedActions: string[];
}

export interface RegisteredAgentRecord {
  did?: string;
  name?: string;
  fingerprint?: string;
  configPath?: string;
  owner?: string;
}

export interface ShadowDiscoveryOptions {
  paths: string[];
  registry?: RegisteredAgentRecord[];
  maxDepth?: number;
  includeSourcePatterns?: boolean;
  maxFileReadBytes?: number;
}

export interface DiscoveryScanResult {
  agents: DiscoveredAgent[];
  shadowAgents: ShadowAgentRecord[];
  errors: string[];
  startedAt: string;
  completedAt: string;
  scannedTargets: number;
  agentCount: number;
}

interface ConfigPattern {
  glob: string;
  type: string;
  confidence: number;
}

interface ContentPattern {
  pattern: RegExp;
  type: string;
  confidence: number;
}

const CONFIG_PATTERNS: ConfigPattern[] = [
  { glob: 'agentmesh.yaml', type: 'agt', confidence: 0.95 },
  { glob: 'agentmesh.yml', type: 'agt', confidence: 0.95 },
  { glob: '.agentmesh/config.yaml', type: 'agt', confidence: 0.95 },
  { glob: 'agent-governance.yaml', type: 'agt', confidence: 0.9 },
  { glob: 'crewai.yaml', type: 'crewai', confidence: 0.9 },
  { glob: 'crewai.yml', type: 'crewai', confidence: 0.9 },
  { glob: 'mcp.json', type: 'mcp-server', confidence: 0.85 },
  { glob: 'mcp-config.json', type: 'mcp-server', confidence: 0.85 },
  { glob: '.mcp/config.json', type: 'mcp-server', confidence: 0.85 },
  { glob: 'claude_desktop_config.json', type: 'mcp-server', confidence: 0.8 },
  { glob: '.copilot-setup-steps.yml', type: 'copilot-agent', confidence: 0.8 },
  { glob: 'copilot-setup-steps.yml', type: 'copilot-agent', confidence: 0.8 },
];

const DOCKER_AGENT_PATTERNS: ContentPattern[] = [
  { pattern: /langchain|langgraph/i, type: 'langchain', confidence: 0.7 },
  { pattern: /crewai/i, type: 'crewai', confidence: 0.7 },
  { pattern: /autogen/i, type: 'autogen', confidence: 0.7 },
  { pattern: /agentmesh|agent\.governance/i, type: 'agt', confidence: 0.72 },
  { pattern: /mcp[_-]server/i, type: 'mcp-server', confidence: 0.72 },
  { pattern: /semantic[_-]kernel/i, type: 'semantic-kernel', confidence: 0.7 },
];

const SOURCE_AGENT_PATTERNS: ContentPattern[] = [
  { pattern: /langchain|langgraph/i, type: 'langchain', confidence: 0.65 },
  { pattern: /crewai/i, type: 'crewai', confidence: 0.65 },
  { pattern: /autogen|openai-agents/i, type: 'openai-agents', confidence: 0.65 },
  { pattern: /agentmesh|agent[-_]governance/i, type: 'agt', confidence: 0.7 },
  { pattern: /mcp[_-]server|model context protocol/i, type: 'mcp-server', confidence: 0.7 },
  { pattern: /semantic[_-]kernel/i, type: 'semantic-kernel', confidence: 0.65 },
];

const SKIP_DIRS = new Set([
  '.git',
  'node_modules',
  '__pycache__',
  '.venv',
  'venv',
  '.tox',
  '.mypy_cache',
  '.pytest_cache',
  'dist',
  'build',
  '.eggs',
  'coverage',
]);

const SOURCE_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.py', '.mjs', '.cjs']);
const HIGH_RISK_TYPES = new Set(['autogen', 'crewai', 'langchain', 'openai-agents']);
const MEDIUM_RISK_TYPES = new Set(['mcp-server', 'semantic-kernel', 'copilot-agent']);
const DEFAULT_MAX_FILE_READ_BYTES = 64 * 1024;

export class ShadowDiscovery {
  constructor(private readonly registeredAgents: RegisteredAgentRecord[] = []) {}

  scan(options: ShadowDiscoveryOptions): DiscoveryScanResult {
    const startedAt = new Date().toISOString();
    const errors: string[] = [];
    const agents = new Map<string, DiscoveredAgent>();
    const maxDepth = options.maxDepth ?? 10;
    const includeSourcePatterns = options.includeSourcePatterns ?? true;
    const maxFileReadBytes = options.maxFileReadBytes ?? DEFAULT_MAX_FILE_READ_BYTES;

    for (const scanPath of options.paths) {
      const rootPath = path.resolve(scanPath);
      try {
        if (!statSync(rootPath).isDirectory()) {
          errors.push(`Not a directory: ${scanPath}`);
          continue;
        }
      } catch {
        errors.push(`Not a directory: ${scanPath}`);
        continue;
      }

      this.walkDirectory(rootPath, rootPath, maxDepth, includeSourcePatterns, maxFileReadBytes, agents, errors);
    }

    const registry = options.registry ?? this.registeredAgents;
    const discoveredAgents = Array.from(agents.values());
    const shadowAgents = this.reconcile(discoveredAgents, registry);

    return {
      agents: discoveredAgents.sort((left, right) => right.confidence - left.confidence),
      shadowAgents,
      errors,
      startedAt,
      completedAt: new Date().toISOString(),
      scannedTargets: options.paths.length,
      agentCount: discoveredAgents.length,
    };
  }

  reconcile(
    agents: DiscoveredAgent[],
    registry: RegisteredAgentRecord[] = this.registeredAgents,
  ): ShadowAgentRecord[] {
    const shadows: ShadowAgentRecord[] = [];

    for (const agent of agents) {
      const registered = this.matchRegisteredAgent(agent, registry);
      if (registered) {
        agent.status = 'registered';
        agent.owner ??= registered.owner;
        agent.did ??= registered.did;
        continue;
      }

      agent.status = 'shadow';
      const risk = this.scoreRisk(agent);
      shadows.push({
        agent,
        risk,
        recommendedActions: this.recommendActions(agent, risk),
      });
    }

    return shadows.sort((left, right) => right.risk.score - left.risk.score);
  }

  private walkDirectory(
    rootPath: string,
    currentPath: string,
    maxDepth: number,
    includeSourcePatterns: boolean,
    maxFileReadBytes: number,
    agents: Map<string, DiscoveredAgent>,
    errors: string[],
  ): void {
    const relativeDepth = path.relative(rootPath, currentPath);
    const depth = relativeDepth ? relativeDepth.split(path.sep).length : 0;
    if (depth > maxDepth) {
      return;
    }

    let entries;
    try {
      entries = readdirSync(currentPath, { withFileTypes: true });
    } catch (error) {
      errors.push(`Unable to read ${currentPath}: ${error instanceof Error ? error.message : String(error)}`);
      return;
    }

    for (const entry of entries) {
      // Skip symlinks entirely. `Dirent.isDirectory()` and `isFile()`
      // describe the directory entry itself (not the symlink target), so
      // the directory recursion below is already safe, but the downstream
      // `readFileSync` calls in `scanConfigFile` / `scanContainerFile` /
      // `scanSourceFile` follow symlinks. A symlink named (e.g.)
      // `agentmesh.yaml` pointing at `/etc/passwd` would be opened and
      // read; a symlink loop or a symlink to a large file would inflate the
      // discovery cost without bound.
      if (entry.isSymbolicLink()) {
        continue;
      }

      const fullPath = path.join(currentPath, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) {
          this.walkDirectory(rootPath, fullPath, maxDepth, includeSourcePatterns, maxFileReadBytes, agents, errors);
        }
        continue;
      }

      const relativePath = this.normalizePath(path.relative(rootPath, fullPath));
      this.scanConfigFile(rootPath, fullPath, relativePath, entry.name, agents);
      this.scanContainerFile(rootPath, fullPath, relativePath, entry.name, maxFileReadBytes, agents);

      if (includeSourcePatterns) {
        this.scanSourceFile(rootPath, fullPath, relativePath, entry.name, maxFileReadBytes, agents);
      }
    }
  }

  private scanConfigFile(
    rootPath: string,
    fullPath: string,
    relativePath: string,
    fileName: string,
    agents: Map<string, DiscoveredAgent>,
  ): void {
    for (const config of CONFIG_PATTERNS) {
      if (fileName === config.glob || relativePath.endsWith(config.glob)) {
        const mergeKeys = { configPath: this.normalizePath(fullPath) };
        this.addObservation(agents, {
          mergeKeys,
          name: `${config.type} agent at ${relativePath}`,
          agentType: config.type,
          description: `Configuration artifact found at ${relativePath}`,
          rootPath,
          tagKey: 'configFile',
          tagValue: relativePath,
          evidence: {
            scanner: 'config',
            basis: 'config_file',
            source: this.normalizePath(fullPath),
            detail: `Agent config file: ${fileName}`,
            rawData: { path: this.normalizePath(fullPath), type: config.type },
            confidence: config.confidence,
          },
        });
      }
    }
  }

  private scanContainerFile(
    rootPath: string,
    fullPath: string,
    relativePath: string,
    fileName: string,
    maxFileReadBytes: number,
    agents: Map<string, DiscoveredAgent>,
  ): void {
    if (!['Dockerfile', 'docker-compose.yml', 'docker-compose.yaml'].includes(fileName)) {
      return;
    }

    const content = this.readTextSafely(fullPath, maxFileReadBytes);
    if (!content) {
      return;
    }

    for (const descriptor of DOCKER_AGENT_PATTERNS) {
      const match = descriptor.pattern.exec(content);
      if (!match) {
        continue;
      }

      const mergeKeys = {
        dockerPath: this.normalizePath(fullPath),
        pattern: descriptor.type,
      };
      this.addObservation(agents, {
        mergeKeys,
        name: `Containerized ${descriptor.type} agent at ${relativePath}`,
        agentType: descriptor.type,
        description: `Container artifact references ${descriptor.type}`,
        rootPath,
        tagKey: 'dockerFile',
        tagValue: relativePath,
        evidence: {
          scanner: 'config',
          basis: 'container_reference',
          source: this.normalizePath(fullPath),
          detail: `Container file references ${match[0]}`,
          rawData: { file: this.normalizePath(fullPath), match: match[0] },
          confidence: descriptor.confidence,
        },
      });
      break;
    }
  }

  private scanSourceFile(
    rootPath: string,
    fullPath: string,
    relativePath: string,
    fileName: string,
    maxFileReadBytes: number,
    agents: Map<string, DiscoveredAgent>,
  ): void {
    if (!SOURCE_EXTENSIONS.has(path.extname(fileName).toLowerCase())) {
      return;
    }

    const content = this.readTextSafely(fullPath, maxFileReadBytes);
    if (!content) {
      return;
    }

    for (const descriptor of SOURCE_AGENT_PATTERNS) {
      const match = descriptor.pattern.exec(content);
      if (!match) {
        continue;
      }

      const mergeKeys = {
        sourcePath: this.normalizePath(fullPath),
        pattern: descriptor.type,
      };
      this.addObservation(agents, {
        mergeKeys,
        name: `${descriptor.type} source integration at ${relativePath}`,
        agentType: descriptor.type,
        description: `Source pattern suggests a ${descriptor.type} agent integration`,
        rootPath,
        tagKey: 'sourceFile',
        tagValue: relativePath,
        evidence: {
          scanner: 'config',
          basis: 'source_pattern',
          source: this.normalizePath(fullPath),
          detail: `Source pattern match: ${match[0]}`,
          rawData: { file: this.normalizePath(fullPath), match: match[0] },
          confidence: descriptor.confidence,
        },
      });
      break;
    }
  }

  private addObservation(
    agents: Map<string, DiscoveredAgent>,
    observation: {
      mergeKeys: Record<string, string>;
      name: string;
      agentType: string;
      description: string;
      rootPath: string;
      tagKey: string;
      tagValue: string;
      evidence: Omit<DiscoveryEvidence, 'timestamp'>;
    },
  ): void {
    const fingerprint = this.computeFingerprint(observation.mergeKeys);
    const timestamp = new Date().toISOString();
    const evidence: DiscoveryEvidence = { ...observation.evidence, timestamp };
    const existing = agents.get(fingerprint);

    if (existing) {
      existing.evidence.push(evidence);
      existing.confidence = Math.max(existing.confidence, evidence.confidence);
      existing.lastSeenAt = timestamp;
      existing.tags[observation.tagKey] = observation.tagValue;
      return;
    }

    agents.set(fingerprint, {
      fingerprint,
      name: observation.name,
      agentType: observation.agentType,
      description: observation.description,
      status: 'unknown',
      evidence: [evidence],
      confidence: evidence.confidence,
      mergeKeys: observation.mergeKeys,
      firstSeenAt: timestamp,
      lastSeenAt: timestamp,
      tags: {
        root: this.normalizePath(observation.rootPath),
        [observation.tagKey]: observation.tagValue,
      },
    });
  }

  private scoreRisk(agent: DiscoveredAgent): DiscoveryRiskAssessment {
    const factors: string[] = [];
    let score = 0;

    if (!agent.did) {
      score += 30;
      factors.push('No cryptographic identity (DID/SPIFFE)');
    }

    if (!agent.owner) {
      score += 20;
      factors.push('No assigned owner');
    }

    if (agent.status === 'shadow' || agent.status === 'unregistered') {
      score += 20;
      factors.push(`Agent status: ${agent.status}`);
    }

    if (HIGH_RISK_TYPES.has(agent.agentType)) {
      score += 15;
      factors.push(`High-risk agent type: ${agent.agentType}`);
    } else if (MEDIUM_RISK_TYPES.has(agent.agentType)) {
      score += 10;
      factors.push(`Medium-risk agent type: ${agent.agentType}`);
    }

    const daysSinceFirstSeen = Math.floor(
      (Date.now() - new Date(agent.firstSeenAt).getTime()) / (24 * 60 * 60 * 1000),
    );
    if (daysSinceFirstSeen > 30) {
      score += 10;
      factors.push(`Ungoverned for ${daysSinceFirstSeen} days`);
    } else if (daysSinceFirstSeen > 7) {
      score += 5;
      factors.push(`Ungoverned for ${daysSinceFirstSeen} days`);
    }

    if (agent.confidence < 0.5) {
      score -= 10;
      factors.push('Low detection confidence');
    }

    const clampedScore = Math.max(0, Math.min(100, score));
    return {
      level: this.riskLevelForScore(clampedScore),
      score: clampedScore,
      factors,
      assessedAt: new Date().toISOString(),
    };
  }

  private riskLevelForScore(score: number): DiscoveryRiskLevel {
    if (score >= 75) return 'critical';
    if (score >= 50) return 'high';
    if (score >= 25) return 'medium';
    if (score >= 10) return 'low';
    return 'info';
  }

  private recommendActions(agent: DiscoveredAgent, risk: DiscoveryRiskAssessment): string[] {
    const actions: string[] = [];

    if (agent.confidence >= 0.8) {
      actions.push('Register this agent with AgentMesh to establish governance identity.');
    } else {
      actions.push('Investigate this artifact to confirm it is an active AI agent deployment.');
    }

    if (!agent.owner) {
      actions.push('Assign an owner responsible for the agent lifecycle and policy posture.');
    }

    if (agent.agentType === 'mcp-server') {
      actions.push('Run the MCP security scanner against this server definition before allowing production use.');
    }

    if (risk.level === 'critical' || risk.level === 'high') {
      actions.push('Apply deny-by-default policy, execution ring limits, and kill-switch coverage before activation.');
    } else {
      actions.push('Review capabilities and apply least-privilege policies before onboarding.');
    }

    return actions;
  }

  private matchRegisteredAgent(
    agent: DiscoveredAgent,
    registry: RegisteredAgentRecord[],
  ): RegisteredAgentRecord | undefined {
    return registry.find((registered) => {
      if (agent.did && registered.did === agent.did) {
        return true;
      }

      if (registered.fingerprint && registered.fingerprint === agent.fingerprint) {
        return true;
      }

      if (registered.configPath) {
        const registeredPath = this.normalizePath(path.resolve(registered.configPath));
        if (Object.values(agent.mergeKeys).some((value) => this.normalizePath(value) === registeredPath)) {
          return true;
        }
      }

      if (registered.name && agent.name.toLowerCase().includes(registered.name.toLowerCase())) {
        return true;
      }

      return false;
    });
  }

  private readTextSafely(filePath: string, maxFileReadBytes: number): string | undefined {
    try {
      return readFileSync(filePath).subarray(0, maxFileReadBytes).toString('utf-8');
    } catch {
      return undefined;
    }
  }

  private computeFingerprint(mergeKeys: Record<string, string>): string {
    const canonical = Object.entries(mergeKeys)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, value]) => `${key}=${this.normalizePath(value)}`)
      .join('|');

    return createHash('sha256').update(canonical).digest('hex').slice(0, 16);
  }

  private normalizePath(value: string): string {
    return value.replace(/\\/g, '/');
  }
}
