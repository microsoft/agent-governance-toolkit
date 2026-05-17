// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { createHash, randomUUID } from 'crypto';
import type {
  ContextEntry,
  ContextIsolationViolation,
  ContextPoisoningConfig,
  ContextPoisoningScanResult,
  PoisoningFinding,
  PoisoningPattern,
} from './types';

const DEFAULT_PATTERNS: PoisoningPattern[] = [
  {
    id: 'prompt-injection-ignore',
    name: 'Prompt injection: ignore previous instructions',
    description: 'Detects attempts to override system instructions via "ignore" directives',
    detector: 'regex',
    pattern: '(?:ignore|disregard|forget|override)\\s+(?:all\\s+)?(?:previous|prior|above|earlier|system)\\s+(?:instructions|rules|prompts|context)',
    severity: 'critical',
  },
  {
    id: 'prompt-injection-roleplay',
    name: 'Prompt injection: role assumption',
    description: 'Detects attempts to make the agent assume a different role or persona',
    detector: 'regex',
    pattern: '(?:you\\s+are\\s+now|act\\s+as|pretend\\s+(?:to\\s+be|you\\s+are)|from\\s+now\\s+on\\s+you\\s+are|new\\s+instructions?:)',
    severity: 'high',
  },
  {
    id: 'prompt-injection-system-override',
    name: 'Prompt injection: system prompt extraction',
    description: 'Detects attempts to extract or modify system prompts',
    detector: 'regex',
    pattern: '(?:show|reveal|display|output|print|repeat)\\s+(?:your|the)?\\s*(?:system\\s+(?:prompt|message|instructions)|initial\\s+(?:prompt|instructions))',
    severity: 'high',
  },
  {
    id: 'context-stuffing',
    name: 'Context window stuffing',
    description: 'Detects abnormally large entries that may attempt to push important context out of the window',
    detector: 'size',
    severity: 'medium',
  },
  {
    id: 'high-entropy-payload',
    name: 'High entropy payload',
    description: 'Detects entries with abnormally high entropy that may contain encoded/obfuscated payloads',
    detector: 'entropy',
    severity: 'medium',
  },
  {
    id: 'repetition-attack',
    name: 'Repetition flooding',
    description: 'Detects repeated identical or near-identical entries that may attempt to bias agent behavior',
    detector: 'repetition',
    severity: 'medium',
  },
  {
    id: 'injection-delimiter',
    name: 'Delimiter injection',
    description: 'Detects use of common prompt delimiters to break context boundaries',
    detector: 'injection',
    pattern: '(?:```\\s*system|<\\|(?:im_start|system|end)\\|>|\\[INST\\]|<<SYS>>|###\\s*(?:System|Instruction|Human|Assistant):)',
    severity: 'critical',
  },
];

const DEFAULT_CONFIG: Required<Omit<ContextPoisoningConfig, 'knownPatterns'>> = {
  maxContextSizeBytes: 100_000,
  maxEntriesPerSession: 200,
  entropyThreshold: 5.5,
  similarityThreshold: 0.9,
  enableIsolation: true,
};

/**
 * Detects context poisoning attacks in agent memory stores (OWASP ASI-06).
 *
 * Scans context entries for known attack patterns including prompt injection,
 * context window stuffing, high-entropy payloads, and repetition flooding.
 * Also validates memory isolation between agent sessions.
 */
export class ContextPoisoningDetector {
  private readonly config: Required<Omit<ContextPoisoningConfig, 'knownPatterns'>>;
  private readonly patterns: PoisoningPattern[];
  private readonly compiledRegex = new Map<string, RegExp>();
  private readonly contextStore = new Map<string, ContextEntry[]>();
  private readonly integrityHashes = new Map<string, string>();

  private static readonly MAX_CONTEXT_KEYS = 10_000;
  private static readonly MAX_ENTRIES_PER_KEY = 1_000;

  constructor(config?: ContextPoisoningConfig) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.patterns = [...DEFAULT_PATTERNS, ...(config?.knownPatterns ?? [])];

    for (const p of this.patterns) {
      if (p.detector === 'regex' && p.pattern) {
        this.compiledRegex.set(p.id, new RegExp(p.pattern, 'i'));
      } else if (p.detector === 'injection' && p.pattern) {
        this.compiledRegex.set(p.id, new RegExp(p.pattern, 'i'));
      }
    }
  }

  /**
   * Add a context entry to the store and compute its integrity hash.
   */
  addEntry(entry: ContextEntry): void {
    const key = `${entry.agentId}:${entry.sessionId}`;
    const entries = this.contextStore.get(key) ?? [];
    if (entries.length >= ContextPoisoningDetector.MAX_ENTRIES_PER_KEY) {
      entries.shift();
    }
    entries.push(entry);

    if (!this.contextStore.has(key) && this.contextStore.size >= ContextPoisoningDetector.MAX_CONTEXT_KEYS) {
      // Evict oldest key (first inserted).
      const oldest = this.contextStore.keys().next().value;
      if (oldest !== undefined) {
        this.contextStore.delete(oldest);
      }
    }
    this.contextStore.set(key, entries);

    const hash = this.computeHash(entry);
    this.integrityHashes.set(entry.entryId, hash);
  }

  /**
   * Scan all stored context entries for poisoning indicators.
   */
  scan(): ContextPoisoningScanResult {
    const findings: PoisoningFinding[] = [];
    let entriesScanned = 0;

    for (const entries of this.contextStore.values()) {
      for (const entry of entries) {
        entriesScanned++;
        const entryFindings = this.scanEntry(entry);
        findings.push(...entryFindings);
      }

      // Check repetition across entries in the same session
      const repetitionFindings = this.checkRepetition(entries);
      findings.push(...repetitionFindings);
    }

    const isolationViolations = this.config.enableIsolation
      ? this.checkIsolation()
      : [];

    const integrityValid = this.verifyIntegrity();
    const riskLevel = this.assessRisk(findings, isolationViolations);

    return {
      scannedAt: new Date().toISOString(),
      entriesScanned,
      findings,
      integrityValid,
      isolationViolations,
      riskLevel,
    };
  }

  /**
   * Scan a single context entry for poisoning patterns.
   */
  scanEntry(entry: ContextEntry): PoisoningFinding[] {
    const findings: PoisoningFinding[] = [];

    for (const pattern of this.patterns) {
      const finding = this.checkPattern(entry, pattern);
      if (finding) {
        findings.push(finding);
      }
    }

    return findings;
  }

  /**
   * Verify integrity of all stored entries.
   * Returns false if any entry has been tampered with.
   */
  verifyIntegrity(): boolean {
    for (const entries of this.contextStore.values()) {
      for (const entry of entries) {
        const storedHash = this.integrityHashes.get(entry.entryId);
        if (!storedHash) continue;
        const currentHash = this.computeHash(entry);
        if (currentHash !== storedHash) return false;
      }
    }
    return true;
  }

  /**
   * Check memory isolation between sessions for the same agent.
   */
  checkIsolation(): ContextIsolationViolation[] {
    const violations: ContextIsolationViolation[] = [];

    // Group by agentId
    const agentSessions = new Map<string, Map<string, ContextEntry[]>>();
    for (const [key, entries] of this.contextStore) {
      const [agentId] = key.split(':');
      if (!agentSessions.has(agentId)) {
        agentSessions.set(agentId, new Map());
      }
      const sessions = agentSessions.get(agentId)!;
      const sessionId = entries[0]?.sessionId;
      if (sessionId) {
        sessions.set(sessionId, entries);
      }
    }

    // Check for content leaking between sessions
    for (const [agentId, sessions] of agentSessions) {
      const sessionIds = [...sessions.keys()];
      for (let i = 0; i < sessionIds.length; i++) {
        for (let j = i + 1; j < sessionIds.length; j++) {
          const entriesA = sessions.get(sessionIds[i])!;
          const entriesB = sessions.get(sessionIds[j])!;
          const shared = this.findSharedContent(entriesA, entriesB);

          if (shared.length > 0) {
            violations.push({
              sourceSessionId: sessionIds[i],
              targetSessionId: sessionIds[j],
              agentId,
              sharedEntryIds: shared,
              description: `${shared.length} context entries shared between sessions, violating memory isolation`,
            });
          }
        }
      }
    }

    return violations;
  }

  /**
   * Get all stored entries for a specific agent/session.
   */
  getEntries(agentId: string, sessionId: string): ContextEntry[] {
    return [...(this.contextStore.get(`${agentId}:${sessionId}`) ?? [])];
  }

  /**
   * Clear all entries for a specific agent/session.
   */
  clearSession(agentId: string, sessionId: string): void {
    const key = `${agentId}:${sessionId}`;
    const entries = this.contextStore.get(key);
    if (entries) {
      for (const entry of entries) {
        this.integrityHashes.delete(entry.entryId);
      }
    }
    this.contextStore.delete(key);
  }

  // ── Internal helpers ──

  private checkPattern(entry: ContextEntry, pattern: PoisoningPattern): PoisoningFinding | null {
    switch (pattern.detector) {
      case 'regex':
      case 'injection':
        return this.checkRegex(entry, pattern);
      case 'entropy':
        return this.checkEntropy(entry, pattern);
      case 'size':
        return this.checkSize(entry, pattern);
      case 'repetition':
        return null; // Handled separately across entries
      default:
        return null;
    }
  }

  private checkRegex(entry: ContextEntry, pattern: PoisoningPattern): PoisoningFinding | null {
    const regex = this.compiledRegex.get(pattern.id);
    if (!regex) return null;

    const match = regex.exec(entry.content);
    if (!match) return null;

    return {
      findingId: randomUUID(),
      patternId: pattern.id,
      patternName: pattern.name,
      severity: pattern.severity,
      entryId: entry.entryId,
      sessionId: entry.sessionId,
      agentId: entry.agentId,
      description: pattern.description,
      evidence: match[0].substring(0, 200),
      recommendation: this.getRecommendation(pattern),
    };
  }

  private checkEntropy(entry: ContextEntry, pattern: PoisoningPattern): PoisoningFinding | null {
    if (entry.content.length < 50) return null;

    const entropy = this.shannonEntropy(entry.content);
    if (entropy < this.config.entropyThreshold) return null;

    return {
      findingId: randomUUID(),
      patternId: pattern.id,
      patternName: pattern.name,
      severity: pattern.severity,
      entryId: entry.entryId,
      sessionId: entry.sessionId,
      agentId: entry.agentId,
      description: `Entry has abnormally high entropy (${entropy.toFixed(2)} bits/char, threshold: ${this.config.entropyThreshold})`,
      evidence: `First 100 chars: ${entry.content.substring(0, 100)}`,
      recommendation: 'Review entry for encoded or obfuscated payloads. Consider rejecting high-entropy inputs.',
    };
  }

  private checkSize(entry: ContextEntry, pattern: PoisoningPattern): PoisoningFinding | null {
    const sizeBytes = Buffer.byteLength(entry.content, 'utf-8');
    if (sizeBytes <= this.config.maxContextSizeBytes) return null;

    return {
      findingId: randomUUID(),
      patternId: pattern.id,
      patternName: pattern.name,
      severity: pattern.severity,
      entryId: entry.entryId,
      sessionId: entry.sessionId,
      agentId: entry.agentId,
      description: `Entry size (${sizeBytes} bytes) exceeds maximum (${this.config.maxContextSizeBytes} bytes)`,
      evidence: `Size: ${sizeBytes} bytes, limit: ${this.config.maxContextSizeBytes} bytes`,
      recommendation: 'Truncate or reject oversized context entries to prevent context window stuffing.',
    };
  }

  private checkRepetition(entries: ContextEntry[]): PoisoningFinding[] {
    const findings: PoisoningFinding[] = [];
    const contentCounts = new Map<string, ContextEntry[]>();

    for (const entry of entries) {
      const normalized = entry.content.trim().toLowerCase();
      const existing = contentCounts.get(normalized) ?? [];
      existing.push(entry);
      contentCounts.set(normalized, existing);
    }

    const repetitionPattern = this.patterns.find((p) => p.id === 'repetition-attack');
    if (!repetitionPattern) return findings;

    for (const [, duplicates] of contentCounts) {
      if (duplicates.length >= 3) {
        findings.push({
          findingId: randomUUID(),
          patternId: repetitionPattern.id,
          patternName: repetitionPattern.name,
          severity: repetitionPattern.severity,
          entryId: duplicates[0].entryId,
          sessionId: duplicates[0].sessionId,
          agentId: duplicates[0].agentId,
          description: `Content repeated ${duplicates.length} times in session, possible repetition flooding`,
          evidence: `Repeated content (first 100 chars): ${duplicates[0].content.substring(0, 100)}`,
          recommendation: 'Deduplicate repeated context entries. Rate-limit identical submissions.',
        });
      }
    }

    return findings;
  }

  private findSharedContent(entriesA: ContextEntry[], entriesB: ContextEntry[]): string[] {
    const shared: string[] = [];
    const contentMapA = new Map<string, string>();

    for (const entry of entriesA) {
      contentMapA.set(entry.content.trim(), entry.entryId);
    }

    for (const entry of entriesB) {
      const normalizedContent = entry.content.trim();
      if (contentMapA.has(normalizedContent) && normalizedContent.length > 20) {
        shared.push(contentMapA.get(normalizedContent)!, entry.entryId);
      }
    }

    return shared;
  }

  private shannonEntropy(text: string): number {
    const freq = new Map<string, number>();
    for (const char of text) {
      freq.set(char, (freq.get(char) ?? 0) + 1);
    }

    let entropy = 0;
    const len = text.length;
    for (const count of freq.values()) {
      const p = count / len;
      if (p > 0) {
        entropy -= p * Math.log2(p);
      }
    }

    return entropy;
  }

  private computeHash(entry: ContextEntry): string {
    return createHash('sha256')
      .update(`${entry.entryId}:${entry.sessionId}:${entry.agentId}:${entry.role}:${entry.content}:${entry.timestamp}`)
      .digest('hex');
  }

  private getRecommendation(pattern: PoisoningPattern): string {
    switch (pattern.severity) {
      case 'critical':
        return 'Block this input immediately. Log the attempt and quarantine the session.';
      case 'high':
        return 'Flag for review and consider blocking. Monitor the source for repeated attempts.';
      case 'medium':
        return 'Log the anomaly and apply additional validation before processing.';
      default:
        return 'Monitor for repeated occurrences and consider adding to block list.';
    }
  }

  private assessRisk(
    findings: PoisoningFinding[],
    violations: ContextIsolationViolation[],
  ): 'none' | 'low' | 'medium' | 'high' | 'critical' {
    if (findings.length === 0 && violations.length === 0) return 'none';

    const hasCritical = findings.some((f) => f.severity === 'critical');
    const hasHigh = findings.some((f) => f.severity === 'high');
    const hasMedium = findings.some((f) => f.severity === 'medium');

    if (hasCritical || violations.length > 0) return 'critical';
    if (hasHigh) return 'high';
    if (hasMedium) return 'medium';
    return 'low';
  }
}
