// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { CredentialRedactor } from './credential-redactor';
import {
  CredentialRedactorConfig,
  FindingSeverity,
  McpResponseFinding,
  McpResponseScanResult,
  McpResponseScannerConfig,
} from './types';
import {
  createRegexScanBudget,
  debugSecurityFailure,
  getSafeErrorMessage,
  isRecord,
  truncatePreview,
} from './utils';

const INJECTION_PATTERNS = [
  /<\s*(?:system|assistant|instructions?|prompt)[^>]*>/gi,
  /<\|(?:system|assistant|user)\|>/gi,
  /\[\/?INST\]/g,
];

const IMPERATIVE_PATTERNS = [
  /ignore\s+(?:all\s+)?previous/gi,
  /override\s+(?:the\s+)?(?:previous|above|original)/gi,
  /do\s+not\s+follow/gi,
  /reveal\s+(?:all\s+)?(?:secrets|credentials|tokens)/gi,
  /include\s+the\s+contents?\s+of/gi,
];

const EXFILTRATION_PATTERNS = [
  /\b(?:curl|wget)\b/gi,
  /https?:\/\/(?:[^/\s]+\.)?(?:webhook|requestbin|ngrok|pastebin)[^\s"'<>]*/gi,
  /\b(?:send|upload|post|exfiltrat\w*)\b.{0,40}https?:\/\/[^\s"'<>]+/gi,
];

/**
 * Scans MCP tool responses for prompt injection and credential leakage before LLM use.
 */
export class McpResponseScanner {
  private readonly blockSeverities: Set<FindingSeverity>;
  private readonly sanitizeText: boolean;
  private readonly redactor: CredentialRedactor;
  private readonly config: McpResponseScannerConfig;

  constructor(
    config: McpResponseScannerConfig = {},
    redactorConfig: CredentialRedactorConfig = {},
  ) {
    this.config = config;
    this.blockSeverities = new Set(config.blockSeverities ?? ['critical']);
    this.sanitizeText = config.sanitizeText ?? true;
    this.redactor = new CredentialRedactor({
      ...redactorConfig,
      clock: redactorConfig.clock ?? config.clock,
      scanTimeoutMs: redactorConfig.scanTimeoutMs ?? config.scanTimeoutMs,
    });
  }

  scan<T>(value: T): McpResponseScanResult<T> {
    try {
      const budget = createRegexScanBudget(this.config.clock, this.config.scanTimeoutMs);
      const redactionResult = this.redactor.redact(value);
      const findings: McpResponseFinding[] = redactionResult.redactions.map(
        (redaction) => ({
          type: 'credential_leak',
          severity: 'critical',
          message: `Credential-like value detected at ${redaction.path ?? '$'}`,
          matchedText: redaction.matchedValueType,
          path: redaction.path,
        }),
      );

      const sanitized = this.scanNode(
        redactionResult.redacted,
        '$',
        findings,
        budget,
      ) as T;

      return {
        safe: findings.length === 0,
        blocked: findings.some((finding) => this.blockSeverities.has(finding.severity)),
        findings,
        original: value,
        sanitized,
      };
    } catch (error) {
      debugSecurityFailure(this.config.logger, 'responseScanner.scan', error);
      const findings: McpResponseFinding[] = [{
        type: 'instruction_injection',
        severity: 'critical',
        message: getSafeErrorMessage(error, 'Internal scan error - output blocked (fail-closed)'),
        matchedText: 'scan_error',
        path: '$',
      }];
      return {
        safe: false,
        blocked: true,
        findings,
        original: value,
        sanitized: value,
      };
    }
  }

  private scanNode(
    value: unknown,
    path: string,
    findings: McpResponseFinding[],
    budget: ReturnType<typeof createRegexScanBudget>,
  ): unknown {
    if (typeof value === 'string') {
      return this.scanString(value, path, findings, budget);
    }
    if (Array.isArray(value)) {
      return value.map((item, index) => this.scanNode(item, `${path}[${index}]`, findings, budget));
    }
    if (!isRecord(value)) {
      return value;
    }

    const clone: Record<string, unknown> = {};
    for (const [key, current] of Object.entries(value)) {
      clone[key] = this.scanNode(current, `${path}.${key}`, findings, budget);
    }
    return clone;
  }

  private scanString(
    value: string,
    path: string,
    findings: McpResponseFinding[],
    budget: ReturnType<typeof createRegexScanBudget>,
  ): string {
    let sanitized = value;

    const detectors: Array<{
      type: McpResponseFinding['type'];
      severity: FindingSeverity;
      message: string;
      patterns: RegExp[];
    }> = [
      {
        type: 'instruction_injection',
        severity: 'critical',
        message: 'Instruction-like tag detected in tool output',
        patterns: INJECTION_PATTERNS,
      },
      {
        type: 'imperative_language',
        severity: 'warning',
        message: 'Imperative prompt-like text detected in tool output',
        patterns: IMPERATIVE_PATTERNS,
      },
      {
        type: 'exfiltration_url',
        severity: 'critical',
        message: 'Exfiltration-like URL or command detected in tool output',
        patterns: EXFILTRATION_PATTERNS,
      },
    ];

    for (const detector of detectors) {
      for (const pattern of detector.patterns) {
        budget.checkpoint('Regex scan exceeded time budget - output blocked');
        pattern.lastIndex = 0;
        const matches = [...sanitized.matchAll(pattern)];
        if (matches.length === 0) {
          continue;
        }
        for (const match of matches) {
          findings.push({
            type: detector.type,
            severity: detector.severity,
            message: detector.message,
            matchedText: truncatePreview(match[0]),
            path,
          });
        }
        if (this.sanitizeText) {
          sanitized = sanitized.replace(pattern, `[FILTERED:${detector.type}]`);
        }
      }
    }

    return sanitized;
  }
}
