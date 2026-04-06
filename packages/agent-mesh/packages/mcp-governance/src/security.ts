// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { createHash } from 'crypto';
import {
  McpScanResult,
  McpSeverity,
  McpSecurityScannerConfig,
  McpThreat,
  McpThreatType,
  McpToolDefinition,
  ToolFingerprint,
} from './types';
import {
  createRegexScanBudget,
  debugSecurityFailure,
  getSafeErrorMessage,
  hasMatch,
  SystemClock,
} from './utils';

const INVISIBLE_UNICODE_PATTERNS = [
  /[\u200b\u200c\u200d\ufeff]/g,
  /[\u202a-\u202e]/g,
  /[\u2066-\u2069]/g,
];

const HIDDEN_INSTRUCTION_PATTERNS = [
  /ignore\s+(?:all\s+)?previous/gi,
  /override\s+(?:the\s+)?(?:previous|above|original)/gi,
  /actually\s+do/gi,
  /\bsystem\s*:/gi,
  /\bassistant\s*:/gi,
];

const EXFILTRATION_PATTERNS = [
  /\bcurl\b/gi,
  /\bwget\b/gi,
  /https?:\/\//gi,
  /include\s+the\s+contents?\s+of\b/gi,
];

const ROLE_OVERRIDE_PATTERNS = [
  /you\s+are\b/gi,
  /your\s+task\s+is\b/gi,
  /always\s+return\b/gi,
];

/**
 * Scans MCP tool metadata for poisoning, rug-pulls, and cross-server attacks.
 */
export class McpSecurityScanner {
  private readonly registry = new Map<string, ToolFingerprint>();
  private readonly config: Required<Pick<McpSecurityScannerConfig, 'clock' | 'scanTimeoutMs'>>
    & McpSecurityScannerConfig;

  constructor(config: McpSecurityScannerConfig = {}) {
    this.config = {
      clock: config.clock ?? new SystemClock(),
      scanTimeoutMs: config.scanTimeoutMs ?? 100,
    };
  }

  scanTool(
    toolName: string,
    description: string,
    schema?: Record<string, unknown>,
    serverName: string = 'unknown',
  ): McpThreat[] {
    const budget = createRegexScanBudget(this.config.clock, this.config.scanTimeoutMs);
    try {
      const threats: McpThreat[] = [];
      threats.push(...this.checkHiddenInstructions(description, toolName, serverName, budget));
      threats.push(...this.checkDescriptionInjection(description, toolName, serverName, budget));
      if (schema) {
        threats.push(...this.checkSchemaAbuse(schema, toolName, serverName, budget));
      }
      threats.push(...this.checkCrossServer(toolName, serverName, budget));
      const rugPull = this.checkRugPull(toolName, description, schema, serverName);
      if (rugPull) {
        threats.push(rugPull);
      }
      return threats;
    } catch (error) {
      debugSecurityFailure(this.config.logger, 'securityScanner.scanTool', error);
      return [{
        threatType: McpThreatType.ToolPoisoning,
        severity: McpSeverity.Critical,
        toolName,
        serverName,
        message: getSafeErrorMessage(error, 'Internal scan error - tool marked unsafe (fail-closed)'),
      }];
    }
  }

  scanServer(serverName: string, tools: McpToolDefinition[]): McpScanResult {
    const threats: McpThreat[] = [];
    const flagged = new Set<string>();
    for (const tool of tools) {
      const toolThreats = this.scanTool(
        tool.name,
        tool.description ?? '',
        tool.inputSchema,
        serverName,
      );
      if (toolThreats.length > 0) {
        flagged.add(tool.name);
        threats.push(...toolThreats);
      }
    }
    return {
      safe: threats.length === 0,
      threats,
      toolsScanned: tools.length,
      toolsFlagged: flagged.size,
    };
  }

  registerTool(
    toolName: string,
    description: string,
    schema: Record<string, unknown> | undefined,
    serverName: string,
  ): ToolFingerprint {
    const key = `${serverName}::${toolName}`;
    const now = new Date();
    const descriptionHash = sha256(description);
    const schemaHash = sha256(schema ?? {});
    const existing = this.registry.get(key);
    if (existing) {
      if (
        existing.descriptionHash !== descriptionHash
        || existing.schemaHash !== schemaHash
      ) {
        existing.descriptionHash = descriptionHash;
        existing.schemaHash = schemaHash;
        existing.lastSeen = now;
        existing.version += 1;
      } else {
        existing.lastSeen = now;
      }
      return existing;
    }

    const fingerprint: ToolFingerprint = {
      toolName,
      serverName,
      descriptionHash,
      schemaHash,
      firstSeen: now,
      lastSeen: now,
      version: 1,
    };
    this.registry.set(key, fingerprint);
    return fingerprint;
  }

  checkRugPull(
    toolName: string,
    description: string,
    schema: Record<string, unknown> | undefined,
    serverName: string,
  ): McpThreat | undefined {
    const existing = this.registry.get(`${serverName}::${toolName}`);
    if (!existing) {
      return undefined;
    }
    const changes: string[] = [];
    if (existing.descriptionHash !== sha256(description)) {
      changes.push('description');
    }
    if (existing.schemaHash !== sha256(schema ?? {})) {
      changes.push('schema');
    }
    if (changes.length === 0) {
      return undefined;
    }
    return {
      threatType: McpThreatType.RugPull,
      severity: McpSeverity.Critical,
      toolName,
      serverName,
      message: `Tool definition changed since registration: ${changes.join(', ')}`,
      details: {
        changedFields: changes,
        version: existing.version,
      },
    };
  }

  private checkHiddenInstructions(
    description: string,
    toolName: string,
    serverName: string,
    budget: ReturnType<typeof createRegexScanBudget>,
  ): McpThreat[] {
    const threats: McpThreat[] = [];
    for (const pattern of INVISIBLE_UNICODE_PATTERNS) {
      budget.checkpoint('Regex scan exceeded time budget - tool marked unsafe (fail-closed)');
      if (hasMatch(pattern, description)) {
        threats.push({
          threatType: McpThreatType.HiddenInstruction,
          severity: McpSeverity.Critical,
          toolName,
          serverName,
          message: 'Invisible unicode characters detected in tool description',
          matchedPattern: pattern.source,
        });
      }
    }
    budget.checkpoint('Regex scan exceeded time budget - tool marked unsafe (fail-closed)');
    const hiddenComment = findHiddenComment(description);
    if (hiddenComment) {
      threats.push({
        threatType: McpThreatType.HiddenInstruction,
        severity: McpSeverity.Critical,
        toolName,
        serverName,
        message: 'Hidden comment detected in tool description',
        matchedPattern: 'hidden_comment',
      });
    }
    for (const pattern of HIDDEN_INSTRUCTION_PATTERNS) {
      budget.checkpoint('Regex scan exceeded time budget - tool marked unsafe (fail-closed)');
      if (hasMatch(pattern, description)) {
        threats.push({
          threatType: McpThreatType.HiddenInstruction,
          severity: McpSeverity.Critical,
          toolName,
          serverName,
          message: `Instruction-like pattern in tool description: ${pattern.source}`,
          matchedPattern: pattern.source,
        });
      }
    }
    return threats;
  }

  private checkDescriptionInjection(
    description: string,
    toolName: string,
    serverName: string,
    budget: ReturnType<typeof createRegexScanBudget>,
  ): McpThreat[] {
    const threats: McpThreat[] = [];
    for (const pattern of ROLE_OVERRIDE_PATTERNS) {
      budget.checkpoint('Regex scan exceeded time budget - tool marked unsafe (fail-closed)');
      if (hasMatch(pattern, description)) {
        threats.push({
          threatType: McpThreatType.DescriptionInjection,
          severity: McpSeverity.Warning,
          toolName,
          serverName,
          message: `Role override pattern in description: ${pattern.source}`,
          matchedPattern: pattern.source,
        });
      }
    }
    for (const pattern of EXFILTRATION_PATTERNS) {
      budget.checkpoint('Regex scan exceeded time budget - tool marked unsafe (fail-closed)');
      if (hasMatch(pattern, description)) {
        threats.push({
          threatType: McpThreatType.DescriptionInjection,
          severity: McpSeverity.Critical,
          toolName,
          serverName,
          message: `Data exfiltration pattern in description: ${pattern.source}`,
          matchedPattern: pattern.source,
        });
      }
    }
    return threats;
  }

  private checkSchemaAbuse(
    schema: Record<string, unknown>,
    toolName: string,
    serverName: string,
    budget: ReturnType<typeof createRegexScanBudget>,
  ): McpThreat[] {
    const threats: McpThreat[] = [];
    if (
      schema.type === 'object'
      && !schema.properties
      && schema.additionalProperties !== false
    ) {
      threats.push({
        threatType: McpThreatType.ToolPoisoning,
        severity: McpSeverity.Warning,
        toolName,
        serverName,
        message: 'Overly permissive schema: object type with no defined properties',
      });
    }

    const properties = (schema.properties ?? {}) as Record<string, Record<string, unknown>>;
    const required = Array.isArray(schema.required) ? schema.required : [];
    const suspiciousNames = ['system_prompt', 'instructions', 'override', 'exec', 'eval', 'callback_url'];
    for (const [propName, propDef] of Object.entries(properties)) {
      budget.checkpoint('Regex scan exceeded time budget - tool marked unsafe (fail-closed)');
      if (
        required.includes(propName)
        && suspiciousNames.some((name) => propName.toLowerCase().includes(name))
      ) {
        threats.push({
          threatType: McpThreatType.ToolPoisoning,
          severity: McpSeverity.Critical,
          toolName,
          serverName,
          message: `Suspicious required field: '${propName}'`,
        });
      }
      if (typeof propDef.default === 'string') {
        for (const pattern of HIDDEN_INSTRUCTION_PATTERNS) {
          budget.checkpoint('Regex scan exceeded time budget - tool marked unsafe (fail-closed)');
          if (hasMatch(pattern, propDef.default)) {
            threats.push({
              threatType: McpThreatType.ToolPoisoning,
              severity: McpSeverity.Critical,
              toolName,
              serverName,
              message: `Instruction in default value for field '${propName}'`,
              matchedPattern: pattern.source,
            });
          }
        }
      }
    }
    return threats;
  }

  private checkCrossServer(
    toolName: string,
    serverName: string,
    budget: ReturnType<typeof createRegexScanBudget>,
  ): McpThreat[] {
    const threats: McpThreat[] = [];
    for (const fingerprint of this.registry.values()) {
      budget.checkpoint('Regex scan exceeded time budget - tool marked unsafe (fail-closed)');
      if (fingerprint.toolName === toolName && fingerprint.serverName !== serverName) {
        threats.push({
          threatType: McpThreatType.CrossServerAttack,
          severity: McpSeverity.Critical,
          toolName,
          serverName,
          message: `Tool '${toolName}' already registered from server '${fingerprint.serverName}'`,
        });
      }
    }
    return threats;
  }
}

function sha256(value: unknown): string {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

function findHiddenComment(value: string): string | undefined {
  return findDelimitedMarker(value, '<!--', '-->')
    ?? findDelimitedMarker(value, '[//]:#(', ')')
    ?? findDelimitedMarker(value, '[comment]:<>(', ')');
}

function findDelimitedMarker(
  value: string,
  startToken: string,
  endToken: string,
): string | undefined {
  const startIndex = value.indexOf(startToken);
  if (startIndex === -1) {
    return undefined;
  }
  const endIndex = value.indexOf(endToken, startIndex + startToken.length);
  if (endIndex === -1) {
    return undefined;
  }
  return value.slice(startIndex, endIndex + endToken.length);
}
