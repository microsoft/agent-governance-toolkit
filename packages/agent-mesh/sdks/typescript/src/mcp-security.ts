// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { createHash } from 'crypto';
import {
  MCPScanAuditRecord,
  MCPScanResult,
  MCPSecurityScannerConfig,
  MCPSeverity,
  MCPThreat,
  MCPThreatType,
  MCPToolDefinition,
  ToolFingerprint,
} from './types';
import {
  createRegexScanBudget,
  debugSecurityFailure,
  DEFAULT_MCP_CLOCK,
} from './mcp-utils';

const INVISIBLE_UNICODE_PATTERNS = [
  /[\u200b\u200c\u200d\ufeff]/g,
  /[\u202a-\u202e]/g,
  /[\u2066-\u2069]/g,
  /[\u00ad]/g,
  /[\u2060\u180e]/g,
];

const HIDDEN_INSTRUCTION_PATTERNS = [
  /ignore\s+(?:all\s+)?previous/gi,
  /override\s+(?:the\s+)?(?:previous|above|original)/gi,
  /instead\s+of\s+(?:the\s+)?(?:above|previous|described)/gi,
  /actually\s+do/gi,
  /\bsystem\s*:/gi,
  /\bassistant\s*:/gi,
  /do\s+not\s+follow/gi,
  /disregard\s+(?:all\s+)?(?:above|prior|previous)/gi,
];

const ENCODED_PAYLOAD_PATTERNS = [
  /[A-Za-z0-9+/]{40,}={0,2}/g,
  /(?:\\x[0-9a-fA-F]{2}){4,}/g,
];

const EXFILTRATION_PATTERNS = [
  /\bcurl\b/gi,
  /\bwget\b/gi,
  /\bfetch\s*\(/gi,
  /https?:\/\//gi,
  /\bsend\s+email\b/gi,
  /\bsend\s+to\b/gi,
  /\bpost\s+to\b/gi,
  /include\s+the\s+contents?\s+of\b/gi,
];

const ROLE_OVERRIDE_PATTERNS = [
  /you\s+are\b/gi,
  /your\s+task\s+is\b/gi,
  /respond\s+with\b/gi,
  /always\s+return\b/gi,
  /you\s+must\b/gi,
  /your\s+role\s+is\b/gi,
];

const EXCESSIVE_WHITESPACE_PATTERN = /\n{5,}.+/gs;

const SUSPICIOUS_DECODED_KEYWORDS = [
  'ignore',
  'override',
  'system',
  'password',
  'secret',
  'admin',
  'root',
  'exec',
  'eval',
  'send',
  'curl',
  'fetch',
];

export class MCPSecurityScanner {
  private readonly toolRegistry = new Map<string, ToolFingerprint>();
  private readonly auditRecords: MCPScanAuditRecord[] = [];
  private readonly config: Required<Pick<MCPSecurityScannerConfig, 'clock' | 'scanTimeoutMs'>>
    & MCPSecurityScannerConfig;

  constructor(config: MCPSecurityScannerConfig = {}) {
    this.config = {
      clock: config.clock ?? DEFAULT_MCP_CLOCK,
      scanTimeoutMs: config.scanTimeoutMs ?? 100,
    };
  }

  scanTool(
    toolName: string,
    description: string,
    schema?: Record<string, unknown>,
    serverName: string = 'unknown',
  ): MCPThreat[] {
    const budget = createRegexScanBudget(this.config.clock, this.config.scanTimeoutMs);
    try {
      const threats: MCPThreat[] = [];
      threats.push(...this.checkHiddenInstructions(description, toolName, serverName, budget));
      threats.push(...this.checkDescriptionInjection(description, toolName, serverName, budget));
      if (schema) {
        threats.push(...this.checkSchemaAbuse(schema, toolName, serverName, budget));
      }
      threats.push(...this.checkCrossServer(toolName, serverName));

      const rugPull = this.checkRugPull(toolName, description, schema, serverName);
      if (rugPull) {
        threats.push(rugPull);
      }

      this.recordAudit('scan_tool', toolName, serverName, threats);
      return threats;
    } catch (error) {
      debugSecurityFailure(this.config.logger, 'securityScanner.scanTool', error);
      return [{
        threatType: MCPThreatType.ToolPoisoning,
        severity: MCPSeverity.Critical,
        toolName,
        serverName,
        message: 'Scan error - tool rejected (fail-closed)',
      }];
    }
  }

  scanServer(serverName: string, tools: MCPToolDefinition[]): MCPScanResult {
    const threats: MCPThreat[] = [];
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
    const now = Date.now();
    const descriptionHash = sha256(description);
    const schemaHash = sha256(schema ?? {});
    const existing = this.toolRegistry.get(key);

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
    this.toolRegistry.set(key, fingerprint);
    return fingerprint;
  }

  checkRugPull(
    toolName: string,
    description: string,
    schema: Record<string, unknown> | undefined,
    serverName: string,
  ): MCPThreat | undefined {
    const existing = this.toolRegistry.get(`${serverName}::${toolName}`);
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
      threatType: MCPThreatType.RugPull,
      severity: MCPSeverity.Critical,
      toolName,
      serverName,
      message: `Tool definition changed since registration: ${changes.join(', ')} modified (version ${existing.version})`,
      details: {
        changedFields: changes,
        version: existing.version,
      },
    };
  }

  get auditLog(): MCPScanAuditRecord[] {
    return [...this.auditRecords];
  }

  private checkHiddenInstructions(
    description: string,
    toolName: string,
    serverName: string,
    budget: ReturnType<typeof createRegexScanBudget>,
  ): MCPThreat[] {
    const threats: MCPThreat[] = [];

    for (const pattern of INVISIBLE_UNICODE_PATTERNS) {
      budget.checkpoint('Regex scan exceeded time budget - tool rejected (fail-closed)');
      const match = description.match(pattern);
      if (match) {
        threats.push({
          threatType: MCPThreatType.HiddenInstruction,
          severity: MCPSeverity.Critical,
          toolName,
          serverName,
          message: 'Invisible unicode characters detected in tool description',
          matchedPattern: pattern.source,
          details: {
            character: match[0],
          },
        });
        break;
      }
    }

    budget.checkpoint('Regex scan exceeded time budget - tool rejected (fail-closed)');
    const hiddenComment = findHiddenComment(description);
    if (hiddenComment) {
      threats.push({
        threatType: MCPThreatType.HiddenInstruction,
        severity: MCPSeverity.Critical,
        toolName,
        serverName,
        message: 'Hidden comment detected in tool description',
        matchedPattern: 'hidden_comment',
        details: {
          commentPreview: hiddenComment.slice(0, 80),
        },
      });
    }

    for (const pattern of ENCODED_PAYLOAD_PATTERNS) {
      budget.checkpoint('Regex scan exceeded time budget - tool rejected (fail-closed)');
      const match = description.match(pattern);
      if (!match) {
        continue;
      }

      const suspicious = match.some((candidate) => {
        budget.checkpoint('Regex scan exceeded time budget - tool rejected (fail-closed)');
        if (candidate.startsWith('\\x')) {
          return true;
        }
        try {
          const decoded = Buffer.from(candidate, 'base64').toString('utf-8').toLowerCase();
          return SUSPICIOUS_DECODED_KEYWORDS.some((keyword) => decoded.includes(keyword));
        } catch {
          return true;
        }
      });

      if (suspicious) {
        threats.push({
          threatType: MCPThreatType.HiddenInstruction,
          severity: MCPSeverity.Warning,
          toolName,
          serverName,
          message: 'Encoded payload detected in tool description',
          matchedPattern: pattern.source,
        });
      }
    }

    budget.checkpoint('Regex scan exceeded time budget - tool rejected (fail-closed)');
    if (hasMatch(EXCESSIVE_WHITESPACE_PATTERN, description)) {
      threats.push({
        threatType: MCPThreatType.HiddenInstruction,
        severity: MCPSeverity.Warning,
        toolName,
        serverName,
        message: 'Instructions hidden after excessive whitespace',
        matchedPattern: EXCESSIVE_WHITESPACE_PATTERN.source,
      });
    }

    for (const pattern of HIDDEN_INSTRUCTION_PATTERNS) {
      budget.checkpoint('Regex scan exceeded time budget - tool rejected (fail-closed)');
      if (hasMatch(pattern, description)) {
        threats.push({
          threatType: MCPThreatType.HiddenInstruction,
          severity: MCPSeverity.Critical,
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
  ): MCPThreat[] {
    const threats: MCPThreat[] = [];

    for (const pattern of HIDDEN_INSTRUCTION_PATTERNS) {
      budget.checkpoint('Regex scan exceeded time budget - tool rejected (fail-closed)');
      if (hasMatch(pattern, description)) {
        threats.push({
          threatType: MCPThreatType.DescriptionInjection,
          severity: MCPSeverity.Critical,
          toolName,
          serverName,
          message: `Prompt-injection style pattern in description: ${pattern.source}`,
          matchedPattern: pattern.source,
        });
      }
    }

    for (const pattern of ROLE_OVERRIDE_PATTERNS) {
      budget.checkpoint('Regex scan exceeded time budget - tool rejected (fail-closed)');
      if (hasMatch(pattern, description)) {
        threats.push({
          threatType: MCPThreatType.DescriptionInjection,
          severity: MCPSeverity.Warning,
          toolName,
          serverName,
          message: `Role override pattern in description: ${pattern.source}`,
          matchedPattern: pattern.source,
        });
      }
    }

    for (const pattern of EXFILTRATION_PATTERNS) {
      budget.checkpoint('Regex scan exceeded time budget - tool rejected (fail-closed)');
      if (hasMatch(pattern, description)) {
        threats.push({
          threatType: MCPThreatType.DescriptionInjection,
          severity: MCPSeverity.Critical,
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
  ): MCPThreat[] {
    const threats: MCPThreat[] = [];

    if (
      schema.type === 'object'
      && !schema.properties
      && schema.additionalProperties !== false
    ) {
      threats.push({
        threatType: MCPThreatType.ToolPoisoning,
        severity: MCPSeverity.Warning,
        toolName,
        serverName,
        message: 'Overly permissive schema: object type with no defined properties',
      });
    }

    const properties = (schema.properties ?? {}) as Record<string, Record<string, unknown>>;
    const required = Array.isArray(schema.required) ? schema.required : [];
    const suspiciousNames = [
      'system_prompt',
      'instructions',
      'override',
      'command',
      'exec',
      'eval',
      'callback_url',
      'webhook',
      'target_url',
    ];

    for (const [propName, propDef] of Object.entries(properties)) {
      budget.checkpoint('Regex scan exceeded time budget - tool rejected (fail-closed)');
      if (
        required.includes(propName)
        && suspiciousNames.some((name) => propName.toLowerCase().includes(name))
      ) {
        threats.push({
          threatType: MCPThreatType.ToolPoisoning,
          severity: MCPSeverity.Critical,
          toolName,
          serverName,
          message: `Suspicious required field: '${propName}'`,
          details: { fieldName: propName },
        });
      }

      if (typeof propDef.default === 'string' && propDef.default.length > 10) {
        for (const pattern of HIDDEN_INSTRUCTION_PATTERNS) {
          budget.checkpoint('Regex scan exceeded time budget - tool rejected (fail-closed)');
          if (hasMatch(pattern, propDef.default)) {
            threats.push({
              threatType: MCPThreatType.ToolPoisoning,
              severity: MCPSeverity.Critical,
              toolName,
              serverName,
              message: `Instruction in default value for field '${propName}'`,
              matchedPattern: pattern.source,
              details: { fieldName: propName },
            });
            break;
          }
        }
      }

      if (typeof propDef.description === 'string') {
        for (const pattern of HIDDEN_INSTRUCTION_PATTERNS) {
          budget.checkpoint('Regex scan exceeded time budget - tool rejected (fail-closed)');
          if (hasMatch(pattern, propDef.description)) {
            threats.push({
              threatType: MCPThreatType.ToolPoisoning,
              severity: MCPSeverity.Critical,
              toolName,
              serverName,
              message: `Hidden instruction in property '${propName}' description`,
              matchedPattern: pattern.source,
              details: { fieldName: propName },
            });
            break;
          }
        }
      }
    }

    return threats;
  }

  private checkCrossServer(toolName: string, serverName: string): MCPThreat[] {
    const threats: MCPThreat[] = [];

    for (const fingerprint of this.toolRegistry.values()) {
      if (fingerprint.toolName === toolName && fingerprint.serverName !== serverName) {
        threats.push({
          threatType: MCPThreatType.CrossServerAttack,
          severity: MCPSeverity.Critical,
          toolName,
          serverName,
          message: `Tool '${toolName}' already registered from server '${fingerprint.serverName}' - potential impersonation`,
          details: {
            originalServer: fingerprint.serverName,
          },
        });
      }

      if (
        fingerprint.serverName !== serverName
        && fingerprint.toolName !== toolName
        && isTyposquat(toolName, fingerprint.toolName)
      ) {
        threats.push({
          threatType: MCPThreatType.CrossServerAttack,
          severity: MCPSeverity.Warning,
          toolName,
          serverName,
          message: `Tool name '${toolName}' resembles '${fingerprint.toolName}' from server '${fingerprint.serverName}' - potential typosquatting`,
          details: {
            similarTool: fingerprint.toolName,
            similarServer: fingerprint.serverName,
          },
        });
      }
    }

    return threats;
  }

  private recordAudit(
    action: string,
    toolName: string,
    serverName: string,
    threats: MCPThreat[],
  ): void {
    this.auditRecords.push({
      timestamp: new Date().toISOString(),
      action,
      toolName,
      serverName,
      threatsFound: threats.length,
      threatTypes: threats.map((threat) => threat.threatType),
    });
  }
}

function sha256(value: unknown): string {
  return createHash('sha256')
    .update(JSON.stringify(value))
    .digest('hex');
}

function isTyposquat(left: string, right: string): boolean {
  if (left === right) {
    return false;
  }
  if (Math.abs(left.length - right.length) > 2) {
    return false;
  }
  const distance = levenshtein(left.toLowerCase(), right.toLowerCase());
  return distance >= 1 && distance <= 2 && Math.min(left.length, right.length) >= 4;
}

function levenshtein(left: string, right: string): number {
  const rows = left.length + 1;
  const cols = right.length + 1;
  const matrix = Array.from({ length: rows }, () => Array<number>(cols).fill(0));

  for (let row = 0; row < rows; row += 1) {
    matrix[row][0] = row;
  }
  for (let col = 0; col < cols; col += 1) {
    matrix[0][col] = col;
  }

  for (let row = 1; row < rows; row += 1) {
    for (let col = 1; col < cols; col += 1) {
      const cost = left[row - 1] === right[col - 1] ? 0 : 1;
      matrix[row][col] = Math.min(
        matrix[row - 1][col] + 1,
        matrix[row][col - 1] + 1,
        matrix[row - 1][col - 1] + cost,
      );
    }
  }

  return matrix[rows - 1][cols - 1];
}

function hasMatch(pattern: RegExp, value: string): boolean {
  pattern.lastIndex = 0;
  return pattern.test(value);
}

function findHiddenComment(value: string): string | undefined {
  return findDelimitedMarker(value, '<!--', '-->')
    ?? findDelimitedMarker(value, '[//]:#(', ')')
    ?? findDelimitedMarker(value, '[comment]:<>(', ')');
}

function findDelimitedMarker(
  value: string,
  startMarker: string,
  endMarker: string,
): string | undefined {
  const startIndex = value.indexOf(startMarker);
  if (startIndex === -1) {
    return undefined;
  }

  const endIndex = value.indexOf(endMarker, startIndex + startMarker.length);
  if (endIndex === -1) {
    return undefined;
  }

  return value.slice(startIndex, endIndex + endMarker.length);
}
