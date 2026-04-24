// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// ── MCP Security Scanner ──
// Detects tool-poisoning, typosquatting, hidden-instruction, and rug-pull
// threats in MCP tool definitions.

/** Threat categories recognised by the scanner. */
export enum McpThreatType {
  ToolPoisoning = 'tool_poisoning',
  Typosquatting = 'typosquatting',
  HiddenInstruction = 'hidden_instruction',
  RugPull = 'rug_pull',
}

/** A single threat detected during a scan. */
export interface McpThreat {
  type: McpThreatType;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  evidence?: string;
}

/** Result of scanning one MCP tool definition. */
export interface McpScanResult {
  tool_name: string;
  threats: McpThreat[];
  risk_score: number; // 0-100
  safe: boolean;
}

/** Minimal MCP tool definition accepted by the scanner. */
export interface McpToolDefinition {
  name: string;
  description: string;
  parameters?: Record<string, unknown>;
}

// ── Well-known tool names for typosquatting detection ──

const KNOWN_TOOL_NAMES: string[] = [
  'read_file',
  'write_file',
  'execute_command',
  'search',
  'browse',
  'fetch',
  'list_directory',
  'create_file',
  'delete_file',
  'run_script',
  'get_weather',
  'send_email',
  'query_database',
  'http_request',
  'calculator',
];

// ── Detection helpers ──

/** Patterns that suggest prompt-injection / tool-poisoning. */
const POISONING_PATTERNS: RegExp[] = [
  /<system>/i,
  /ignore previous/i,
  /you must/i,
  /disregard/i,
  /override/i,
  /forget (all|your|previous)/i,
  /new instructions/i,
  /act as/i,
];

/** Unicode zero-width and homoglyph code-points. */
const ZERO_WIDTH_CHARS = [
  '\u200B', // zero-width space
  '\u200C', // zero-width non-joiner
  '\u200D', // zero-width joiner
  '\uFEFF', // BOM / zero-width no-break space
  '\u00AD', // soft hyphen
  '\u2060', // word joiner
  '\u180E', // Mongolian vowel separator
];

/** Common Cyrillic / Greek homoglyphs for Latin letters. */
const HOMOGLYPH_MAP: Record<string, string> = {
  '\u0430': 'a', // Cyrillic а
  '\u0435': 'e', // Cyrillic е
  '\u043E': 'o', // Cyrillic о
  '\u0440': 'p', // Cyrillic р
  '\u0441': 'c', // Cyrillic с
  '\u0443': 'y', // Cyrillic у
  '\u0445': 'x', // Cyrillic х
  '\u0456': 'i', // Cyrillic і
  '\u0458': 'j', // Cyrillic ј
  '\u03B1': 'a', // Greek α
  '\u03BF': 'o', // Greek ο
  '\u03C1': 'p', // Greek ρ
};

/** Instruction-like patterns used for rug-pull detection. */
const INSTRUCTION_PATTERNS: RegExp[] = [
  /you (should|must|need to)/i,
  /always /i,
  /never /i,
  /do not /i,
  /important:/i,
  /warning:/i,
  /note:/i,
  /step \d/i,
  /first,/i,
  /finally,/i,
];

const RUG_PULL_DESCRIPTION_LENGTH = 500;
const RUG_PULL_MIN_INSTRUCTION_MATCHES = 2;

// ── Levenshtein distance ──

function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0) as number[]);
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[m][n];
}

// ── Severity scoring weights ──

const SEVERITY_WEIGHT: Record<McpThreat['severity'], number> = {
  low: 10,
  medium: 25,
  high: 50,
  critical: 80,
};

// ── McpSecurityScanner ──

/**
 * Scans MCP tool definitions for security threats.
 */
export class McpSecurityScanner {
  /** Scan a single tool definition. */
  scan(toolDefinition: McpToolDefinition): McpScanResult {
    const threats: McpThreat[] = [];

    this.detectToolPoisoning(toolDefinition, threats);
    this.detectTyposquatting(toolDefinition, threats);
    this.detectHiddenInstructions(toolDefinition, threats);
    this.detectRugPull(toolDefinition, threats);

    const risk_score = Math.min(
      100,
      threats.reduce((sum, t) => sum + SEVERITY_WEIGHT[t.severity], 0),
    );

    return {
      tool_name: toolDefinition.name,
      threats,
      risk_score,
      safe: threats.length === 0,
    };
  }

  /** Scan multiple tool definitions. */
  scanAll(tools: McpToolDefinition[]): McpScanResult[] {
    return tools.map((t) => this.scan(t));
  }

  // ── Private detection methods ──

  private detectToolPoisoning(tool: McpToolDefinition, threats: McpThreat[]): void {
    const text = tool.description;
    for (const pattern of POISONING_PATTERNS) {
      const match = pattern.exec(text);
      if (match) {
        threats.push({
          type: McpThreatType.ToolPoisoning,
          severity: 'critical',
          description: `Prompt-injection pattern detected in tool description: "${match[0]}"`,
          evidence: match[0],
        });
      }
    }

    // Detect encoded characters (percent-encoded payloads)
    if (/%[0-9A-Fa-f]{2}/.test(text)) {
      try {
        const decoded = decodeURIComponent(text);
        for (const pattern of POISONING_PATTERNS) {
          const match = pattern.exec(decoded);
          if (match) {
            threats.push({
              type: McpThreatType.ToolPoisoning,
              severity: 'critical',
              description: `Encoded prompt-injection detected after URL-decoding: "${match[0]}"`,
              evidence: match[0],
            });
          }
        }
      } catch {
        // malformed encoding – not a threat by itself
      }
    }
  }

  private detectTyposquatting(tool: McpToolDefinition, threats: McpThreat[]): void {
    const name = tool.name.toLowerCase();
    for (const known of KNOWN_TOOL_NAMES) {
      if (name === known) continue; // exact match is fine
      const dist = levenshtein(name, known);
      if (dist > 0 && dist <= 2) {
        threats.push({
          type: McpThreatType.Typosquatting,
          severity: dist === 1 ? 'high' : 'medium',
          description: `Tool name "${tool.name}" is suspiciously similar to known tool "${known}" (edit distance ${dist})`,
          evidence: known,
        });
      }
    }
  }

  private detectHiddenInstructions(tool: McpToolDefinition, threats: McpThreat[]): void {
    const text = tool.description;

    // Zero-width characters
    for (const zwc of ZERO_WIDTH_CHARS) {
      if (text.includes(zwc)) {
        threats.push({
          type: McpThreatType.HiddenInstruction,
          severity: 'high',
          description: `Zero-width character U+${zwc.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')} found in description`,
          evidence: `U+${zwc.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}`,
        });
        break; // one finding per category is enough
      }
    }

    // Homoglyphs
    for (const ch of text) {
      if (HOMOGLYPH_MAP[ch]) {
        threats.push({
          type: McpThreatType.HiddenInstruction,
          severity: 'high',
          description: `Homoglyph character detected: "${ch}" looks like "${HOMOGLYPH_MAP[ch]}" but is a different Unicode code point`,
          evidence: ch,
        });
        break; // one finding per category is enough
      }
    }
  }

  private detectRugPull(tool: McpToolDefinition, threats: McpThreat[]): void {
    const text = tool.description;
    if (text.length <= RUG_PULL_DESCRIPTION_LENGTH) return;

    let instructionMatches = 0;
    for (const pattern of INSTRUCTION_PATTERNS) {
      if (pattern.test(text)) instructionMatches++;
    }

    if (instructionMatches >= RUG_PULL_MIN_INSTRUCTION_MATCHES) {
      threats.push({
        type: McpThreatType.RugPull,
        severity: 'medium',
        description:
          `Unusually long description (${text.length} chars) with ${instructionMatches} instruction-like patterns — possible rug-pull payload`,
        evidence: `length=${text.length}, instruction_patterns=${instructionMatches}`,
      });
    }
  }
}
