// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// ── MCP Runtime Threat Scanner ──
// Scans MCP tool call parameters at runtime to detect and block
// parameter injection, path traversal, SSRF, credential leakage,
// and destructive operations before they reach the tool server.
//
// This complements the static McpSecurityScanner which analyzes
// tool definitions. This module scans actual tool call arguments
// during execution — the runtime verification layer.
//
// NOTE: This is a threat scanner focused on security-relevant
// patterns, not a general schema/parameter validator. Parameters
// that do not match threat patterns will pass through.

/** Threat categories for runtime tool call scanning. */
export enum McpCallThreatType {
  PathTraversal = 'path_traversal',
  CommandInjection = 'command_injection',
  SSRF = 'ssrf',
  CredentialLeakage = 'credential_leakage',
  DestructiveOperation = 'destructive_operation',
  ParameterOverflow = 'parameter_overflow',
}

/** A single threat detected during runtime scanning. */
export interface McpCallThreat {
  type: McpCallThreatType;
  severity: 'low' | 'medium' | 'high' | 'critical';
  parameter: string;
  description: string;
  evidence?: string;
  blocked: boolean;
}

/** Result of scanning a tool call. */
export interface McpCallValidationResult {
  tool_name: string;
  safe: boolean;
  blocked: boolean;
  threats: McpCallThreat[];
}

/** A tool call to scan. */
export interface McpToolCall {
  tool_name: string;
  arguments: Record<string, unknown>;
}

/** Configuration for the runtime threat scanner. */
export interface McpRuntimeValidatorConfig {
  /** Block calls with any threats (fail-closed). Default: true */
  block_on_threat: boolean;
  /** Block only on high/critical threats. Default: false */
  block_on_high_severity_only: boolean;
  /** Allowed base paths for file operations. Default: [] (no restrictions) */
  allowed_paths: string[];
  /** Blocked URL patterns (regex strings). Default: private IP ranges */
  blocked_url_patterns: string[];
  /** Maximum parameter string length. Default: 10000 */
  max_param_length: number;
}

const DEFAULT_CONFIG: McpRuntimeValidatorConfig = {
  block_on_threat: true,
  block_on_high_severity_only: false,
  allowed_paths: [],
  blocked_url_patterns: [],
  max_param_length: 10_000,
};

// ── Detection Patterns ──

/** Path traversal sequences. */
const PATH_TRAVERSAL_PATTERNS: RegExp[] = [
  /\.\.[\/\\]/,
  /\.\.%2[fF]/,
  /%2[eE]\./,
  /%2[eE]%2[fF]/,
  /\.\.%5[cC]/,
  /%2[eE]%5[cC]/,
  /%252[eE]/,
  /\.\.[\/\\]\.\./,
];

/** Shell metacharacters that indicate command injection. */
const COMMAND_INJECTION_PATTERNS: RegExp[] = [
  /[;|&`$]/,
  /\$\(/,
  /\$\{/,
  /`[^`]+`/,
  /\|\|/,
  /&&/,
  />\s*\//,
  /<\s*\//,
  /\n\s*(rm|cat|curl|wget|nc|bash|sh|python|perl|ruby)\b/,
];

/** Destructive operation patterns in parameter values. */
const DESTRUCTIVE_PATTERNS: RegExp[] = [
  /\brm\s+-rf\b/i,
  /\bformat\b.*\bdrive\b/i,
  /\bdrop\s+table\b/i,
  /\bdelete\s+from\b/i,
  /\btruncate\b/i,
  /\bshutdown\b/i,
  /\breboot\b/i,
  /\bmkfs\b/i,
  /\bdd\s+if=/i,
  /:(){ :\|:\& };:/,
];

/** Credential patterns (API keys, tokens, passwords). */
const CREDENTIAL_PATTERNS: RegExp[] = [
  /(?:^|\b)(?:sk|pk|api[_-]?key|token|secret|password|passwd|pwd)\s*[=:]\s*["']?[A-Za-z0-9_\-\.]{16,}/i,
  /ghp_[A-Za-z0-9]{36}/,
  /gho_[A-Za-z0-9]{36}/,
  /github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}/,
  /sk-[A-Za-z0-9]{32,}/,
  /xox[bpas]-[A-Za-z0-9-]+/,
  /AKIA[0-9A-Z]{16}/,
  /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/,
  /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+/,
];

/**
 * Private/internal IP ranges for SSRF detection.
 * Covers: localhost, link-local, RFC1918, cloud metadata,
 * IPv6 variants, decimal-IP, and @-userinfo bypasses.
 */
const SSRF_PATTERNS: RegExp[] = [
  /127\.0\.0\.\d{1,3}/,
  /0\.0\.0\.0/,
  /::1/,
  /\[::1\]/,
  /169\.254\.\d{1,3}\.\d{1,3}/,
  /10\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
  /172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}/,
  /192\.168\.\d{1,3}\.\d{1,3}/,
  /metadata\.google\.internal/i,
  /169\.254\.169\.254/,
  /\/\/localhost\b/i,
  /@(?:127\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)/,
  /\b(?:2130706433|3232235521|167772161)\b/,
  /\b0x7f000001\b/i,
];

// ── Heuristic: identify file-path and URL parameter names ──

const FILE_PATH_PARAM_NAMES = /^(?:file_?path|path|dir(?:ectory)?|folder|filename|file_?name|source|dest(?:ination)?|target|input(?:_?file)?|output(?:_?file)?|cwd|root|base(?:_?path)?|location|url)$/i;
const URL_PARAM_NAMES = /^(?:url|uri|endpoint|href|link|webhook|callback|redirect|fetch_?url|request_?url|api_?url|base_?url|target_?url)$/i;
const COMMAND_PARAM_NAMES = /^(?:command|cmd|script|shell|exec|run|code|eval|expression|query)$/i;

// ─ McpRuntimeValidator ──

/**
 * Scans MCP tool call parameters at runtime for security threats.
 * Complements McpSecurityScanner (static analysis) with runtime checks.
 *
 * Recursively scans nested objects and arrays to prevent bypass via
 * nested parameter structures (e.g., {config: {path: '../..'}}).
 */
export class McpRuntimeValidator {
  private config: McpRuntimeValidatorConfig;
  private blockedUrlRegexes: RegExp[];

  constructor(config?: Partial<McpRuntimeValidatorConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.blockedUrlRegexes = [
      ...SSRF_PATTERNS,
      ...this.config.blocked_url_patterns.map(p => new RegExp(p, 'i')),
    ];
  }

  /** Scan a single tool call. Returns result with threats and safety verdict. */
  validate(call: McpToolCall): McpCallValidationResult {
    const threats: McpCallThreat[] = [];
    this.scanArguments(call.arguments, threats, '');

    const shouldBlock = this.config.block_on_threat && (
      this.config.block_on_high_severity_only
        ? threats.some(t => t.severity === 'high' || t.severity === 'critical')
        : threats.length > 0
    );

    return {
      tool_name: call.tool_name,
      safe: !shouldBlock,
      blocked: shouldBlock,
      threats,
    };
  }

  /** Scan multiple tool calls. */
  validateAll(calls: McpToolCall[]): McpCallValidationResult[] {
    return calls.map(c => this.validate(c));
  }

  // ── Recursive argument scanning ──

  private scanArguments(
    args: Record<string, unknown>,
    threats: McpCallThreat[],
    parentPath: string,
  ): void {
    for (const [key, value] of Object.entries(args)) {
      const paramPath = parentPath ? `${parentPath}.${key}` : key;

      if (value === null || value === undefined) continue;

      if (typeof value === 'object' && !Array.isArray(value)) {
        this.scanArguments(value as Record<string, unknown>, threats, paramPath);
        continue;
      }

      if (Array.isArray(value)) {
        for (let i = 0; i < value.length; i++) {
          const elementPath = `${paramPath}[${i}]`;
          const element = value[i];
          if (typeof element === 'object' && element !== null && !Array.isArray(element)) {
            this.scanArguments(element as Record<string, unknown>, threats, elementPath);
          } else if (typeof element === 'string') {
            this.scanStringValue(elementPath, element, threats);
          }
        }
        continue;
      }

      if (typeof value === 'string') {
        this.scanStringValue(paramPath, value, threats);
      }
    }
  }

  /** Run all threat checks on a single string value. */
  private scanStringValue(paramPath: string, value: string, threats: McpCallThreat[]): void {
    const leafKey = paramPath.includes('.')
      ? paramPath.split('.').pop()!.replace(/\[\d+\]$/, '')
      : paramPath.replace(/\[\d+\]$/, '');

    this.checkParameterOverflow(paramPath, value, threats);

    if (FILE_PATH_PARAM_NAMES.test(leafKey)) {
      this.checkPathTraversal(paramPath, value, threats);
    }

    if (URL_PARAM_NAMES.test(leafKey)) {
      this.checkSSRF(paramPath, value, threats);
    }

    if (COMMAND_PARAM_NAMES.test(leafKey)) {
      this.checkCommandInjection(paramPath, value, threats);
    }

    this.checkCredentialLeakage(paramPath, value, threats);
    this.checkDestructiveOperation(paramPath, value, threats);
  }

  // ── Private detection methods ──

  private checkParameterOverflow(name: string, value: string, threats: McpCallThreat[]): void {
    if (value.length > this.config.max_param_length) {
      threats.push({
        type: McpCallThreatType.ParameterOverflow,
        severity: 'medium',
        parameter: name,
        description: `Parameter "${name}" exceeds maximum length (${value.length} > ${this.config.max_param_length})`,
        evidence: `length=${value.length}`,
        blocked: true,
      });
    }
  }

  private checkPathTraversal(name: string, value: string, threats: McpCallThreat[]): void {
    for (const pattern of PATH_TRAVERSAL_PATTERNS) {
      const match = pattern.exec(value);
      if (match) {
        threats.push({
          type: McpCallThreatType.PathTraversal,
          severity: 'critical',
          parameter: name,
          description: `Path traversal sequence detected in parameter "${name}"`,
          evidence: match[0],
          blocked: true,
        });
        return;
      }
    }

    // Check allowed paths with proper directory-boundary comparison
    if (this.config.allowed_paths.length > 0) {
      const resolved = value.replace(/\\/g, '/');
      const isAllowed = this.config.allowed_paths.some(allowed => {
        const normalizedAllowed = allowed.replace(/\\/g, '/').replace(/\/+$/, '');
        return resolved === normalizedAllowed || resolved.startsWith(normalizedAllowed + '/');
      });
      if (!isAllowed) {
        threats.push({
          type: McpCallThreatType.PathTraversal,
          severity: 'high',
          parameter: name,
          description: `Path "${value}" is outside allowed directories`,
          evidence: `allowed=${this.config.allowed_paths.join(',')}`,
          blocked: true,
        });
      }
    }
  }

  private checkSSRF(name: string, value: string, threats: McpCallThreat[]): void {
    for (const pattern of this.blockedUrlRegexes) {
      const match = pattern.exec(value);
      if (match) {
        threats.push({
          type: McpCallThreatType.SSRF,
          severity: 'critical',
          parameter: name,
          description: `Potential SSRF: URL parameter "${name}" targets a private/internal address`,
          evidence: match[0],
          blocked: true,
        });
        return;
      }
    }
  }

  private checkCommandInjection(name: string, value: string, threats: McpCallThreat[]): void {
    let matches = 0;
    const evidenceParts: string[] = [];
    for (const pattern of COMMAND_INJECTION_PATTERNS) {
      const match = pattern.exec(value);
      if (match) {
        matches++;
        evidenceParts.push(match[0]);
      }
    }
    if (matches >= 1) {
      threats.push({
        type: McpCallThreatType.CommandInjection,
        severity: 'critical',
        parameter: name,
        description: `Potential command injection detected in parameter "${name}" (${matches} pattern${matches > 1 ? 's' : ''} matched)`,
        evidence: evidenceParts.join(', '),
        blocked: true,
      });
    }
  }

  private checkCredentialLeakage(name: string, value: string, threats: McpCallThreat[]): void {
    for (const pattern of CREDENTIAL_PATTERNS) {
      const match = pattern.exec(value);
      if (match) {
        threats.push({
          type: McpCallThreatType.CredentialLeakage,
          severity: 'high',
          parameter: name,
          description: `Potential credential or secret detected in parameter "${name}"`,
          evidence: `[REDACTED — matched ${this.describeCredentialPattern(pattern)}]`,
          blocked: true,
        });
        return;
      }
    }
  }

  private checkDestructiveOperation(name: string, value: string, threats: McpCallThreat[]): void {
    for (const pattern of DESTRUCTIVE_PATTERNS) {
      const match = pattern.exec(value);
      if (match) {
        threats.push({
          type: McpCallThreatType.DestructiveOperation,
          severity: 'high',
          parameter: name,
          description: `Destructive operation pattern detected in parameter "${name}"`,
          evidence: match[0],
          blocked: true,
        });
        return;
      }
    }
  }

  /** Describe a credential pattern without echoing the matched content. */
  private describeCredentialPattern(pattern: RegExp): string {
    const src = pattern.source;
    if (src.includes('ghp_')) return 'GitHub PAT pattern';
    if (src.includes('gho_')) return 'GitHub OAuth pattern';
    if (src.includes('github_pat_')) return 'GitHub fine-grained PAT pattern';
    if (src.includes('sk-')) return 'OpenAI-style key pattern';
    if (src.includes('xox[')) return 'Slack token pattern';
    if (src.includes('AKIA')) return 'AWS access key pattern';
    if (src.includes('PRIVATE')) return 'private key pattern';
    if (src.includes('eyJ')) return 'JWT pattern';
    return 'credential pattern';
  }
}
