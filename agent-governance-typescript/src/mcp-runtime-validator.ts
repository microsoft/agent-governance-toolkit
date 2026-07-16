// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// ── MCP Runtime Tool Call Validator ──
// Validates MCP tool call parameters at runtime to detect and block
// parameter injection, path traversal, SSRF, credential leakage,
// and destructive operations before they reach the tool server.
//
// This complements the static McpSecurityScanner which analyzes
// tool definitions. This module validates actual tool call arguments
// during execution — the runtime verification layer.

/** Threat categories for runtime tool call validation. */
export enum McpCallThreatType {
  PathTraversal = 'path_traversal',
  CommandInjection = 'command_injection',
  SSRF = 'ssrf',
  CredentialLeakage = 'credential_leakage',
  DestructiveOperation = 'destructive_operation',
  ParameterOverflow = 'parameter_overflow',
}

/** A single threat detected during runtime validation. */
export interface McpCallThreat {
  type: McpCallThreatType;
  severity: 'low' | 'medium' | 'high' | 'critical';
  parameter: string;
  description: string;
  evidence?: string;
  blocked: boolean;
}

/** Result of validating a tool call. */
export interface McpCallValidationResult {
  tool_name: string;
  safe: boolean;
  threats: McpCallThreat[];
  sanitized_params?: Record<string, unknown>;
}

/** A tool call to validate. */
export interface McpToolCall {
  tool_name: string;
  arguments: Record<string, unknown>;
}

/** Configuration for the runtime validator. */
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
  /** Whether to attempt sanitization instead of blocking. Default: false */
  sanitize_instead_of_block: boolean;
}

const DEFAULT_CONFIG: McpRuntimeValidatorConfig = {
  block_on_threat: true,
  block_on_high_severity_only: false,
  allowed_paths: [],
  blocked_url_patterns: [],
  max_param_length: 10_000,
  sanitize_instead_of_block: false,
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
  /\b:(){ :|:& };:\b/,  // fork bomb
];

/** Credential patterns (API keys, tokens, passwords). */
const CREDENTIAL_PATTERNS: RegExp[] = [
  /(?:^|\b)(?:sk|pk|api[_-]?key|token|secret|password|passwd|pwd)\s*[=:]\s*["']?[A-Za-z0-9_\-\.]{16,}/i,
  /ghp_[A-Za-z0-9]{36}/,                           // GitHub PAT
  /gho_[A-Za-z0-9]{36}/,                           // GitHub OAuth
  /github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}/,    // GitHub fine-grained PAT
  /sk-[A-Za-z0-9]{32,}/,                           // OpenAI-style key
  /xox[bpas]-[A-Za-z0-9-]+/,                        // Slack token
  /AKIA[0-9A-Z]{16}/,                               // AWS Access Key
  /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/,     // Private key
  /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+/,          // JWT
];

/** Private/internal IP ranges for SSRF detection. */
const SSRF_PATTERNS: RegExp[] = [
  /127\.0\.0\.\d{1,3}/,                            // localhost
  /0\.0\.0\.0/,                                     // all interfaces
  /::1/,                                            // IPv6 localhost
  /169\.254\.\d{1,3}\.\d{1,3}/,                    // link-local (AWS metadata)
  /10\.\d{1,3}\.\d{1,3}\.\d{1,3}/,                 // private class A
  /172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}/,  // private class B
  /192\.168\.\d{1,3}\.\d{1,3}/,                    // private class C
  /metadata\.google\.internal/i,                    // GCP metadata
  /169\.254\.169\.254/,                             // AWS/Azure metadata
];

// ── Heuristic: identify file-path and URL parameter names ──

const FILE_PATH_PARAM_NAMES = /^(?:file_?path|path|dir(?:ectory)?|folder|filename|file_?name|source|dest(?:ination)?|target|input(?:_?file)?|output(?:_?file)?|cwd|root|base(?:_?path)?|location|url)$/i;
const URL_PARAM_NAMES = /^(?:url|uri|endpoint|href|link|webhook|callback|redirect|fetch_?url|request_?url|api_?url|base_?url|target_?url)$/i;
const COMMAND_PARAM_NAMES = /^(?:command|cmd|script|shell|exec|run|code|eval|expression|query)$/i;

// ── McpRuntimeValidator ──

/**
 * Validates MCP tool call parameters at runtime.
 * Complements McpSecurityScanner (static analysis) with runtime checks.
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

  /** Validate a single tool call. Returns result with threats and safety verdict. */
  validate(call: McpToolCall): McpCallValidationResult {
    const threats: McpCallThreat[] = [];

    for (const [paramName, paramValue] of Object.entries(call.arguments)) {
      const valueStr = typeof paramValue === 'string' ? paramValue : JSON.stringify(paramValue);
      if (!valueStr) continue;

      // Parameter overflow check
      this.checkParameterOverflow(paramName, valueStr, threats);

      // Path traversal (on file-path-like parameters)
      if (FILE_PATH_PARAM_NAMES.test(paramName)) {
        this.checkPathTraversal(paramName, valueStr, threats);
      }

      // URL/SSRF (on URL-like parameters)
      if (URL_PARAM_NAMES.test(paramName)) {
        this.checkSSRF(paramName, valueStr, threats);
      }

      // Command injection (on command-like parameters, or any string param)
      if (COMMAND_PARAM_NAMES.test(paramName)) {
        this.checkCommandInjection(paramName, valueStr, threats);
      }

      // Credential leakage (on ALL parameters)
      this.checkCredentialLeakage(paramName, valueStr, threats);

      // Destructive operation (on ALL parameters)
      this.checkDestructiveOperation(paramName, valueStr, threats);
    }

    const shouldBlock = this.config.block_on_threat && (
      this.config.block_on_high_severity_only
        ? threats.some(t => t.severity === 'high' || t.severity === 'critical')
        : threats.length > 0
    );

    return {
      tool_name: call.tool_name,
      safe: !shouldBlock,
      threats,
      blocked: shouldBlock,
    };
  }

  /** Validate multiple tool calls. */
  validateAll(calls: McpToolCall[]): McpCallValidationResult[] {
    return calls.map(c => this.validate(c));
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
        return; // one finding per parameter
      }
    }

    // Check allowed paths if configured
    if (this.config.allowed_paths.length > 0) {
      const resolved = value.replace(/\\/g, '/');
      const isAllowed = this.config.allowed_paths.some(allowed =>
        resolved.startsWith(allowed.replace(/\\/g, '/'))
      );
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
          evidence: match[0].substring(0, 20) + '...',
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
}
