// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Input Sanitizer
 * 
 * Detects and blocks common attack patterns:
 * - Prompt injection attempts
 * - Path traversal attacks
 * - Command injection
 * - PII exposure
 */

export interface SanitizeResult {
  safe: boolean;
  reason?: string;
  details?: string;
}

export class Sanitizer {
  // Path traversal patterns
  private pathTraversalPatterns = [
    /\.\.\//g,
    /\.\.\\+/g,
    /%2e%2e%2f/gi,
    /%2e%2e\//gi,
    /\.\.%2f/gi,
    /%252e%252e%252f/gi,
  ];

  // Command injection patterns
  private commandInjectionPatterns = [
    /[;&|`$](?![^"']*["'][^"']*$)/,  // Shell metacharacters
    /\$\(.*\)/,                        // Command substitution
    /`.*`/,                            // Backtick execution
    /\|\s*(?:bash|sh|cmd|powershell)/i,
  ];

  // Prompt injection patterns
  private promptInjectionPatterns = [
    /ignore\s+(all\s+)?previous\s+instructions/i,
    /disregard\s+(all\s+)?prior/i,
    /forget\s+everything/i,
    /you\s+are\s+now/i,
    /new\s+instructions?:/i,
    /system:\s*override/i,
    /<\/SYSTEM>/i,
    /<\|endoftext\|>/,
    /\[\[SYSTEM\]\]/i,
  ];

  // PII patterns
  private piiPatterns = [
    // SSN
    /\b\d{3}-\d{2}-\d{4}\b/,
    // Credit card (basic)
    /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/,
    // Email (for detection, not blocking)
    // /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/,
  ];

  check(toolName: string, args: Record<string, any>): SanitizeResult {
    const argsStr = JSON.stringify(args);

    // Check path arguments specifically
    for (const key of ['path', 'file_path', 'filename', 'directory']) {
      if (args[key]) {
        const pathResult = this.checkPath(args[key]);
        if (!pathResult.safe) {
          return pathResult;
        }
      }
    }

    // Check for command injection in string arguments
    for (const [key, value] of Object.entries(args)) {
      if (typeof value === 'string') {
        const cmdResult = this.checkCommandInjection(value);
        if (!cmdResult.safe) {
          return {
            safe: false,
            reason: `Command injection detected in argument '${key}'`,
            details: cmdResult.details,
          };
        }
      }
    }

    // Check for prompt injection
    const promptResult = this.checkPromptInjection(argsStr);
    if (!promptResult.safe) {
      return promptResult;
    }

    // Check for PII
    const piiResult = this.checkPII(argsStr);
    if (!piiResult.safe) {
      return piiResult;
    }

    return { safe: true };
  }

  private checkPath(path: string): SanitizeResult {
    for (const pattern of this.pathTraversalPatterns) {
      if (pattern.test(path)) {
        return {
          safe: false,
          reason: 'Path traversal attempt detected',
          details: `Path contains suspicious pattern: ${path}`,
        };
      }
    }

    // Check for absolute paths to sensitive directories
    const sensitivePaths = [
      '/etc/', '/proc/', '/sys/', '/dev/',
      'C:\\Windows\\', 'C:\\Program Files\\',
      '~/.ssh/', '~/.aws/', '~/.config/',
    ];
    for (const sensitive of sensitivePaths) {
      if (path.toLowerCase().includes(sensitive.toLowerCase())) {
        return {
          safe: false,
          reason: 'Access to sensitive system path',
          details: `Path attempts to access: ${sensitive}`,
        };
      }
    }

    return { safe: true };
  }

  private checkCommandInjection(value: string): SanitizeResult {
    for (const pattern of this.commandInjectionPatterns) {
      if (pattern.test(value)) {
        return {
          safe: false,
          reason: 'Command injection pattern detected',
          details: `Value contains shell metacharacter or injection pattern`,
        };
      }
    }
    return { safe: true };
  }

  private checkPromptInjection(text: string): SanitizeResult {
    for (const pattern of this.promptInjectionPatterns) {
      if (pattern.test(text)) {
        return {
          safe: false,
          reason: 'Potential prompt injection detected',
          details: `Input contains injection pattern`,
        };
      }
    }
    return { safe: true };
  }

  private checkPII(text: string): SanitizeResult {
    for (const pattern of this.piiPatterns) {
      if (pattern.test(text)) {
        return {
          safe: false,
          reason: 'PII detected in input',
          details: 'Input contains sensitive personal information',
        };
      }
    }
    return { safe: true };
  }
}
