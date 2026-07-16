// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  McpRuntimeValidator,
  McpCallThreatType,
  McpToolCall,
} from '../src/mcp-runtime-validator';

describe('McpRuntimeValidator', () => {
  let validator: McpRuntimeValidator;

  beforeEach(() => {
    validator = new McpRuntimeValidator();
  });

  // ── Safe calls ──

  describe('safe tool calls', () => {
    it('allows a benign file read', () => {
      const call: McpToolCall = {
        tool_name: 'read_file',
        arguments: { file_path: '/home/user/data/report.csv' },
      };
      const result = validator.validate(call);
      expect(result.safe).toBe(true);
      expect(result.threats).toHaveLength(0);
    });

    it('allows a normal URL fetch', () => {
      const call: McpToolCall = {
        tool_name: 'fetch',
        arguments: { url: 'https://api.example.com/v1/data' },
      };
      const result = validator.validate(call);
      expect(result.safe).toBe(true);
    });

    it('allows normal command execution', () => {
      const call: McpToolCall = {
        tool_name: 'execute',
        arguments: { command: 'ls -la /tmp/output' },
      };
      const result = validator.validate(call);
      expect(result.safe).toBe(true);
    });

    it('validateAll returns results for all calls', () => {
      const calls: McpToolCall[] = [
        { tool_name: 'read_file', arguments: { path: '/data/a.txt' } },
        { tool_name: 'write_file', arguments: { path: '/data/b.txt' } },
      ];
      const results = validator.validateAll(calls);
      expect(results).toHaveLength(2);
      expect(results.every(r => r.safe)).toBe(true);
    });
  });

  // ── Path Traversal ──

  describe('path traversal detection', () => {
    it('blocks ../../etc/passwd in file_path', () => {
      const call: McpToolCall = {
        tool_name: 'read_file',
        arguments: { file_path: '../../etc/passwd' },
      };
      const result = validator.validate(call);
      expect(result.safe).toBe(false);
      expect(result.threats.some(t => t.type === McpCallThreatType.PathTraversal)).toBe(true);
      expect(result.threats[0].severity).toBe('critical');
    });

    it('blocks URL-encoded traversal', () => {
      const call: McpToolCall = {
        tool_name: 'read_file',
        arguments: { file_path: '..%2F..%2Fetc%2Fpasswd' },
      };
      const result = validator.validate(call);
      expect(result.threats.some(t => t.type === McpCallThreatType.PathTraversal)).toBe(true);
    });

    it('blocks double-encoded traversal', () => {
      const call: McpToolCall = {
        tool_name: 'path',
        arguments: { path: '%252e%252e%252f' },
      };
      const result = validator.validate(call);
      expect(result.threats.some(t => t.type === McpCallThreatType.PathTraversal)).toBe(true);
    });

    it('enforces allowed_paths when configured', () => {
      const restricted = new McpRuntimeValidator({
        allowed_paths: ['/data/safe'],
      });
      const call: McpToolCall = {
        tool_name: 'read_file',
        arguments: { file_path: '/etc/shadow' },
      };
      const result = restricted.validate(call);
      expect(result.threats.some(t =>
        t.type === McpCallThreatType.PathTraversal && t.severity === 'high'
      )).toBe(true);
    });

    it('allows paths within allowed_paths', () => {
      const restricted = new McpRuntimeValidator({
        allowed_paths: ['/data'],
      });
      const call: McpToolCall = {
        tool_name: 'read_file',
        arguments: { file_path: '/data/reports/output.csv' },
      };
      const result = restricted.validate(call);
      expect(result.threats.filter(t => t.type === McpCallThreatType.PathTraversal)).toHaveLength(0);
    });
  });

  // ── SSRF ──

  describe('SSRF detection', () => {
    it('blocks AWS metadata endpoint', () => {
      const call: McpToolCall = {
        tool_name: 'fetch',
        arguments: { url: 'http://169.254.169.254/latest/meta-data/' },
      };
      const result = validator.validate(call);
      expect(result.safe).toBe(false);
      expect(result.threats.some(t => t.type === McpCallThreatType.SSRF)).toBe(true);
      expect(result.threats[0].severity).toBe('critical');
    });

    it('blocks localhost access', () => {
      const call: McpToolCall = {
        tool_name: 'fetch',
        arguments: { url: 'http://127.0.0.1:8080/admin' },
      };
      const result = validator.validate(call);
      expect(result.threats.some(t => t.type === McpCallThreatType.SSRF)).toBe(true);
    });

    it('blocks private IP ranges', () => {
      const call: McpToolCall = {
        tool_name: 'endpoint',
        arguments: { endpoint: 'http://10.0.0.1/internal-api' },
      };
      const result = validator.validate(call);
      expect(result.threats.some(t => t.type === McpCallThreatType.SSRF)).toBe(true);
    });

    it('blocks GCP metadata endpoint', () => {
      const call: McpToolCall = {
        tool_name: 'fetch',
        arguments: { url: 'http://metadata.google.internal/computeMetadata/v1/' },
      };
      const result = validator.validate(call);
      expect(result.threats.some(t => t.type === McpCallThreatType.SSRF)).toBe(true);
    });

    it('allows public URLs', () => {
      const call: McpToolCall = {
        tool_name: 'fetch',
        arguments: { url: 'https://api.github.com/repos/test/test' },
      };
      const result = validator.validate(call);
      expect(result.threats.filter(t => t.type === McpCallThreatType.SSRF)).toHaveLength(0);
    });
  });

  // ── Command Injection ──

  describe('command injection detection', () => {
    it('blocks pipe operator', () => {
      const call: McpToolCall = {
        tool_name: 'run',
        arguments: { command: 'echo hello | cat /etc/passwd' },
      };
      const result = validator.validate(call);
      expect(result.threats.some(t => t.type === McpCallThreatType.CommandInjection)).toBe(true);
      expect(result.threats[0].severity).toBe('critical');
    });

    it('blocks command substitution', () => {
      const call: McpToolCall = {
        tool_name: 'exec',
        arguments: { command: 'echo $(cat /etc/shadow)' },
      };
      const result = validator.validate(call);
      expect(result.threats.some(t => t.type === McpCallThreatType.CommandInjection)).toBe(true);
    });

    it('blocks backtick injection', () => {
      const call: McpToolCall = {
        tool_name: 'run',
        arguments: { command: 'echo `rm -rf /`' },
      };
      const result = validator.validate(call);
      expect(result.threats.some(t => t.type === McpCallThreatType.CommandInjection)).toBe(true);
    });

    it('blocks semicolon chaining', () => {
      const call: McpToolCall = {
        tool_name: 'shell',
        arguments: { shell: 'ls; rm -rf /' },
      };
      const result = validator.validate(call);
      expect(result.threats.some(t => t.type === McpCallThreatType.CommandInjection)).toBe(true);
    });
  });

  // ── Credential Leakage ──

  describe('credential leakage detection', () => {
    it('detects GitHub PAT in any parameter', () => {
      const call: McpToolCall = {
        tool_name: 'http_request',
        arguments: {
          url: 'https://api.github.com',
          file_path: 'sk-fake-token-value-1234567890abcdef12',
        },
      };
      const result = validator.validate(call);
      expect(result.threats.some(t => t.type === McpCallThreatType.CredentialLeakage)).toBe(true);
    });

    it('detects AWS access key', () => {
      const call: McpToolCall = {
        tool_name: 'configure',
        arguments: { path: 'key=AKIAIOSFODNN7EXAMPLE' },
      };
      const result = validator.validate(call);
      expect(result.threats.some(t => t.type === McpCallThreatType.CredentialLeakage)).toBe(true);
    });

    it('detects JWT tokens', () => {
      const call: McpToolCall = {
        tool_name: 'send',
        arguments: {
          url: 'https://api.example.com',
          target: 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123',
        },
      };
      const result = validator.validate(call);
      expect(result.threats.some(t => t.type === McpCallThreatType.CredentialLeakage)).toBe(true);
    });

    it('detects private key material', () => {
      const call: McpToolCall = {
        tool_name: 'write_file',
        arguments: {
          path: '/tmp/key.pem',
          file_path: '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...',
        },
      };
      const result = validator.validate(call);
      expect(result.threats.some(t => t.type === McpCallThreatType.CredentialLeakage)).toBe(true);
    });
  });

  // ── Destructive Operations ──

  describe('destructive operation detection', () => {
    it('blocks SQL DROP TABLE', () => {
      const call: McpToolCall = {
        tool_name: 'query_database',
        arguments: { query: 'DROP TABLE users;' },
      };
      const result = validator.validate(call);
      expect(result.threats.some(t => t.type === McpCallThreatType.DestructiveOperation)).toBe(true);
      expect(result.threats[0].severity).toBe('high');
    });

    it('blocks rm -rf', () => {
      const call: McpToolCall = {
        tool_name: 'execute',
        arguments: { command: 'rm -rf /' },
      };
      const result = validator.validate(call);
      expect(result.threats.some(t => t.type === McpCallThreatType.DestructiveOperation)).toBe(true);
    });

    it('blocks DELETE FROM SQL', () => {
      const call: McpToolCall = {
        tool_name: 'db_query',
        arguments: { query: 'DELETE FROM production_records' },
      };
      const result = validator.validate(call);
      expect(result.threats.some(t => t.type === McpCallThreatType.DestructiveOperation)).toBe(true);
    });
  });

  // ── Parameter Overflow ──

  describe('parameter overflow', () => {
    it('blocks oversized parameters', () => {
      const call: McpToolCall = {
        tool_name: 'process',
        arguments: { path: 'x'.repeat(15_000) },
      };
      const result = validator.validate(call);
      expect(result.threats.some(t => t.type === McpCallThreatType.ParameterOverflow)).toBe(true);
    });

    it('respects custom max_param_length', () => {
      const strict = new McpRuntimeValidator({ max_param_length: 100 });
      const call: McpToolCall = {
        tool_name: 'test',
        arguments: { path: 'x'.repeat(200) },
      };
      const result = strict.validate(call);
      expect(result.threats.some(t => t.type === McpCallThreatType.ParameterOverflow)).toBe(true);
    });
  });

  // ── Configuration ──

  describe('configuration', () => {
    it('block_on_high_severity_only ignores low severity', () => {
      const lenient = new McpRuntimeValidator({
        block_on_high_severity_only: true,
      });
      // Parameter overflow is medium severity
      const call: McpToolCall = {
        tool_name: 'test',
        arguments: { path: 'x'.repeat(15_000) },
      };
      const result = lenient.validate(call);
      expect(result.threats.length).toBeGreaterThan(0);
      expect(result.blocked).toBe(false); // medium severity, not blocked
    });

    it('block_on_threat=false never blocks', () => {
      const permissive = new McpRuntimeValidator({ block_on_threat: false });
      const call: McpToolCall = {
        tool_name: 'read_file',
        arguments: { file_path: '../../etc/passwd' },
      };
      const result = permissive.validate(call);
      expect(result.threats.length).toBeGreaterThan(0);
      expect(result.blocked).toBe(false);
    });

    it('custom blocked_url_patterns work', () => {
      const custom = new McpRuntimeValidator({
        blocked_url_patterns: ['internal\\.corp'],
      });
      const call: McpToolCall = {
        tool_name: 'fetch',
        arguments: { url: 'http://internal.corp/admin' },
      };
      const result = custom.validate(call);
      expect(result.threats.some(t => t.type === McpCallThreatType.SSRF)).toBe(true);
    });
  });

  // ── Combined threats ──

  describe('multiple threats in one call', () => {
    it('detects both SSRF and credential leakage', () => {
      const call: McpToolCall = {
        tool_name: 'http_request',
        arguments: {
          url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
          file_path: 'sk-1234567890abcdef1234567890abcdef12',
        },
      };
      const result = validator.validate(call);
      expect(result.threats.length).toBeGreaterThanOrEqual(2);
      const types = result.threats.map(t => t.type);
      expect(types).toContain(McpCallThreatType.SSRF);
      expect(types).toContain(McpCallThreatType.CredentialLeakage);
    });
  });
});
