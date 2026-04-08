// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  CredentialPatternDefinition,
  CredentialRedactionResult,
  CredentialRedactorConfig,
  MCPRedaction,
} from './types';
import { isRecord, truncatePreview, validateRegex } from './mcp-utils';

const DEFAULT_REPLACEMENT = '[REDACTED]';
const SENSITIVE_KEY_PATTERN = /(password|passwd|pwd|secret|token|api[_-]?key|connection.?string|accountkey|sharedaccesssignature|sas)/i;

const BUILTIN_PATTERNS: CredentialPatternDefinition[] = [
  { name: 'openai_key', pattern: /\bsk-[A-Za-z0-9]{16,}\b/g },
  { name: 'github_token', pattern: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g },
  { name: 'aws_access_key', pattern: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'bearer_token', pattern: /\bBearer\s+[A-Za-z0-9._\-+/=]{10,}\b/gi },
  {
    name: 'connection_string',
    pattern: /\b(?:AccountKey|SharedAccessKey|Password|Pwd|Secret|ApiKey)\s*=\s*[^;,\s]+/gi,
  },
  {
    name: 'pem_block',
    pattern: /-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----/g,
  },
];

interface CompiledPattern {
  name: string;
  pattern: RegExp;
  replacement: string;
}

export class CredentialRedactor {
  private readonly replacementText: string;
  private readonly redactSensitiveKeys: boolean;
  private readonly patterns: CompiledPattern[];

  constructor(config: CredentialRedactorConfig = {}) {
    this.replacementText = config.replacementText ?? DEFAULT_REPLACEMENT;
    this.redactSensitiveKeys = config.redactSensitiveKeys ?? true;
    this.patterns = [...BUILTIN_PATTERNS, ...(config.customPatterns ?? [])].map(
      (definition) => ({
        name: definition.name,
        pattern: toGlobalPattern(definition.pattern),
        replacement: definition.replacement ?? this.replacementText,
      }),
    );
  }

  redactString(value: string, path?: string): CredentialRedactionResult<string> {
    let nextValue = value;
    const redactions: MCPRedaction[] = [];

    for (const pattern of this.patterns) {
      pattern.pattern.lastIndex = 0;
      const matches = [...nextValue.matchAll(pattern.pattern)];
      if (matches.length === 0) {
        continue;
      }

      for (const match of matches) {
        redactions.push({
          type: pattern.name,
          path,
          replacement: pattern.replacement,
          matchedText: truncatePreview(match[0]),
        });
      }

      nextValue = nextValue.replace(pattern.pattern, pattern.replacement);
    }

    return {
      redacted: nextValue,
      redactions,
    };
  }

  redact<T>(value: T): CredentialRedactionResult<T> {
    const redactions: MCPRedaction[] = [];
    const seen = new WeakMap<object, unknown>();

    const redacted = this.redactNode(value, '$', redactions, seen) as T;
    return {
      redacted,
      redactions,
    };
  }

  private redactNode(
    value: unknown,
    path: string,
    redactions: MCPRedaction[],
    seen: WeakMap<object, unknown>,
  ): unknown {
    if (typeof value === 'string') {
      const result = this.redactString(value, path);
      redactions.push(...result.redactions);
      return result.redacted;
    }

    if (Array.isArray(value)) {
      return value.map((item, index) =>
        this.redactNode(item, `${path}[${index}]`, redactions, seen),
      );
    }

    if (!isRecord(value)) {
      return value;
    }

    if (seen.has(value)) {
      return seen.get(value);
    }

    const clone: Record<string, unknown> = {};
    seen.set(value, clone);

    for (const [key, current] of Object.entries(value)) {
      const childPath = `${path}.${key}`;

      if (
        this.redactSensitiveKeys
        && SENSITIVE_KEY_PATTERN.test(key)
        && typeof current === 'string'
      ) {
        redactions.push({
          type: 'sensitive_key',
          path: childPath,
          replacement: this.replacementText,
          matchedText: truncatePreview(current),
        });
        clone[key] = this.replacementText;
        continue;
      }

      clone[key] = this.redactNode(current, childPath, redactions, seen);
    }

    return clone;
  }
}

function toGlobalPattern(pattern: RegExp | string): RegExp {
  const compiled = pattern instanceof RegExp
    ? new RegExp(
      pattern.source,
      pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`,
    )
    : new RegExp(pattern, 'g');
  validateRegex(compiled);

  if (pattern instanceof RegExp) {
    return compiled;
  }

  return compiled;
}
