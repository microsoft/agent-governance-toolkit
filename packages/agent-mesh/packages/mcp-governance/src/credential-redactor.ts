// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import {
  CredentialPatternDefinition,
  CredentialRedaction,
  CredentialRedactionResult,
  CredentialRedactorConfig,
} from './types';
import {
  createRegexScanBudget,
  isRecord,
  truncatePreview,
  validateRegex,
} from './utils';

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

/**
 * Redacts credential-like values from strings and structured objects.
 */
export class CredentialRedactor {
  private readonly replacementText: string;
  private readonly redactSensitiveKeys: boolean;
  private readonly patterns: CompiledPattern[];
  private readonly clock: CredentialRedactorConfig['clock'];
  private readonly scanTimeoutMs: CredentialRedactorConfig['scanTimeoutMs'];

  constructor(config: CredentialRedactorConfig = {}) {
    this.replacementText = config.replacementText ?? DEFAULT_REPLACEMENT;
    this.redactSensitiveKeys = config.redactSensitiveKeys ?? true;
    this.clock = config.clock;
    this.scanTimeoutMs = config.scanTimeoutMs;
    this.patterns = [...BUILTIN_PATTERNS, ...(config.customPatterns ?? [])].map(
      (definition) => ({
        name: definition.name,
        pattern: toGlobalPattern(definition.pattern),
        replacement: definition.replacement ?? this.replacementText,
      }),
    );
  }

  redactString(
    value: string,
    path?: string,
  ): CredentialRedactionResult<string> {
    const budget = createRegexScanBudget(this.clock, this.scanTimeoutMs);
    return this.redactStringWithBudget(value, path, budget);
  }

  redact<T>(value: T): CredentialRedactionResult<T> {
    const redactions: CredentialRedaction[] = [];
    const seen = new WeakMap<object, unknown>();
    const budget = createRegexScanBudget(this.clock, this.scanTimeoutMs);
    const redacted = this.redactNode(value, '$', redactions, seen, budget) as T;
    return {
      redacted,
      redactions,
    };
  }

  private redactStringWithBudget(
    value: string,
    path: string | undefined,
    budget: ReturnType<typeof createRegexScanBudget>,
  ): CredentialRedactionResult<string> {
    let nextValue = value;
    const redactions: CredentialRedaction[] = [];

    for (const pattern of this.patterns) {
      budget.checkpoint('Regex scan exceeded time budget - content blocked');
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
          matchedValueType: pattern.name,
          matchedTextPreview: truncatePreview(match[0]),
        });
      }

      nextValue = nextValue.replace(pattern.pattern, pattern.replacement);
    }

    return {
      redacted: nextValue,
      redactions,
    };
  }

  private redactNode(
    value: unknown,
    path: string,
    redactions: CredentialRedaction[],
    seen: WeakMap<object, unknown>,
    budget: ReturnType<typeof createRegexScanBudget>,
  ): unknown {
    if (typeof value === 'string') {
      budget.checkpoint('Regex scan exceeded time budget - content blocked');
      const result = this.redactStringWithBudget(value, path, budget);
      redactions.push(...result.redactions);
      return result.redacted;
    }

    if (Array.isArray(value)) {
      return value.map((item, index) =>
        this.redactNode(item, `${path}[${index}]`, redactions, seen, budget),
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
          matchedValueType: 'sensitive_key',
          matchedTextPreview: truncatePreview(current),
        });
        clone[key] = this.replacementText;
        continue;
      }

      clone[key] = this.redactNode(current, childPath, redactions, seen, budget);
    }

    return clone;
  }
}

function toGlobalPattern(pattern: RegExp | string): RegExp {
  const compiled = pattern instanceof RegExp
    ? new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`)
    : new RegExp(pattern, 'g');
  validateRegex(compiled);

  if (pattern instanceof RegExp) {
    return compiled;
  }
  return compiled;
}
