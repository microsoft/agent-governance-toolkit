// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/** Category of a healthcare identifier found in text. */
export type HealthcareIdentifierKind =
  | 'medical_record_number'
  | 'national_provider_identifier'
  | 'health_plan_identifier';

/** A detected identifier's half-open UTF-16 range in the scanned text. */
export interface HealthcareIdentifierMatch {
  kind: HealthcareIdentifierKind;
  start: number;
  end: number;
}

interface IdentifierPattern {
  kind: HealthcareIdentifierKind;
  expression: RegExp;
}

const patterns: readonly IdentifierPattern[] = [
  {
    kind: 'medical_record_number',
    expression: /(^|[^A-Za-z0-9])(?:mrn|medical[ \t\r\n_-]*record)[ \t\r\n_#:-]*([A-Za-z0-9]{6,12})/gi,
  },
  {
    kind: 'national_provider_identifier',
    expression: /(^|[^A-Za-z0-9])(?:npi|provider[ \t\r\n_-]*id)[ \t\r\n_#:-]*([0-9]{10})/gi,
  },
  {
    kind: 'health_plan_identifier',
    expression:
      /(^|[^A-Za-z0-9])(?:hpid|health[ \t\r\n_-]*plan[ \t\r\n_-]*id|member[ \t\r\n_-]*id|policy[ \t\r\n_-]*id)[ \t\r\n_#:-]*([A-Za-z0-9]{8,15})/gi,
  },
];

/**
 * Finds context-labeled MRNs, NPIs, and health-plan/member/policy identifiers.
 *
 * MRNs are limited to 6-12 ASCII letters or digits, health-plan identifiers
 * to 8-15, and NPIs to exactly 10 ASCII digits with a valid 80840-prefixed
 * Luhn check digit. Ranges cover only the identifier values and results are
 * ordered by position. This function does not classify or redact data, verify
 * NPI issuance, or establish HIPAA/SOC 2 compliance. NPIs identify providers
 * and are not inherently PHI.
 */
export function findHealthcareIdentifiers(text: string): HealthcareIdentifierMatch[] {
  const matches: HealthcareIdentifierMatch[] = [];

  for (const { kind, expression } of patterns) {
    for (const match of text.matchAll(expression)) {
      const identifier = match[2];
      const fullStart = match.index;
      if (identifier === undefined || fullStart === undefined) {
        continue;
      }

      const start = fullStart + match[0].length - identifier.length;
      const end = start + identifier.length;
      if (isIdentifierContinuation(text[end])) {
        continue;
      }
      if (kind === 'national_provider_identifier' && !isValidNpi(identifier)) {
        continue;
      }

      matches.push({ kind, start, end });
    }
  }

  return matches.sort(
    (left, right) =>
      left.start - right.start ||
      left.end - right.end ||
      left.kind.localeCompare(right.kind),
  );
}

function isIdentifierContinuation(character: string | undefined): boolean {
  return character !== undefined && /[A-Za-z0-9_-]/.test(character);
}

function isValidNpi(npi: string): boolean {
  if (!/^[0-9]{10}$/.test(npi)) {
    return false;
  }

  const prefixedNpi = `80840${npi}`;
  let checksum = 0;
  let doubleDigit = false;
  for (let index = prefixedNpi.length - 1; index >= 0; index -= 1) {
    let digit = prefixedNpi.charCodeAt(index) - 48;
    if (doubleDigit) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }
    checksum += digit;
    doubleDigit = !doubleDigit;
  }
  return checksum % 10 === 0;
}
