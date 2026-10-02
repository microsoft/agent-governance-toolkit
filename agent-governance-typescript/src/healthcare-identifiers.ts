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
    expression:
      /(?:^|[^A-Za-z0-9])(?:[Mm][Rr][Nn]|[Mm][Ee][Dd][Ii][Cc][Aa][Ll][ \t\r\n_-]*[Rr][Ee][Cc][Oo][Rr][Dd])[ \t\r\n_#:-]*([A-Za-z0-9]{6,12})/g,
  },
  {
    kind: 'national_provider_identifier',
    expression:
      /(?:^|[^A-Za-z0-9])(?:[Nn][Pp][Ii]|[Pp][Rr][Oo][Vv][Ii][Dd][Ee][Rr][ \t\r\n_-]*[Ii][Dd])[ \t\r\n_#:-]*([0-9]{10})/g,
  },
  {
    kind: 'health_plan_identifier',
    expression:
      /(?:^|[^A-Za-z0-9])(?:[Hh][Pp][Ii][Dd]|[Hh][Ee][Aa][Ll][Tt][Hh][ \t\r\n_-]*[Pp][Ll][Aa][Nn](?:[ \t\r\n_-]*[Ii][Dd])?|[Mm][Ee][Mm][Bb][Ee][Rr][ \t\r\n_-]*(?:[Ii][Dd][Ee][Nn][Tt][Ii][Ff][Ii][Cc][Aa][Tt][Ii][Oo][Nn]|[Ii][Dd])|[Pp][Oo][Ll][Ii][Cc][Yy][ \t\r\n_-]*[Ii][Dd])[ \t\r\n_#:-]*([A-Za-z0-9]{8,15})/g,
  },
];

const identifierContinuation = /[\p{L}\p{N}\p{M}_-]/u;

/**
 * Finds context-labeled MRNs, NPIs, and health-plan/member/policy identifiers.
 *
 * MRNs are limited to 6-12 ASCII letters or digits, health-plan identifiers
 * to 8-15, and both require at least one digit. Letter-initial values require
 * a separator after the cue; digits-only values may follow immediately. NPIs
 * must be exactly 10 ASCII digits with a valid 80840-prefixed Luhn check digit.
 * Ranges cover only the identifier values and results are ordered by position.
 * This function does not classify or redact data, verify NPI issuance, or
 * establish HIPAA/SOC 2 compliance. NPIs identify providers and are not
 * inherently PHI.
 */
export function findHealthcareIdentifiers(text: string): HealthcareIdentifierMatch[] {
  const matches: HealthcareIdentifierMatch[] = [];

  for (const { kind, expression } of patterns) {
    for (const match of text.matchAll(expression)) {
      const identifier = match[1];
      const fullStart = match.index;
      if (identifier === undefined || fullStart === undefined) {
        continue;
      }

      const start = fullStart + match[0].length - identifier.length;
      const end = start + identifier.length;
      if (isIdentifierContinuation(text, end)) {
        continue;
      }
      if (kind !== 'national_provider_identifier' && !/[0-9]/.test(identifier)) {
        continue;
      }
      if (identifier[0] < '0' || identifier[0] > '9') {
        if (start === 0 || !isIdentifierSeparator(text[start - 1])) {
          continue;
        }
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

function isIdentifierContinuation(text: string, index: number): boolean {
  const codePoint = text.codePointAt(index);
  return (
    codePoint !== undefined &&
    identifierContinuation.test(String.fromCodePoint(codePoint))
  );
}

function isIdentifierSeparator(character: string | undefined): boolean {
  return character !== undefined && /[ \t\r\n_#:-]/.test(character);
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
