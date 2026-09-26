// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { findHealthcareIdentifiers } from '../src/healthcare-identifiers';
import type { HealthcareIdentifierKind } from '../src/healthcare-identifiers';

const positiveCases: Array<[string, HealthcareIdentifierKind, string]> = [
  ['Patient MRN: A123456789', 'medical_record_number', 'A123456789'],
  ['medical record # Z987654', 'medical_record_number', 'Z987654'],
  ['medical_record: Z987654', 'medical_record_number', 'Z987654'],
  ['medical-record: Z987654', 'medical_record_number', 'Z987654'],
  ['MRN-123456', 'medical_record_number', '123456'],
  ['MRN_123456789012', 'medical_record_number', '123456789012'],
  ['Provider NPI: 1234567893', 'national_provider_identifier', '1234567893'],
  ['npi 1234567893', 'national_provider_identifier', '1234567893'],
  ['provider id 1234567893', 'national_provider_identifier', '1234567893'],
  ['provider-id # 1234567893', 'national_provider_identifier', '1234567893'],
  ['provider_id: 1234567893', 'national_provider_identifier', '1234567893'],
  ['Member ID: ABC12345678', 'health_plan_identifier', 'ABC12345678'],
  ['member_id: ABC12345678', 'health_plan_identifier', 'ABC12345678'],
  ['member-id # ABC12345678', 'health_plan_identifier', 'ABC12345678'],
  ['HPID # 999888777', 'health_plan_identifier', '999888777'],
  ['health plan id X1234567890', 'health_plan_identifier', 'X1234567890'],
  ['health-plan_id: X1234567890', 'health_plan_identifier', 'X1234567890'],
  ['policy id X1234567890', 'health_plan_identifier', 'X1234567890'],
  ['policy-id X1234567890', 'health_plan_identifier', 'X1234567890'],
  ['policy_id 123456789012345', 'health_plan_identifier', '123456789012345'],
];

describe('healthcare identifier detection', () => {
  it.each(positiveCases)('detects the value in %s', (text, kind, expectedValue) => {
    const matches = findHealthcareIdentifiers(text);

    expect(matches).toHaveLength(1);
    expect(matches[0].kind).toBe(kind);
    expect(text.slice(matches[0].start, matches[0].end)).toBe(expectedValue);
  });

  it.each([
    '1234567893',
    'The number is 1234567893',
    '5550109999',
    'Call 555-010-9999 for support',
    'NPI: 1234567890',
    'provider id 1111111111',
    'NPI: 555-010-9999',
    'provider-id 555-010-9999',
    'A123456789',
    'Z987654',
    'ABC12345678',
    'XMRN: A123456789',
    'prefixNPI: 1234567893',
    'MRN: ABCDEFGHIJKLM',
    'MRN: ABCDEF_GHIJKL',
    'MRN: ABCDEF-GHIJKL',
    'MRN: ABCDEF_more',
    'member_id: ABCDEFGHIJKLMNOP',
    'policy_id: ABCDEFGHIJKLMNOP',
    'NPI: 1234567893X',
    'medical record: ABCDE',
    'member id: ABC1234',
  ])('rejects uncued, invalid, or glued value %s', (text) => {
    expect(findHealthcareIdentifiers(text)).toEqual([]);
  });

  it('returns multiple matches in text order', () => {
    const text = 'Member ID: A1234567; MRN: B12345; NPI: 1234567893';

    const matches = findHealthcareIdentifiers(text);

    expect(matches.map((match) => match.kind)).toEqual([
      'health_plan_identifier',
      'medical_record_number',
      'national_provider_identifier',
    ]);
    expect(matches.map((match) => text.slice(match.start, match.end))).toEqual([
      'A1234567',
      'B12345',
      '1234567893',
    ]);
  });
});
