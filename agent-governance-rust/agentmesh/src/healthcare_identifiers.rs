// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Context-aware detection of healthcare identifier values.

use regex::Regex;
use std::sync::LazyLock;

static MRN_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(^|[^A-Za-z0-9])(?:mrn|medical[ \t\r\n_-]*record)[ \t\r\n_#:-]*(?P<identifier>[A-Za-z0-9]{6,12})",
    )
    .expect("MRN regex literal must compile")
});

static NPI_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(^|[^A-Za-z0-9])(?:npi|provider[ \t\r\n_-]*id)[ \t\r\n_#:-]*(?P<identifier>[0-9]{10})",
    )
    .expect("NPI regex literal must compile")
});

static HEALTH_PLAN_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(^|[^A-Za-z0-9])(?:hpid|health[ \t\r\n_-]*plan[ \t\r\n_-]*id|member[ \t\r\n_-]*id|policy[ \t\r\n_-]*id)[ \t\r\n_#:-]*(?P<identifier>[A-Za-z0-9]{8,15})",
    )
    .expect("health-plan identifier regex literal must compile")
});

/// Category of a healthcare identifier found by [`find_healthcare_identifiers`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HealthcareIdentifierKind {
    /// A context-labeled medical record number.
    MedicalRecordNumber,
    /// A provider identifier; an NPI is not inherently PHI.
    NationalProviderIdentifier,
    /// A context-labeled health-plan, member, or policy identifier.
    HealthPlanIdentifier,
}

/// A healthcare identifier's half-open byte range within the scanned text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthcareIdentifierMatch {
    /// The kind of identifier detected.
    pub kind: HealthcareIdentifierKind,
    /// Inclusive UTF-8 byte offset of the identifier value.
    pub start: usize,
    /// Exclusive UTF-8 byte offset of the identifier value.
    pub end: usize,
}

/// Finds context-labeled MRNs, NPIs, and health-plan/member/policy identifiers.
///
/// MRNs are limited to 6-12 ASCII letters or digits, health-plan identifiers
/// to 8-15, and NPIs to exactly 10 ASCII digits with a valid 80840-prefixed
/// Luhn check digit. The returned ranges cover only each identifier value.
///
/// This detector does not classify data, redact values, verify that an NPI was
/// issued, or establish HIPAA/SOC 2 compliance. NPIs identify providers and
/// are not inherently PHI.
pub fn find_healthcare_identifiers(text: &str) -> Vec<HealthcareIdentifierMatch> {
    let mut matches = Vec::new();
    collect_matches(
        text,
        &MRN_PATTERN,
        HealthcareIdentifierKind::MedicalRecordNumber,
        &mut matches,
    );
    collect_matches(
        text,
        &NPI_PATTERN,
        HealthcareIdentifierKind::NationalProviderIdentifier,
        &mut matches,
    );
    collect_matches(
        text,
        &HEALTH_PLAN_PATTERN,
        HealthcareIdentifierKind::HealthPlanIdentifier,
        &mut matches,
    );
    matches.sort_by_key(|matched| (matched.start, matched.end));
    matches
}

fn collect_matches(
    text: &str,
    pattern: &Regex,
    kind: HealthcareIdentifierKind,
    matches: &mut Vec<HealthcareIdentifierMatch>,
) {
    for captures in pattern.captures_iter(text) {
        let Some(identifier) = captures.name("identifier") else {
            continue;
        };
        if text
            .as_bytes()
            .get(identifier.end())
            .is_some_and(|byte| is_identifier_continuation(*byte))
        {
            continue;
        }
        if kind == HealthcareIdentifierKind::NationalProviderIdentifier
            && !is_valid_npi(identifier.as_str())
        {
            continue;
        }
        matches.push(HealthcareIdentifierMatch {
            kind,
            start: identifier.start(),
            end: identifier.end(),
        });
    }
}

fn is_identifier_continuation(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

fn is_valid_npi(npi: &str) -> bool {
    if npi.len() != 10 || !npi.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }

    let prefixed_npi = format!("80840{npi}");
    let mut checksum = 0;
    for (position, byte) in prefixed_npi.bytes().rev().enumerate() {
        let mut digit = usize::from(byte - b'0');
        if position % 2 == 1 {
            digit *= 2;
            if digit > 9 {
                digit -= 9;
            }
        }
        checksum += digit;
    }
    checksum % 10 == 0
}

#[cfg(test)]
mod tests {
    use super::{find_healthcare_identifiers, HealthcareIdentifierKind};

    #[test]
    fn detects_context_labeled_identifiers_and_returns_value_ranges() {
        let cases = [
            (
                "Patient MRN: A123456789",
                HealthcareIdentifierKind::MedicalRecordNumber,
                "A123456789",
            ),
            (
                "medical record # Z987654",
                HealthcareIdentifierKind::MedicalRecordNumber,
                "Z987654",
            ),
            (
                "medical_record: Z987654",
                HealthcareIdentifierKind::MedicalRecordNumber,
                "Z987654",
            ),
            (
                "medical-record: Z987654",
                HealthcareIdentifierKind::MedicalRecordNumber,
                "Z987654",
            ),
            (
                "MRN-123456",
                HealthcareIdentifierKind::MedicalRecordNumber,
                "123456",
            ),
            (
                "MRN_123456789012",
                HealthcareIdentifierKind::MedicalRecordNumber,
                "123456789012",
            ),
            (
                "Provider NPI: 1234567893",
                HealthcareIdentifierKind::NationalProviderIdentifier,
                "1234567893",
            ),
            (
                "npi 1234567893",
                HealthcareIdentifierKind::NationalProviderIdentifier,
                "1234567893",
            ),
            (
                "provider id 1234567893",
                HealthcareIdentifierKind::NationalProviderIdentifier,
                "1234567893",
            ),
            (
                "provider-id # 1234567893",
                HealthcareIdentifierKind::NationalProviderIdentifier,
                "1234567893",
            ),
            (
                "provider_id: 1234567893",
                HealthcareIdentifierKind::NationalProviderIdentifier,
                "1234567893",
            ),
            (
                "Member ID: ABC12345678",
                HealthcareIdentifierKind::HealthPlanIdentifier,
                "ABC12345678",
            ),
            (
                "member_id: ABC12345678",
                HealthcareIdentifierKind::HealthPlanIdentifier,
                "ABC12345678",
            ),
            (
                "member-id # ABC12345678",
                HealthcareIdentifierKind::HealthPlanIdentifier,
                "ABC12345678",
            ),
            (
                "HPID # 999888777",
                HealthcareIdentifierKind::HealthPlanIdentifier,
                "999888777",
            ),
            (
                "health plan id X1234567890",
                HealthcareIdentifierKind::HealthPlanIdentifier,
                "X1234567890",
            ),
            (
                "health-plan_id: X1234567890",
                HealthcareIdentifierKind::HealthPlanIdentifier,
                "X1234567890",
            ),
            (
                "policy id X1234567890",
                HealthcareIdentifierKind::HealthPlanIdentifier,
                "X1234567890",
            ),
            (
                "policy-id X1234567890",
                HealthcareIdentifierKind::HealthPlanIdentifier,
                "X1234567890",
            ),
            (
                "policy_id 123456789012345",
                HealthcareIdentifierKind::HealthPlanIdentifier,
                "123456789012345",
            ),
        ];

        for (text, expected_kind, expected_value) in cases {
            let matches = find_healthcare_identifiers(text);
            assert_eq!(matches.len(), 1, "unexpected matches for {text:?}");
            assert_eq!(matches[0].kind, expected_kind, "wrong kind for {text:?}");
            assert_eq!(
                &text[matches[0].start..matches[0].end],
                expected_value,
                "wrong value range for {text:?}"
            );
        }
    }

    #[test]
    fn rejects_uncued_invalid_or_glued_identifiers() {
        let cases = [
            "1234567893",
            "The number is 1234567893",
            "5550109999",
            "Call 555-010-9999 for support",
            "NPI: 1234567890",
            "provider id 1111111111",
            "NPI: 555-010-9999",
            "provider-id 555-010-9999",
            "A123456789",
            "Z987654",
            "ABC12345678",
            "XMRN: A123456789",
            "prefixNPI: 1234567893",
            "MRN: ABCDEFGHIJKLM",
            "MRN: ABCDEF_GHIJKL",
            "MRN: ABCDEF-GHIJKL",
            "MRN: ABCDEF_more",
            "member_id: ABCDEFGHIJKLMNOP",
            "policy_id: ABCDEFGHIJKLMNOP",
            "NPI: 1234567893X",
            "medical record: ABCDE",
            "member id: ABC1234",
        ];

        for text in cases {
            assert!(
                find_healthcare_identifiers(text).is_empty(),
                "unexpected match for {text:?}"
            );
        }
    }

    #[test]
    fn returns_multiple_matches_in_text_order() {
        let text = "Member ID: A1234567; MRN: B12345; NPI: 1234567893";
        let matches = find_healthcare_identifiers(text);

        assert_eq!(matches.len(), 3);
        assert_eq!(
            matches
                .iter()
                .map(|matched| matched.kind)
                .collect::<Vec<_>>(),
            vec![
                HealthcareIdentifierKind::HealthPlanIdentifier,
                HealthcareIdentifierKind::MedicalRecordNumber,
                HealthcareIdentifierKind::NationalProviderIdentifier,
            ]
        );
        assert_eq!(
            matches
                .iter()
                .map(|matched| &text[matched.start..matched.end])
                .collect::<Vec<_>>(),
            vec!["A1234567", "B12345", "1234567893"]
        );
    }
}
