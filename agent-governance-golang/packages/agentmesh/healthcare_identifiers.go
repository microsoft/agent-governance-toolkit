// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import (
	"regexp"
	"sort"
)

// HealthcareIdentifierKind identifies the kind of healthcare identifier found.
type HealthcareIdentifierKind string

const (
	// HealthcareIdentifierMedicalRecordNumber is a context-labeled MRN.
	HealthcareIdentifierMedicalRecordNumber HealthcareIdentifierKind = "medical_record_number"
	// HealthcareIdentifierNationalProviderIdentifier is a provider NPI.
	HealthcareIdentifierNationalProviderIdentifier HealthcareIdentifierKind = "national_provider_identifier"
	// HealthcareIdentifierHealthPlan is a health-plan, member, or policy identifier.
	HealthcareIdentifierHealthPlan HealthcareIdentifierKind = "health_plan_identifier"
)

// HealthcareIdentifierMatch identifies a detected value by its kind and byte range.
type HealthcareIdentifierMatch struct {
	Kind  HealthcareIdentifierKind
	Start int
	End   int
}

type healthcareIdentifierPattern struct {
	kind    HealthcareIdentifierKind
	pattern *regexp.Regexp
}

var healthcareIdentifierPatterns = [...]healthcareIdentifierPattern{
	{
		kind: HealthcareIdentifierMedicalRecordNumber,
		pattern: regexp.MustCompile(
			`(?i)(^|[^A-Za-z0-9])(mrn|medical[ \t\r\n_-]*record)[ \t\r\n_#:-]*([A-Za-z0-9]{6,12})`,
		),
	},
	{
		kind: HealthcareIdentifierNationalProviderIdentifier,
		pattern: regexp.MustCompile(
			`(?i)(^|[^A-Za-z0-9])(npi|provider[ \t\r\n_-]*id)[ \t\r\n_#:-]*([0-9]{10})`,
		),
	},
	{
		kind: HealthcareIdentifierHealthPlan,
		pattern: regexp.MustCompile(
			`(?i)(^|[^A-Za-z0-9])(hpid|health[ \t\r\n_-]*plan[ \t\r\n_-]*id|member[ \t\r\n_-]*id|policy[ \t\r\n_-]*id)[ \t\r\n_#:-]*([A-Za-z0-9]{8,15})`,
		),
	},
}

// FindHealthcareIdentifiers finds context-labeled MRNs, NPIs, and
// health-plan/member/policy identifiers in text.
//
// MRNs must contain 6-12 ASCII letters or digits, health-plan identifiers
// 8-15, and NPIs exactly 10 ASCII digits with a valid 80840-prefixed Luhn
// check digit. Start is inclusive and End is exclusive; both are byte offsets
// covering only the identifier value. Results are ordered by position.
//
// This detector does not classify data, redact values, verify that an NPI was
// issued, or establish HIPAA/SOC 2 compliance. NPIs identify providers and
// are not inherently PHI.
func FindHealthcareIdentifiers(text string) []HealthcareIdentifierMatch {
	matches := make([]HealthcareIdentifierMatch, 0)
	for _, detector := range healthcareIdentifierPatterns {
		for _, indices := range detector.pattern.FindAllStringSubmatchIndex(text, -1) {
			if len(indices) < 8 {
				continue
			}
			start, end := indices[6], indices[7]
			if end < len(text) && isHealthcareIdentifierContinuation(text[end]) {
				continue
			}
			if detector.kind == HealthcareIdentifierNationalProviderIdentifier &&
				!isValidNPI(text[start:end]) {
				continue
			}
			matches = append(matches, HealthcareIdentifierMatch{
				Kind:  detector.kind,
				Start: start,
				End:   end,
			})
		}
	}

	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Start != matches[j].Start {
			return matches[i].Start < matches[j].Start
		}
		if matches[i].End != matches[j].End {
			return matches[i].End < matches[j].End
		}
		return matches[i].Kind < matches[j].Kind
	})
	return matches
}

func isHealthcareIdentifierContinuation(value byte) bool {
	return value >= 'A' && value <= 'Z' ||
		value >= 'a' && value <= 'z' ||
		value >= '0' && value <= '9' ||
		value == '_' || value == '-'
}

func isValidNPI(npi string) bool {
	if len(npi) != 10 {
		return false
	}
	for i := 0; i < len(npi); i++ {
		if npi[i] < '0' || npi[i] > '9' {
			return false
		}
	}

	prefixedNPI := "80840" + npi
	checksum := 0
	double := false
	for i := len(prefixedNPI) - 1; i >= 0; i-- {
		digit := int(prefixedNPI[i] - '0')
		if double {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		checksum += digit
		double = !double
	}
	return checksum%10 == 0
}
