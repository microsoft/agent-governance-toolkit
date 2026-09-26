// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package agentmesh

import "testing"

func TestFindHealthcareIdentifiersContextualMatches(t *testing.T) {
	cases := []struct {
		text  string
		kind  HealthcareIdentifierKind
		value string
	}{
		{"Patient MRN: A123456789", HealthcareIdentifierMedicalRecordNumber, "A123456789"},
		{"medical record # Z987654", HealthcareIdentifierMedicalRecordNumber, "Z987654"},
		{"medical_record: Z987654", HealthcareIdentifierMedicalRecordNumber, "Z987654"},
		{"medical-record: Z987654", HealthcareIdentifierMedicalRecordNumber, "Z987654"},
		{"MRN-123456", HealthcareIdentifierMedicalRecordNumber, "123456"},
		{"MRN_123456789012", HealthcareIdentifierMedicalRecordNumber, "123456789012"},
		{"Provider NPI: 1234567893", HealthcareIdentifierNationalProviderIdentifier, "1234567893"},
		{"npi 1234567893", HealthcareIdentifierNationalProviderIdentifier, "1234567893"},
		{"provider id 1234567893", HealthcareIdentifierNationalProviderIdentifier, "1234567893"},
		{"provider-id # 1234567893", HealthcareIdentifierNationalProviderIdentifier, "1234567893"},
		{"provider_id: 1234567893", HealthcareIdentifierNationalProviderIdentifier, "1234567893"},
		{"Member ID: ABC12345678", HealthcareIdentifierHealthPlan, "ABC12345678"},
		{"member_id: ABC12345678", HealthcareIdentifierHealthPlan, "ABC12345678"},
		{"member-id # ABC12345678", HealthcareIdentifierHealthPlan, "ABC12345678"},
		{"HPID # 999888777", HealthcareIdentifierHealthPlan, "999888777"},
		{"health plan id X1234567890", HealthcareIdentifierHealthPlan, "X1234567890"},
		{"health-plan_id: X1234567890", HealthcareIdentifierHealthPlan, "X1234567890"},
		{"policy id X1234567890", HealthcareIdentifierHealthPlan, "X1234567890"},
		{"policy-id X1234567890", HealthcareIdentifierHealthPlan, "X1234567890"},
		{"policy_id 123456789012345", HealthcareIdentifierHealthPlan, "123456789012345"},
	}

	for _, test := range cases {
		t.Run(test.text, func(t *testing.T) {
			matches := FindHealthcareIdentifiers(test.text)
			if len(matches) != 1 {
				t.Fatalf("got %d matches, want 1: %#v", len(matches), matches)
			}
			match := matches[0]
			if match.Kind != test.kind {
				t.Errorf("kind = %q, want %q", match.Kind, test.kind)
			}
			if got := test.text[match.Start:match.End]; got != test.value {
				t.Errorf("matched value = %q, want %q", got, test.value)
			}
		})
	}
}

func TestFindHealthcareIdentifiersRejectsValuesWithoutContextOrWithInvalidOrGluedValues(t *testing.T) {
	cases := []string{
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
		"prefixMRN: A123456789",
		"prefixNPI: 1234567893",
		"MRN: characteristics",
		"MRN: ABCDEF_INVALID",
		"MRN: ABCDEF-INVALID",
		"MRN: ABCDEF_more",
		"member_id: misunderstanding",
		"policy_id: misunderstanding",
		"NPI: 1234567893X",
		"medical record: ABCDE",
		"member id: ABC1234",
	}

	for _, text := range cases {
		t.Run(text, func(t *testing.T) {
			if matches := FindHealthcareIdentifiers(text); len(matches) != 0 {
				t.Fatalf("unexpected matches: %#v", matches)
			}
		})
	}
}

func TestFindHealthcareIdentifiersReturnsMatchesInTextOrder(t *testing.T) {
	text := "Member ID: A1234567; MRN: B12345; NPI: 1234567893"
	matches := FindHealthcareIdentifiers(text)
	if len(matches) != 3 {
		t.Fatalf("got %d matches, want 3", len(matches))
	}

	wantKinds := []HealthcareIdentifierKind{
		HealthcareIdentifierHealthPlan,
		HealthcareIdentifierMedicalRecordNumber,
		HealthcareIdentifierNationalProviderIdentifier,
	}
	wantValues := []string{"A1234567", "B12345", "1234567893"}
	for i, match := range matches {
		if match.Kind != wantKinds[i] {
			t.Errorf("match %d kind = %q, want %q", i, match.Kind, wantKinds[i])
		}
		if got := text[match.Start:match.End]; got != wantValues[i] {
			t.Errorf("match %d value = %q, want %q", i, got, wantValues[i])
		}
	}
}
