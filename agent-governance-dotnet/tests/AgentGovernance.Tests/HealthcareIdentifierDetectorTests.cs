// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentGovernance.Security;
using Xunit;

namespace AgentGovernance.Tests;

public class HealthcareIdentifierDetectorTests
{
    [Theory]
    [InlineData("Patient MRN: A123456789", HealthcareIdentifierKind.MedicalRecordNumber, "A123456789")]
    [InlineData("medical record # Z987654", HealthcareIdentifierKind.MedicalRecordNumber, "Z987654")]
    [InlineData("medical_record: Z987654", HealthcareIdentifierKind.MedicalRecordNumber, "Z987654")]
    [InlineData("medical-record: Z987654", HealthcareIdentifierKind.MedicalRecordNumber, "Z987654")]
    [InlineData("MRN-123456", HealthcareIdentifierKind.MedicalRecordNumber, "123456")]
    [InlineData("MRN_123456789012", HealthcareIdentifierKind.MedicalRecordNumber, "123456789012")]
    [InlineData("Provider NPI: 1234567893", HealthcareIdentifierKind.NationalProviderIdentifier, "1234567893")]
    [InlineData("npi 1234567893", HealthcareIdentifierKind.NationalProviderIdentifier, "1234567893")]
    [InlineData("provider id 1234567893", HealthcareIdentifierKind.NationalProviderIdentifier, "1234567893")]
    [InlineData("provider-id # 1234567893", HealthcareIdentifierKind.NationalProviderIdentifier, "1234567893")]
    [InlineData("provider_id: 1234567893", HealthcareIdentifierKind.NationalProviderIdentifier, "1234567893")]
    [InlineData("Member ID: ABC12345678", HealthcareIdentifierKind.HealthPlanIdentifier, "ABC12345678")]
    [InlineData("member_id: ABC12345678", HealthcareIdentifierKind.HealthPlanIdentifier, "ABC12345678")]
    [InlineData("member-id # ABC12345678", HealthcareIdentifierKind.HealthPlanIdentifier, "ABC12345678")]
    [InlineData("HPID # 999888777", HealthcareIdentifierKind.HealthPlanIdentifier, "999888777")]
    [InlineData("health plan id X1234567890", HealthcareIdentifierKind.HealthPlanIdentifier, "X1234567890")]
    [InlineData("health-plan_id: X1234567890", HealthcareIdentifierKind.HealthPlanIdentifier, "X1234567890")]
    [InlineData("policy id X1234567890", HealthcareIdentifierKind.HealthPlanIdentifier, "X1234567890")]
    [InlineData("policy-id X1234567890", HealthcareIdentifierKind.HealthPlanIdentifier, "X1234567890")]
    [InlineData("policy_id 123456789012345", HealthcareIdentifierKind.HealthPlanIdentifier, "123456789012345")]
    public void Find_ReturnsContextualIdentifierValue(
        string text,
        HealthcareIdentifierKind expectedKind,
        string expectedValue)
    {
        var matches = HealthcareIdentifierDetector.Find(text);

        Assert.Single(matches);
        var match = matches[0];
        Assert.Equal(expectedKind, match.Kind);
        Assert.Equal(expectedValue, text[match.Start..match.End]);
    }

    [Theory]
    [InlineData("1234567893")]
    [InlineData("The number is 1234567893")]
    [InlineData("5550109999")]
    [InlineData("Call 555-010-9999 for support")]
    [InlineData("NPI: 1234567890")]
    [InlineData("provider id 1111111111")]
    [InlineData("NPI: 555-010-9999")]
    [InlineData("provider-id 555-010-9999")]
    [InlineData("A123456789")]
    [InlineData("Z987654")]
    [InlineData("ABC12345678")]
    [InlineData("prefixMRN: A123456789")]
    [InlineData("prefixNPI: 1234567893")]
    [InlineData("MRN: characteristics")]
    [InlineData("MRN: ABCDEF_INVALID")]
    [InlineData("MRN: ABCDEF-INVALID")]
    [InlineData("MRN: ABCDEF_more")]
    [InlineData("member_id: misunderstanding")]
    [InlineData("policy_id: misunderstanding")]
    [InlineData("NPI: 1234567893X")]
    [InlineData("medical record: ABCDE")]
    [InlineData("member id: ABC1234")]
    public void Find_RejectsValuesWithoutContextOrWithInvalidOrGluedValues(string text)
    {
        Assert.Empty(HealthcareIdentifierDetector.Find(text));
    }

    [Fact]
    public void Find_ReturnsMultipleMatchesInTextOrder()
    {
        const string text = "Member ID: A1234567; MRN: B12345; NPI: 1234567893";

        var matches = HealthcareIdentifierDetector.Find(text);

        Assert.Equal(3, matches.Count);
        Assert.Equal(
            new[]
            {
                HealthcareIdentifierKind.HealthPlanIdentifier,
                HealthcareIdentifierKind.MedicalRecordNumber,
                HealthcareIdentifierKind.NationalProviderIdentifier
            },
            matches.Select(match => match.Kind));
        Assert.Equal(
            new[] { "A1234567", "B12345", "1234567893" },
            matches.Select(match => text[match.Start..match.End]));
    }
}
