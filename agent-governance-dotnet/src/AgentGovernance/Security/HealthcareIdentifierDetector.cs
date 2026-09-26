// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.RegularExpressions;

namespace AgentGovernance.Security;

/// <summary>Category of a detected healthcare identifier.</summary>
public enum HealthcareIdentifierKind
{
    /// <summary>A context-labeled medical record number.</summary>
    MedicalRecordNumber,
    /// <summary>A provider NPI, which is not inherently PHI.</summary>
    NationalProviderIdentifier,
    /// <summary>A health-plan, member, or policy identifier.</summary>
    HealthPlanIdentifier
}

/// <summary>A healthcare identifier's half-open range in the scanned text.</summary>
/// <param name="Kind">The kind of identifier detected.</param>
/// <param name="Start">The inclusive UTF-16 index of the identifier value.</param>
/// <param name="End">The exclusive UTF-16 index of the identifier value.</param>
public sealed record HealthcareIdentifierMatch(
    HealthcareIdentifierKind Kind,
    int Start,
    int End);

/// <summary>
/// Finds context-labeled MRNs, NPIs, and health-plan/member/policy identifiers.
/// This detector does not classify or redact data.
/// </summary>
public static class HealthcareIdentifierDetector
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);
    private const RegexOptions PatternOptions =
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase;

    private static readonly Pattern[] Patterns =
    [
        new(
            HealthcareIdentifierKind.MedicalRecordNumber,
            new Regex(
                @"(^|[^A-Za-z0-9])(?:mrn|medical[ \t\r\n_-]*record)[ \t\r\n_#:-]*(?<identifier>[A-Za-z0-9]{6,12})",
                PatternOptions,
                RegexTimeout)),
        new(
            HealthcareIdentifierKind.NationalProviderIdentifier,
            new Regex(
                @"(^|[^A-Za-z0-9])(?:npi|provider[ \t\r\n_-]*id)[ \t\r\n_#:-]*(?<identifier>[0-9]{10})",
                PatternOptions,
                RegexTimeout)),
        new(
            HealthcareIdentifierKind.HealthPlanIdentifier,
            new Regex(
                @"(^|[^A-Za-z0-9])(?:hpid|health[ \t\r\n_-]*plan[ \t\r\n_-]*id|member[ \t\r\n_-]*id|policy[ \t\r\n_-]*id)[ \t\r\n_#:-]*(?<identifier>[A-Za-z0-9]{8,15})",
                PatternOptions,
                RegexTimeout))
    ];

    /// <summary>
    /// Finds context-labeled identifiers and returns ranges covering only the
    /// identifier values, ordered by their position in <paramref name="text"/>.
    /// </summary>
    /// <remarks>
    /// MRNs are limited to 6-12 ASCII letters or digits, health-plan identifiers
    /// to 8-15, and NPIs to exactly 10 ASCII digits with a valid 80840-prefixed
    /// Luhn check digit. This method does not verify that an NPI was issued,
    /// classify data, redact values, or establish HIPAA/SOC 2 compliance. NPIs
    /// identify providers and are not inherently PHI.
    /// </remarks>
    /// <param name="text">The text to scan.</param>
    /// <returns>Identifier kinds and half-open UTF-16 ranges.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="text"/> is null.</exception>
    public static IReadOnlyList<HealthcareIdentifierMatch> Find(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var matches = new List<HealthcareIdentifierMatch>();
        foreach (var pattern in Patterns)
        {
            foreach (Match candidate in pattern.Expression.Matches(text))
            {
                var identifier = candidate.Groups["identifier"];
                if (!identifier.Success)
                {
                    continue;
                }

                var end = identifier.Index + identifier.Length;
                if (end < text.Length && IsIdentifierContinuation(text[end]))
                {
                    continue;
                }
                if (pattern.Kind == HealthcareIdentifierKind.NationalProviderIdentifier &&
                    !IsValidNpi(identifier.Value))
                {
                    continue;
                }

                matches.Add(new HealthcareIdentifierMatch(pattern.Kind, identifier.Index, end));
            }
        }

        matches.Sort(static (left, right) =>
        {
            var startOrder = left.Start.CompareTo(right.Start);
            if (startOrder != 0)
            {
                return startOrder;
            }

            var endOrder = left.End.CompareTo(right.End);
            return endOrder != 0 ? endOrder : left.Kind.CompareTo(right.Kind);
        });
        return matches.AsReadOnly();
    }

    private static bool IsIdentifierContinuation(char value) =>
        value is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '_' or '-';

    private static bool IsValidNpi(string npi)
    {
        if (npi.Length != 10 || npi.Any(character => character is < '0' or > '9'))
        {
            return false;
        }

        var prefixedNpi = string.Concat("80840", npi);
        var checksum = 0;
        var doubleDigit = false;
        for (var index = prefixedNpi.Length - 1; index >= 0; index--)
        {
            var digit = prefixedNpi[index] - '0';
            if (doubleDigit)
            {
                digit *= 2;
                if (digit > 9)
                {
                    digit -= 9;
                }
            }
            checksum += digit;
            doubleDigit = !doubleDigit;
        }
        return checksum % 10 == 0;
    }

    private sealed record Pattern(HealthcareIdentifierKind Kind, Regex Expression);
}
