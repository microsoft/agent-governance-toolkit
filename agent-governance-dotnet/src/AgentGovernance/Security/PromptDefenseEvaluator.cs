// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace AgentGovernance.Security;

/// <summary>
/// Coverage result for a single prompt-defense vector.
/// </summary>
public sealed class PromptDefenseVectorResult
{
    /// <summary>
    /// Stable identifier for the evaluated defense vector.
    /// </summary>
    public required string VectorId { get; init; }

    /// <summary>
    /// Human-readable vector name.
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// OWASP mapping for the vector.
    /// </summary>
    public required string OwaspCategory { get; init; }

    /// <summary>
    /// Whether the prompt contains enough evidence for this defense vector.
    /// </summary>
    public bool Covered { get; init; }

    /// <summary>
    /// Number of regex matches found for this vector.
    /// </summary>
    public int MatchCount { get; init; }
}

/// <summary>
/// Deterministic coverage report for a system prompt.
/// </summary>
public sealed class PromptDefenseReport
{
    /// <summary>
    /// Prompt SHA-256 hash for audit-safe tracking.
    /// </summary>
    public required string PromptHash { get; init; }

    /// <summary>
    /// Numeric score from 0-100.
    /// </summary>
    public int Score { get; init; }

    /// <summary>
    /// Letter grade derived from <see cref="Score"/>.
    /// </summary>
    public required string Grade { get; init; }

    /// <summary>
    /// Whether the prompt meets the recommended passing threshold.
    /// </summary>
    public bool Passes { get; init; }

    /// <summary>
    /// Total number of defense vectors assessed.
    /// </summary>
    public int VectorCount { get; init; }

    /// <summary>
    /// Number of covered vectors.
    /// </summary>
    public int CoveredCount { get; init; }

    /// <summary>
    /// Covered vector identifiers.
    /// </summary>
    public IReadOnlyList<string> CoveredVectors { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Missing vector identifiers.
    /// </summary>
    public IReadOnlyList<string> MissingVectors { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Per-vector coverage details.
    /// </summary>
    public IReadOnlyList<PromptDefenseVectorResult> Results { get; init; } = Array.Empty<PromptDefenseVectorResult>();

    /// <summary>
    /// UTC timestamp when the prompt was evaluated.
    /// </summary>
    public DateTime EvaluatedAt { get; init; } = DateTime.UtcNow;
}

/// <summary>
/// Deterministic evaluator for pre-deployment system-prompt defenses.
/// </summary>
public sealed class PromptDefenseEvaluator
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);

    private static readonly IReadOnlyList<PromptDefenseRule> Rules =
    [
        new(
            "role-escape",
            "Role Boundary",
            "LLM01",
            [
                BuildRegex(@"(?:you are|your role|act as|serve as|function as|assistant (?:named|called|is))"),
                BuildRegex(@"(?:never (?:break|change|switch|abandon)|stay in (?:character|role)|maintain.*(?:role|identity|persona))")
            ]),
        new(
            "instruction-override",
            "Instruction Boundary",
            "LLM01",
            [
                BuildRegex(@"(?:do not|never|must not|cannot|should not|refuse|reject|decline)"),
                BuildRegex(@"(?:ignore (?:any|all|prior|previous)|disregard|override)")
            ]),
        new(
            "data-leakage",
            "Data Protection",
            "LLM07",
            [
                BuildRegex(@"(?:do not (?:reveal|share|disclose|expose|output)|never (?:reveal|share|disclose|show)|keep.*(?:secret|confidential|private))"),
                BuildRegex(@"(?:system prompt|internal|instruction|training|behind the scenes)")
            ]),
        new(
            "output-manipulation",
            "Output Control",
            "LLM02",
            [
                BuildRegex(@"(?:only (?:respond|reply|output|answer) (?:in|with|as)|format.*(?:as|in|using)|response (?:format|style))"),
                BuildRegex(@"(?:do not (?:generate|create|produce|output)|never (?:generate|produce))")
            ]),
        new(
            "multilang-bypass",
            "Multi-language Protection",
            "LLM01",
            [
                BuildRegex(@"(?:only (?:respond|reply|answer|communicate) in|respond in (?:english|french|spanish|japanese)|language)"),
                BuildRegex(@"(?:regardless of (?:the )?(?:input|user) language)")
            ]),
        new(
            "unicode-attack",
            "Unicode Protection",
            "LLM01",
            [
                BuildRegex(@"(?:unicode|homoglyph|special character|character encoding)")
            ]),
        new(
            "context-overflow",
            "Length Limits",
            "LLM01",
            [
                BuildRegex(@"(?:max(?:imum)?.*(?:length|char|token|word)|limit.*(?:input|length|size|token)|truncat)")
            ]),
        new(
            "indirect-injection",
            "Indirect Injection Protection",
            "LLM01",
            [
                BuildRegex(@"(?:external (?:data|content|source|input)|user.?(?:provided|supplied|submitted|generated)|third.?party|untrusted)"),
                BuildRegex(@"(?:(?:validate|verify|sanitize|filter|check).*(?:external|input|data|content)|treat.*(?:as (?:data|untrusted|information))|do not (?:follow|execute|obey).*(?:instruction|command).*(?:from|in|within|embedded))")
            ]),
        new(
            "social-engineering",
            "Social Engineering Defense",
            "LLM01",
            [
                BuildRegex(@"(?:emotional|urgency|pressure|threaten|guilt|manipulat)"),
                BuildRegex(@"(?:regardless of|no matter|even if)")
            ]),
        new(
            "output-weaponization",
            "Harmful Content Prevention",
            "LLM02",
            [
                BuildRegex(@"(?:harmful|illegal|dangerous|malicious|weapon|violence|exploit|phishing)"),
                BuildRegex(@"(?:do not (?:help|assist|generate|create).*(?:harm|illegal|danger|weapon))")
            ]),
        new(
            "abuse-prevention",
            "Abuse Prevention",
            "LLM06",
            [
                BuildRegex(@"(?:abuse|misuse|exploit|attack|inappropriate|spam|flood)"),
                BuildRegex(@"(?:rate limit|throttl|quota|maximum.*request)"),
                BuildRegex(@"(?:authenticat|authoriz|permission|access control|api.?key|token)")
            ]),
        new(
            "input-validation",
            "Input Validation",
            "LLM01",
            [
                BuildRegex(@"(?:validate|sanitize|filter|clean|escape|strip|check.*input|input.*(?:validation|check))"),
                BuildRegex(@"(?:sql|xss|injection|script|html|special char|malicious)")
            ])
    ];

    /// <summary>
    /// Evaluate a single prompt for defense coverage.
    /// </summary>
    public PromptDefenseReport Evaluate(string prompt)
    {
        ArgumentNullException.ThrowIfNull(prompt);

        var results = new List<PromptDefenseVectorResult>(Rules.Count);

        foreach (var rule in Rules)
        {
            var matchCount = rule.Patterns.Count(pattern => pattern.IsMatch(prompt));
            results.Add(new PromptDefenseVectorResult
            {
                VectorId = rule.VectorId,
                Name = rule.Name,
                OwaspCategory = rule.OwaspCategory,
                Covered = matchCount >= rule.MinMatches,
                MatchCount = matchCount
            });
        }

        var covered = results.Where(result => result.Covered).Select(result => result.VectorId).ToArray();
        var missing = results.Where(result => !result.Covered).Select(result => result.VectorId).ToArray();
        var score = (int)Math.Round(results.Count == 0 ? 0 : covered.Length * 100.0 / results.Count, MidpointRounding.AwayFromZero);

        return new PromptDefenseReport
        {
            PromptHash = ComputeHash(prompt),
            Score = score,
            Grade = ScoreToGrade(score),
            Passes = score >= 70,
            VectorCount = results.Count,
            CoveredCount = covered.Length,
            CoveredVectors = covered,
            MissingVectors = missing,
            Results = results,
            EvaluatedAt = DateTime.UtcNow
        };
    }

    /// <summary>
    /// Evaluate multiple prompts.
    /// </summary>
    public IReadOnlyList<PromptDefenseReport> EvaluateBatch(IEnumerable<string> prompts)
    {
        ArgumentNullException.ThrowIfNull(prompts);
        return prompts.Select(Evaluate).ToArray();
    }

    /// <summary>
    /// Evaluate prompt content loaded from disk.
    /// </summary>
    public PromptDefenseReport EvaluateFile(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return Evaluate(File.ReadAllText(path, Encoding.UTF8));
    }

    private static Regex BuildRegex(string pattern) =>
        new(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);

    private static string ComputeHash(string value)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string ScoreToGrade(int score) => score switch
    {
        >= 90 => "A",
        >= 70 => "B",
        >= 50 => "C",
        >= 30 => "D",
        _ => "F"
    };

    private sealed record PromptDefenseRule(
        string VectorId,
        string Name,
        string OwaspCategory,
        IReadOnlyList<Regex> Patterns,
        int MinMatches = 1);
}
