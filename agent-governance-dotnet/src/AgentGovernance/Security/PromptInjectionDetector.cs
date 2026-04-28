// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace AgentGovernance.Security;

/// <summary>
/// Type of prompt injection attack detected.
/// </summary>
public enum InjectionType
{
    /// <summary>No injection detected.</summary>
    None,

    /// <summary>Direct instruction override ("ignore previous instructions").</summary>
    DirectOverride,

    /// <summary>Delimiter-based injection (attempting to break out of context).</summary>
    DelimiterAttack,

    /// <summary>Encoded payload (base64, hex, rot13 obfuscation).</summary>
    EncodingAttack,

    /// <summary>Role-play manipulation ("you are now a different AI").</summary>
    RolePlay,

    /// <summary>Context manipulation ("the above instructions are wrong").</summary>
    ContextManipulation,

    /// <summary>Canary token leak detection.</summary>
    CanaryLeak,

    /// <summary>Multi-turn escalation pattern.</summary>
    MultiTurnEscalation
}

/// <summary>
/// Threat severity level.
/// </summary>
public enum ThreatLevel
{
    /// <summary>No threat detected.</summary>
    None = 0,
    /// <summary>Minor suspicious pattern, unlikely to be an attack.</summary>
    Low = 1,
    /// <summary>Moderate threat that warrants review.</summary>
    Medium = 2,
    /// <summary>High-confidence injection attempt.</summary>
    High = 3,
    /// <summary>Critical attack pattern requiring immediate blocking.</summary>
    Critical = 4
}

/// <summary>
/// Result of prompt injection detection analysis.
/// </summary>
public sealed class DetectionResult
{
    /// <summary>Whether an injection was detected.</summary>
    public bool IsInjection { get; init; }

    /// <summary>Type of injection detected.</summary>
    public InjectionType InjectionType { get; init; } = InjectionType.None;

    /// <summary>Severity of the detected threat.</summary>
    public ThreatLevel ThreatLevel { get; init; } = ThreatLevel.None;

    /// <summary>Confidence score (0.0–1.0).</summary>
    public double Confidence { get; init; }

    /// <summary>Patterns that matched.</summary>
    public List<string> MatchedPatterns { get; init; } = new();

    /// <summary>Human-readable explanation.</summary>
    public string? Explanation { get; init; }

    /// <summary>SHA-256 hash of the analysed input (for audit without storing raw input).</summary>
    public string? InputHash { get; init; }

    /// <summary>A safe (no-injection) result.</summary>
    public static DetectionResult Safe(string? inputHash = null) => new()
    {
        IsInjection = false,
        ThreatLevel = ThreatLevel.None,
        Confidence = 0,
        InputHash = inputHash
    };
}

/// <summary>
/// Configuration for the prompt injection detector.
/// </summary>
public sealed class DetectionConfig
{
    /// <summary>Sensitivity level: "strict", "balanced", or "permissive".</summary>
    public string Sensitivity { get; init; } = "balanced";

    /// <summary>Additional custom regex patterns to check.</summary>
    public List<string> CustomPatterns { get; init; } = new();

    /// <summary>Exact strings that always trigger detection.</summary>
    public List<string> Blocklist { get; init; } = new();

    /// <summary>Exact strings that are exempt from detection.</summary>
    public List<string> Allowlist { get; init; } = new();

    /// <summary>Canary tokens to detect leaks of.</summary>
    public List<string> CanaryTokens { get; init; } = new();
}

/// <summary>
/// Detects prompt injection attacks in text input using pattern matching,
/// encoding detection, and canary token monitoring. Fail-closed: any detection
/// error is treated as a high-threat injection.
/// </summary>
public sealed class PromptInjectionDetector
{
    private readonly DetectionConfig _config;
    private readonly List<(Regex Pattern, InjectionType Type, ThreatLevel Threat, string Name)> _patterns;

    /// <summary>
    /// Initializes a new detector with optional configuration.
    /// </summary>
    public PromptInjectionDetector(DetectionConfig? config = null)
    {
        _config = config ?? new DetectionConfig();
        _patterns = BuildPatterns();
    }

    /// <summary>
    /// Analyses text for prompt injection attacks.
    /// </summary>
    /// <param name="input">The text to analyse.</param>
    /// <returns>A <see cref="DetectionResult"/> with the findings.</returns>
    public DetectionResult Detect(string input)
    {
        if (string.IsNullOrEmpty(input))
            return DetectionResult.Safe();

        var inputHash = ComputeHash(input);

        try
        {
            // Allowlist check.
            if (_config.Allowlist.Any(a =>
                input.Contains(a, StringComparison.OrdinalIgnoreCase)))
            {
                return DetectionResult.Safe(inputHash);
            }

            // Blocklist check.
            var blockedMatch = _config.Blocklist.FirstOrDefault(b =>
                input.Contains(b, StringComparison.OrdinalIgnoreCase));
            if (blockedMatch is not null)
            {
                return new DetectionResult
                {
                    IsInjection = true,
                    InjectionType = InjectionType.DirectOverride,
                    ThreatLevel = ThreatLevel.Critical,
                    Confidence = 1.0,
                    MatchedPatterns = { blockedMatch },
                    Explanation = $"Blocked content detected: '{blockedMatch}'.",
                    InputHash = inputHash
                };
            }

            var matches = new List<string>();
            var highestThreat = ThreatLevel.None;
            var detectedType = InjectionType.None;

            // Pattern matching.
            foreach (var (pattern, type, threat, name) in _patterns)
            {
                if (pattern.IsMatch(input))
                {
                    matches.Add(name);
                    if (threat > highestThreat)
                    {
                        highestThreat = threat;
                        detectedType = type;
                    }
                }
            }

            // Encoding detection (base64 payloads).
            var encodingResult = DetectEncodedPayloads(input);
            if (encodingResult is not null)
            {
                matches.Add(encodingResult.Value.Name);
                if (encodingResult.Value.Threat > highestThreat)
                {
                    highestThreat = encodingResult.Value.Threat;
                    detectedType = InjectionType.EncodingAttack;
                }
            }

            // Canary token detection.
            foreach (var canary in _config.CanaryTokens)
            {
                if (input.Contains(canary, StringComparison.OrdinalIgnoreCase))
                {
                    matches.Add($"canary:{canary[..Math.Min(8, canary.Length)]}...");
                    highestThreat = ThreatLevel.Critical;
                    detectedType = InjectionType.CanaryLeak;
                }
            }

            // Apply sensitivity filter.
            var minThreat = _config.Sensitivity.ToLowerInvariant() switch
            {
                "strict" => ThreatLevel.Low,
                "balanced" => ThreatLevel.Medium,
                "permissive" => ThreatLevel.High,
                _ => ThreatLevel.Medium
            };

            if (matches.Count == 0 || highestThreat < minThreat)
            {
                return DetectionResult.Safe(inputHash);
            }

            return new DetectionResult
            {
                IsInjection = true,
                InjectionType = detectedType,
                ThreatLevel = highestThreat,
                Confidence = Math.Min(1.0, matches.Count * 0.3 + 0.4),
                MatchedPatterns = matches,
                Explanation = $"Detected {detectedType}: {string.Join(", ", matches)}.",
                InputHash = inputHash
            };
        }
        catch (Exception)
        {
            // Fail-closed: treat errors as potential injection.
            return new DetectionResult
            {
                IsInjection = true,
                InjectionType = InjectionType.None,
                ThreatLevel = ThreatLevel.High,
                Confidence = 0.5,
                Explanation = "Detection error — fail-closed.",
                InputHash = inputHash
            };
        }
    }

    /// <summary>
    /// Analyses multiple inputs and returns results for each.
    /// </summary>
    public IReadOnlyList<DetectionResult> DetectBatch(IEnumerable<string> inputs)
    {
        return inputs.Select(Detect).ToList().AsReadOnly();
    }

    private static readonly int MaxCustomPatternLength = 1000;
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);
    private static readonly Regex Base64Pattern = new(@"[A-Za-z0-9+/]{20,}={0,2}", RegexOptions.Compiled, TimeSpan.FromMilliseconds(200));

    private (string Name, ThreatLevel Threat)? DetectEncodedPayloads(string input)
    {
        // Look for base64-encoded strings (at least 20 chars).
        var b64Matches = Base64Pattern.Matches(input);

        foreach (Match match in b64Matches)
        {
            try
            {
                var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(match.Value));
                var suspicious = new[] { "ignore", "override", "system prompt", "you are", "forget" };
                if (suspicious.Any(s => decoded.Contains(s, StringComparison.OrdinalIgnoreCase)))
                {
                    return ("base64_encoded_injection", ThreatLevel.High);
                }
            }
            catch
            {
                // Not valid base64 — skip.
            }
        }

        return null;
    }

    private List<(Regex, InjectionType, ThreatLevel, string)> BuildPatterns()
    {
        var patterns = new List<(Regex, InjectionType, ThreatLevel, string)>
        {
            // Direct override patterns.
            (Compile(@"ignore\s+(all\s+)?previous\s+instructions"), InjectionType.DirectOverride, ThreatLevel.Critical, "ignore_previous"),
            (Compile(@"ignore\s+(all\s+)?prior\s+(instructions|context|rules)"), InjectionType.DirectOverride, ThreatLevel.Critical, "ignore_prior"),
            (Compile(@"disregard\s+(all\s+)?(previous|above|prior)"), InjectionType.DirectOverride, ThreatLevel.Critical, "disregard"),
            (Compile(@"forget\s+(everything|all|your)\s*(instructions|rules|constraints)?"), InjectionType.DirectOverride, ThreatLevel.Critical, "forget_instructions"),
            (Compile(@"new\s+system\s+prompt"), InjectionType.DirectOverride, ThreatLevel.Critical, "new_system_prompt"),
            (Compile(@"override\s+(your\s+)?(instructions|rules|constraints)"), InjectionType.DirectOverride, ThreatLevel.Critical, "override_instructions"),

            // Delimiter attacks.
            (Compile(@"<\|?(system|endoftext|im_start|im_end)\|?>"), InjectionType.DelimiterAttack, ThreatLevel.High, "delimiter_tags"),
            (Compile(@"\[INST\]|\[/INST\]|\[SYS\]"), InjectionType.DelimiterAttack, ThreatLevel.High, "instruction_tags"),
            (Compile(@"###\s*(SYSTEM|INSTRUCTION|HUMAN|ASSISTANT)"), InjectionType.DelimiterAttack, ThreatLevel.High, "markdown_delimiters"),

            // Role-play manipulation.
            (Compile(@"you\s+are\s+now\s+(a|an|the)"), InjectionType.RolePlay, ThreatLevel.High, "role_reassignment"),
            (Compile(@"pretend\s+(you\s+are|to\s+be)"), InjectionType.RolePlay, ThreatLevel.Medium, "pretend"),
            (Compile(@"act\s+as\s+(if|a|an|the)"), InjectionType.RolePlay, ThreatLevel.Medium, "act_as"),
            (Compile(@"jailbreak|DAN\s*mode|developer\s*mode"), InjectionType.RolePlay, ThreatLevel.Critical, "jailbreak"),

            // Context manipulation.
            (Compile(@"the\s+(above|previous)\s+(instructions?|text|context)\s+(is|are|was|were)\s+(wrong|incorrect|fake|test)"), InjectionType.ContextManipulation, ThreatLevel.High, "context_invalidation"),
            (Compile(@"actually[,.]?\s*(the\s+real|your\s+true|your\s+actual)\s+instructions?"), InjectionType.ContextManipulation, ThreatLevel.High, "actual_instructions"),

            // SQL / code injection via prompts.
            (Compile(@";\s*DROP\s+TABLE", RegexOptions.IgnoreCase), InjectionType.DirectOverride, ThreatLevel.Critical, "sql_injection"),
            (Compile(@"UNION\s+SELECT", RegexOptions.IgnoreCase), InjectionType.DirectOverride, ThreatLevel.High, "sql_union"),
        };

        // Add custom patterns with length and timeout guards.
        foreach (var custom in _config.CustomPatterns)
        {
            if (custom.Length > MaxCustomPatternLength)
                continue;

            try
            {
                patterns.Add((Compile(custom), InjectionType.DirectOverride, ThreatLevel.High, $"custom:{custom[..Math.Min(20, custom.Length)]}"));
            }
            catch
            {
                // Invalid regex — skip.
            }
        }

        return patterns;
    }

    private static Regex Compile(string pattern, RegexOptions extra = RegexOptions.None)
    {
        return new Regex(pattern, RegexOptions.Compiled | RegexOptions.IgnoreCase | extra, RegexTimeout);
    }

    private static string ComputeHash(string input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
