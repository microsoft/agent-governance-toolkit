// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Text.RegularExpressions;

namespace AgentGovernance.Mcp;

/// <summary>
/// Response-layer threat categories.
/// </summary>
public enum McpResponseThreatType
{
    /// <summary>Prompt injection tags (e.g., &lt;system&gt;, HTML comments).</summary>
    PromptInjectionTag,
    /// <summary>Imperative phrasing attempting to override instructions.</summary>
    ImperativePhrasing,
    /// <summary>Credential leakage in response content.</summary>
    CredentialLeakage,
    /// <summary>External URL in a context suggesting data exfiltration.</summary>
    ExfiltrationUrl
}

/// <summary>
/// A single finding from response sanitization.
/// </summary>
public sealed class McpResponseFinding
{
    /// <summary>Category of the response threat.</summary>
    public required McpResponseThreatType ThreatType { get; init; }

    /// <summary>Labels providing detail (e.g., credential kind, pattern name).</summary>
    public required IReadOnlyList<string> Labels { get; init; }
}

/// <summary>
/// Result of scanning and sanitizing MCP response text.
/// </summary>
public sealed class McpSanitizedResponse
{
    /// <summary>The sanitized text with threats neutralized.</summary>
    public required string Sanitized { get; init; }

    /// <summary>Findings detected during sanitization.</summary>
    public required IReadOnlyList<McpResponseFinding> Findings { get; init; }

    /// <summary>Whether the text was modified during sanitization.</summary>
    public bool Modified => Sanitized != _original;

    private readonly string _original;
    internal McpSanitizedResponse(string original) => _original = original;
}

/// <summary>
/// Scans and sanitizes MCP tool output before it reaches an LLM.
/// Detects prompt injection tags, imperative override phrasing,
/// credential leakage, and data exfiltration URLs. Thread-safe.
/// </summary>
public sealed class McpResponseSanitizer
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);

    private static readonly Regex PromptTagPattern = new(
        @"(?is)(<!--.*?-->|<system>.*?</system>|<assistant>.*?</assistant>)",
        RegexOptions.Compiled, RegexTimeout);

    private static readonly Regex ImperativePattern = new(
        @"(?i)(ignore\s+(all\s+)?previous|you\s+must|reveal\s+(all\s+)?secrets|override\s+(the\s+)?instructions?)",
        RegexOptions.Compiled, RegexTimeout);

    private static readonly Regex UrlPattern = new(
        @"https?://[^\s""']+",
        RegexOptions.Compiled, RegexTimeout);

    private static readonly string[] ExfiltrationTerms =
    [
        "send", "upload", "post", "curl", "wget", "exfil"
    ];

    private readonly McpCredentialRedactor _redactor;

    /// <summary>
    /// Creates a new response sanitizer with a default credential redactor.
    /// </summary>
    public McpResponseSanitizer() : this(new McpCredentialRedactor()) { }

    /// <summary>
    /// Creates a new response sanitizer with the specified credential redactor.
    /// </summary>
    public McpResponseSanitizer(McpCredentialRedactor redactor)
    {
        _redactor = redactor ?? throw new ArgumentNullException(nameof(redactor));
    }

    /// <summary>
    /// Scans text for threats and returns a sanitized version.
    /// </summary>
    public McpSanitizedResponse ScanText(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var sanitized = text;
        var findings = new List<McpResponseFinding>();

        // Prompt injection tags
        if (PromptTagPattern.IsMatch(sanitized))
        {
            findings.Add(new McpResponseFinding
            {
                ThreatType = McpResponseThreatType.PromptInjectionTag,
                Labels = ["prompt_tag"]
            });
            sanitized = PromptTagPattern.Replace(sanitized, "[REDACTED_PROMPT_TAG]");
        }

        // Imperative override phrasing
        if (ImperativePattern.IsMatch(sanitized))
        {
            findings.Add(new McpResponseFinding
            {
                ThreatType = McpResponseThreatType.ImperativePhrasing,
                Labels = ["imperative_phrase"]
            });
            sanitized = ImperativePattern.Replace(sanitized, "[REDACTED_INSTRUCTION]");
        }

        // Exfiltration URLs
        var lower = sanitized.ToLowerInvariant();
        if (ExfiltrationTerms.Any(t => lower.Contains(t)) && UrlPattern.IsMatch(sanitized))
        {
            findings.Add(new McpResponseFinding
            {
                ThreatType = McpResponseThreatType.ExfiltrationUrl,
                Labels = ["external_url"]
            });
            sanitized = UrlPattern.Replace(sanitized, "[REDACTED_URL]");
        }

        // Credential leakage
        var redaction = _redactor.Redact(sanitized);
        if (redaction.Modified)
        {
            findings.Add(new McpResponseFinding
            {
                ThreatType = McpResponseThreatType.CredentialLeakage,
                Labels = redaction.Detected.Select(k => k.ToString().ToLowerInvariant()).ToList()
            });
            sanitized = redaction.Sanitized;
        }

        return new McpSanitizedResponse(text)
        {
            Sanitized = sanitized,
            Findings = findings.AsReadOnly()
        };
    }
}
