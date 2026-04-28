// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Text.RegularExpressions;

namespace AgentGovernance.Mcp;

/// <summary>
/// Categorical credential types that may be redacted.
/// </summary>
public enum CredentialKind
{
    /// <summary>API key pattern (e.g., api_key=..., x-api-key: ...).</summary>
    ApiKey,
    /// <summary>Bearer token (e.g., Authorization: Bearer ...).</summary>
    BearerToken,
    /// <summary>Connection string with password or shared access key.</summary>
    ConnectionString,
    /// <summary>Generic secret assignment (password=, secret=, token=).</summary>
    SecretAssignment
}

/// <summary>
/// Result of credential redaction.
/// </summary>
public sealed class RedactionResult
{
    /// <summary>The sanitized text with credentials replaced by placeholders.</summary>
    public required string Sanitized { get; init; }

    /// <summary>Credential types that were detected and redacted.</summary>
    public required IReadOnlyList<CredentialKind> Detected { get; init; }

    /// <summary>Whether any credentials were redacted.</summary>
    public bool Modified => Detected.Count > 0;
}

/// <summary>
/// Redacts credentials from text and structured data.
/// Detects API keys, bearer tokens, connection strings, and generic secret assignments.
/// Thread-safe.
/// </summary>
public sealed class McpCredentialRedactor
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);

    private static readonly (CredentialKind Kind, Regex Pattern, string Placeholder)[] Patterns =
    [
        (CredentialKind.BearerToken,
         new Regex(@"(?i)\bbearer\s+[a-z0-9._~+/=-]{8,}", RegexOptions.Compiled, RegexTimeout),
         "[REDACTED_BEARER_TOKEN]"),

        (CredentialKind.ApiKey,
         new Regex(@"(?i)(?:api[_\-]?key|x-api-key)\s*[:=]\s*[""']?[a-z0-9_\-]{8,}[""']?", RegexOptions.Compiled, RegexTimeout),
         "[REDACTED_API_KEY]"),

        (CredentialKind.ConnectionString,
         new Regex(@"(?i)\b(?:server|host|endpoint)=[^;]+;[^;\n]*(?:password|sharedaccesskey)=[^;\n]+", RegexOptions.Compiled, RegexTimeout),
         "[REDACTED_CONNECTION_STRING]"),

        (CredentialKind.SecretAssignment,
         new Regex(@"(?i)\b(?:password|secret|token)\s*[:=]\s*[""']?[^\s""';,]{4,}[""']?", RegexOptions.Compiled, RegexTimeout),
         "[REDACTED_SECRET]")
    ];

    private static readonly Dictionary<string, CredentialKind> KeyHints = new(StringComparer.OrdinalIgnoreCase)
    {
        ["authorization"] = CredentialKind.BearerToken,
        ["bearer"] = CredentialKind.BearerToken,
        ["api_key"] = CredentialKind.ApiKey,
        ["apikey"] = CredentialKind.ApiKey,
        ["x-api-key"] = CredentialKind.ApiKey,
        ["token"] = CredentialKind.SecretAssignment,
        ["secret"] = CredentialKind.SecretAssignment,
        ["password"] = CredentialKind.SecretAssignment,
        ["credential"] = CredentialKind.SecretAssignment,
        ["connection_string"] = CredentialKind.ConnectionString,
        ["connectionstring"] = CredentialKind.ConnectionString
    };

    /// <summary>
    /// Redacts credentials from a text string.
    /// </summary>
    public RedactionResult Redact(string input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var sanitized = input;
        var detected = new List<CredentialKind>();

        foreach (var (kind, pattern, placeholder) in Patterns)
        {
            if (pattern.IsMatch(sanitized))
            {
                if (!detected.Contains(kind))
                    detected.Add(kind);
                sanitized = pattern.Replace(sanitized, placeholder);
            }
        }

        return new RedactionResult
        {
            Sanitized = sanitized,
            Detected = detected.AsReadOnly()
        };
    }

    /// <summary>
    /// Returns the placeholder string for a credential kind.
    /// </summary>
    public static string PlaceholderFor(CredentialKind kind) => kind switch
    {
        CredentialKind.ApiKey => "[REDACTED_API_KEY]",
        CredentialKind.BearerToken => "[REDACTED_BEARER_TOKEN]",
        CredentialKind.ConnectionString => "[REDACTED_CONNECTION_STRING]",
        CredentialKind.SecretAssignment => "[REDACTED_SECRET]",
        _ => "[REDACTED]"
    };

    /// <summary>
    /// Infers a credential kind from a dictionary key name (e.g., "x-api-key" → ApiKey).
    /// Returns null if the key doesn't match any known credential pattern.
    /// </summary>
    public static CredentialKind? InferKindFromKey(string key)
    {
        if (string.IsNullOrEmpty(key)) return null;
        var lower = key.ToLowerInvariant();
        foreach (var (hint, kind) in KeyHints)
        {
            if (lower.Contains(hint))
                return kind;
        }
        return null;
    }
}
