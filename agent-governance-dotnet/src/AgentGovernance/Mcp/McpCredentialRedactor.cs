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
    SecretAssignment,
    /// <summary>GitHub access token.</summary>
    GitHubToken,
    /// <summary>OpenAI API token.</summary>
    OpenAiToken,
    /// <summary>Slack access token.</summary>
    SlackToken,
    /// <summary>AWS access key identifier.</summary>
    AwsAccessKey,
    /// <summary>Google API key.</summary>
    GoogleApiKey,
    /// <summary>RFC 7468 PEM private key block.</summary>
    PemPrivateKey
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
         "[REDACTED_SECRET]"),

        // These five patterns use a lookaround with an explicit excluded-character
        // set rather than \b, so a secret glued directly to a preceding or
        // following word character (e.g. "session_ghp_..." or "AKIA..._old") is
        // still detected. \b treats "_" as a word character, so it finds no
        // boundary next to one; a plain \b also cannot express the asymmetry a
        // fixed-length or "_"-excluding value class needs (AwsAccessKey and
        // GitHubToken's gh[psour]_ alternative have no shorter match to fall back
        // to when the boundary check fails, so the whole pattern would fail
        // rather than match a truncated token).
        //
        // The excluded set on the left is [A-Za-z0-9] everywhere below: any
        // character that is not part of the value's own class is a valid left
        // separator, never a reason to reject the match. OpenAiToken's right
        // side is left as-is (still excludes "_"/"-" too): its value class is
        // variable-length and already includes both characters, so a glued
        // suffix is absorbed into the match regardless of what the trailing
        // lookahead excludes, and narrowing it here is not needed to fix this
        // bug. GitHubToken, AwsAccessKey and GoogleApiKey do not have that
        // variable-length class to fall back on, so their right side is fixed
        // the same way as their left.
        (CredentialKind.GitHubToken,
         new Regex(@"(?<![A-Za-z0-9])(?:gh[psour]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{22,})(?![A-Za-z0-9])", RegexOptions.Compiled, RegexTimeout),
         "[REDACTED_GITHUB_TOKEN]"),

        (CredentialKind.OpenAiToken,
         new Regex(@"(?<![A-Za-z0-9])sk-[A-Za-z0-9][A-Za-z0-9_-]{18,}(?![A-Za-z0-9_-])", RegexOptions.Compiled, RegexTimeout),
         "[REDACTED_OPENAI_TOKEN]"),

        (CredentialKind.SlackToken,
         new Regex(@"(?<![A-Za-z0-9-])xox[abprs]-[A-Za-z0-9-]+(?![A-Za-z0-9-])", RegexOptions.Compiled, RegexTimeout),
         "[REDACTED_SLACK_TOKEN]"),

        (CredentialKind.AwsAccessKey,
         new Regex(@"(?<![A-Za-z0-9])AKIA[A-Z0-9]{16}(?![A-Za-z0-9])", RegexOptions.Compiled, RegexTimeout),
         "[REDACTED_AWS_ACCESS_KEY]"),

        // Value class includes "-"/"_", and the count is fixed at 35, so a real
        // key can land on either right where the 35th character happens to be
        // one of them. When that happens and an unrelated alphanumeric
        // character follows with no separator (for example a 35 char run
        // ending in "-" glued straight to more text), this pattern treats that
        // the same as any other "one more alphanumeric character" case and
        // does not redact it, on the same reasoning as AwsAccessKey: the
        // presence of more alphanumeric content right there is evidence this
        // is not a cleanly isolated key. That is a real, if narrow, gap
        // compared to the previous plain \b, which treated "-" as an automatic
        // boundary on its own. Pinned deliberately by
        // Redact_DoesNotWidenGoogleApiKeyMatch_WhenKeyEndsInHyphen below rather
        // than left as an unexamined side effect.
        (CredentialKind.GoogleApiKey,
         new Regex(@"(?<![A-Za-z0-9])AIza[0-9A-Za-z\-_]{35}(?![A-Za-z0-9])", RegexOptions.Compiled, RegexTimeout),
         "[REDACTED_GOOGLE_API_KEY]"),

        (CredentialKind.PemPrivateKey,
         new Regex(@"-----BEGIN (?<label>(?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY)-----(?:\r?\n[!-~ \t]*)*?\r?\n-----END \k<label>-----", RegexOptions.Compiled, RegexTimeout),
         "[REDACTED_PEM_PRIVATE_KEY]")
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
        CredentialKind.GitHubToken => "[REDACTED_GITHUB_TOKEN]",
        CredentialKind.OpenAiToken => "[REDACTED_OPENAI_TOKEN]",
        CredentialKind.SlackToken => "[REDACTED_SLACK_TOKEN]",
        CredentialKind.AwsAccessKey => "[REDACTED_AWS_ACCESS_KEY]",
        CredentialKind.GoogleApiKey => "[REDACTED_GOOGLE_API_KEY]",
        CredentialKind.PemPrivateKey => "[REDACTED_PEM_PRIVATE_KEY]",
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
