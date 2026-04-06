// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace AgentGovernance.Mcp;

/// <summary>
/// Redacts credentials, API keys, and secrets from strings before they are written to audit logs.
/// Implements OWASP MCP Security Cheat Sheet §10: "Redact secrets and PII from logs."
/// <para>
/// Detects common credential patterns (OpenAI keys, GitHub PATs, AWS access keys, Bearer tokens,
/// private keys, connection strings) and replaces them with <c>[REDACTED]</c>.
/// </para>
/// </summary>
public static class CredentialRedactor
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);
    private static readonly string[] SensitiveKeyTokens =
    {
        "apikey",
        "accesstoken",
        "refreshtoken",
        "bearertoken",
        "authtoken",
        "accesskey",
        "secretkey",
        "clientsecret",
        "privatekey",
        "connectionstring",
        "password",
        "credential",
        "token",
        "secret",
    };

    /// <summary>Replacement string for redacted values.</summary>
    public const string RedactedPlaceholder = "[REDACTED]";

    /// <summary>
    /// Optional logger for recording redaction events.
    /// When <c>null</c>, no logging occurs — the redactor operates silently.
    /// </summary>
    public static ILogger? Logger { get; set; }

    // ── Credential patterns ──

    /// <summary>OpenAI API keys (sk-live_xxx, sk-test_xxx, sk-proj-xxx).</summary>
    public static readonly Regex OpenAiKeyPattern =
        new(@"sk[-_](live|test|proj)[-_]\w{20,}", RegexOptions.Compiled, RegexTimeout);

    /// <summary>GitHub personal access tokens.</summary>
    public static readonly Regex GitHubPatPattern =
        new(@"ghp_[A-Za-z0-9]{36,}", RegexOptions.Compiled, RegexTimeout);

    /// <summary>GitHub fine-grained tokens.</summary>
    public static readonly Regex GitHubFineGrainedPattern =
        new(@"github_pat_[A-Za-z0-9_]{20,}", RegexOptions.Compiled, RegexTimeout);

    /// <summary>AWS access key IDs.</summary>
    public static readonly Regex AwsAccessKeyPattern =
        new(@"AKIA[A-Z0-9]{16}", RegexOptions.Compiled, RegexTimeout);

    /// <summary>Bearer tokens in authorization headers.</summary>
    public static readonly Regex BearerTokenPattern =
        new(@"Bearer\s+[A-Za-z0-9._\-]{20,}", RegexOptions.Compiled, RegexTimeout);

    /// <summary>PEM-encoded private keys.</summary>
    public static readonly Regex PrivateKeyPattern =
        new(@"-----BEGIN(?:\s+[A-Z0-9]+)*\s+PRIVATE\s+KEY-----[\s\S]*?-----END(?:\s+[A-Z0-9]+)*\s+PRIVATE\s+KEY-----",
            RegexOptions.Compiled | RegexOptions.Singleline,
            RegexTimeout);

    /// <summary>Azure/SQL connection strings with password.</summary>
    public static readonly Regex ConnectionStringPattern =
        new(@"(Password|pwd)\s*=\s*[^;]{4,}", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout);

    /// <summary>Generic high-entropy secrets (hex strings 40+ chars, likely tokens).</summary>
    public static readonly Regex GenericSecretPattern =
        new(@"\b[0-9a-fA-F]{40,}\b", RegexOptions.Compiled, RegexTimeout);

    /// <summary>Azure Storage account keys.</summary>
    public static readonly Regex AzureStorageKeyPattern =
        new(@"AccountKey\s*=\s*[A-Za-z0-9+/]{43,}={0,2}", RegexOptions.Compiled, RegexTimeout);

    /// <summary>Database URIs with embedded credentials (postgres, mongodb, redis, mysql, amqp).</summary>
    public static readonly Regex DatabaseUriPattern =
        new(@"(postgresql|postgres|mongodb(\+srv)?|redis|mysql|amqp)://[^:]+:[^@]+@", RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout);

    /// <summary>
    /// All credential patterns with human-readable names for diagnostics.
    /// </summary>
    public static IReadOnlyList<(Regex Pattern, string Name)> AllPatterns { get; } = new List<(Regex, string)>
    {
        (OpenAiKeyPattern, "OpenAI API key"),
        (GitHubPatPattern, "GitHub PAT"),
        (GitHubFineGrainedPattern, "GitHub fine-grained token"),
        (AwsAccessKeyPattern, "AWS access key"),
        (BearerTokenPattern, "Bearer token"),
        (PrivateKeyPattern, "Private key"),
        (ConnectionStringPattern, "Connection string password"),
        (AzureStorageKeyPattern, "Azure Storage key"),
        (DatabaseUriPattern, "Database URI credentials"),
        (GenericSecretPattern, "Generic secret"),
    };

    /// <summary>
    /// Redacts all detected credentials in the input string, replacing them with <c>[REDACTED]</c>.
    /// Returns the original string unchanged if no credentials are found.
    /// </summary>
    /// <param name="input">The string to redact credentials from.</param>
    /// <returns>The redacted string.</returns>
    public static string Redact(string? input)
    {
        if (string.IsNullOrEmpty(input))
            return input ?? string.Empty;

        var result = input;
        int count = 0;
        foreach (var (pattern, _) in AllPatterns)
        {
            try
            {
                var before = result;
                result = pattern.Replace(result, RedactedPlaceholder);
                if (!ReferenceEquals(before, result))
                    count++;
            }
            catch (RegexMatchTimeoutException ex)
            {
                Logger?.LogWarning(ex, "MCP credential redaction timed out; redacting entire value");
                return RedactedPlaceholder;
            }
        }

        if (count > 0)
        {
            Logger?.LogInformation("MCP credential redaction: {Count} sensitive values redacted", count);
        }

        return result;
    }

    /// <summary>
    /// Redacts credentials in all string values of a dictionary.
    /// Nested dictionaries are serialized to JSON before redaction
    /// to ensure embedded credentials are detected. Values under
    /// obviously sensitive key names are redacted even when they do
    /// not match a specific credential regex.
    /// Returns a new dictionary with redacted values.
    /// </summary>
    public static Dictionary<string, object> RedactDictionary(Dictionary<string, object>? parameters)
    {
        if (parameters is null || parameters.Count == 0)
            return new Dictionary<string, object>();

        var result = new Dictionary<string, object>(parameters.Count, StringComparer.OrdinalIgnoreCase);
        foreach (var kv in parameters)
        {
            // Serialize complex values to JSON so nested credentials are visible
            var valueStr = kv.Value switch
            {
                string s => s,
                null => string.Empty,
                Dictionary<string, object> => System.Text.Json.JsonSerializer.Serialize(kv.Value),
                System.Collections.IEnumerable => System.Text.Json.JsonSerializer.Serialize(kv.Value),
                _ => kv.Value.ToString() ?? string.Empty
            };

            result[kv.Key] = IsSensitiveKeyName(kv.Key) && valueStr.Length > 0
                ? RedactedPlaceholder
                : Redact(valueStr);
        }

        return result;
    }

    private static bool IsSensitiveKeyName(string key)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return false;
        }

        Span<char> normalizedBuffer = stackalloc char[key.Length];
        var count = 0;

        foreach (var character in key)
        {
            if (!char.IsLetterOrDigit(character))
            {
                continue;
            }

            normalizedBuffer[count++] = char.ToLowerInvariant(character);
        }

        if (count == 0)
        {
            return false;
        }

        var normalizedKey = normalizedBuffer[..count].ToString();
        return SensitiveKeyTokens.Any(token => normalizedKey.Contains(token, StringComparison.Ordinal));
    }

    /// <summary>
    /// Checks if the input contains any credential patterns without modifying it.
    /// Useful for detection/alerting.
    /// </summary>
    public static bool ContainsCredentials(string? input)
    {
        if (string.IsNullOrEmpty(input))
            return false;

        foreach (var (pattern, _) in AllPatterns)
        {
            try
            {
                if (pattern.IsMatch(input))
                    return true;
            }
            catch (RegexMatchTimeoutException ex)
            {
                Logger?.LogWarning(ex, "MCP credential detection timed out; treating input as sensitive");
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Returns the names of all credential types detected in the input.
    /// </summary>
    public static IReadOnlyList<string> DetectCredentialTypes(string? input)
    {
        if (string.IsNullOrEmpty(input))
            return Array.Empty<string>();

        var detected = new List<string>();
        foreach (var (pattern, name) in AllPatterns)
        {
            try
            {
                if (pattern.IsMatch(input))
                    detected.Add(name);
            }
            catch (RegexMatchTimeoutException ex)
            {
                Logger?.LogWarning(ex, "MCP credential type detection timed out; reporting unknown sensitive content");
                return ["Unknown sensitive content"];
            }
        }

        return detected;
    }
}
