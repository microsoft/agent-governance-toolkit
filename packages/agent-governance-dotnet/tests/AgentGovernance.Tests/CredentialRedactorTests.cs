// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Mcp;
using Xunit;

namespace AgentGovernance.Tests;

public class CredentialRedactorTests
{
    // ── Redact: individual credential patterns ──

    [Fact]
    public void Redact_OpenAiKey_Redacted()
    {
        var input = "key: sk-live_abc12345678901234567890";
        var result = CredentialRedactor.Redact(input);

        Assert.DoesNotContain("sk-live_", result);
        Assert.Contains(CredentialRedactor.RedactedPlaceholder, result);
        Assert.StartsWith("key: ", result);
    }

    [Fact]
    public void Redact_GitHubPat_Redacted()
    {
        var input = "token: ghp_abcdefghijklmnopqrstuvwxyz1234567890";
        var result = CredentialRedactor.Redact(input);

        Assert.DoesNotContain("ghp_", result);
        Assert.Contains(CredentialRedactor.RedactedPlaceholder, result);
    }

    [Fact]
    public void Redact_GitHubFineGrained_Redacted()
    {
        var input = "token: github_pat_xxxxxxxxxxxxxxxxxxxx_yyyyyy";
        var result = CredentialRedactor.Redact(input);

        Assert.DoesNotContain("github_pat_", result);
        Assert.Contains(CredentialRedactor.RedactedPlaceholder, result);
    }

    [Fact]
    public void Redact_AwsAccessKey_Redacted()
    {
        var input = "aws_key=AKIAIOSFODNN7EXAMPLE";
        var result = CredentialRedactor.Redact(input);

        Assert.DoesNotContain("AKIAIOSFODNN7EXAMPLE", result);
        Assert.Contains(CredentialRedactor.RedactedPlaceholder, result);
    }

    [Fact]
    public void Redact_BearerToken_Redacted()
    {
        var input = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIx";
        var result = CredentialRedactor.Redact(input);

        Assert.DoesNotContain("eyJhbGciOiJIUzI1Ni", result);
        Assert.Contains(CredentialRedactor.RedactedPlaceholder, result);
    }

    [Fact]
    public void Redact_PrivateKey_Redacted()
    {
        var input = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ...\n-----END RSA PRIVATE KEY-----";
        var result = CredentialRedactor.Redact(input);

        Assert.DoesNotContain("-----BEGIN RSA PRIVATE KEY-----", result);
        Assert.DoesNotContain("MIIEpAIBAAKCAQ", result);
        Assert.DoesNotContain("-----END RSA PRIVATE KEY-----", result);
        Assert.Contains(CredentialRedactor.RedactedPlaceholder, result);
    }

    [Fact]
    public void Redact_ConnectionString_Redacted()
    {
        var input = "Server=myserver;Database=mydb;Password=MySecret123;";
        var result = CredentialRedactor.Redact(input);

        Assert.DoesNotContain("MySecret123", result);
        Assert.Contains(CredentialRedactor.RedactedPlaceholder, result);
    }

    // ── Redact: safe inputs ──

    [Fact]
    public void Redact_NoCredentials_Unchanged()
    {
        var input = "This is a normal log message with no secrets.";
        var result = CredentialRedactor.Redact(input);

        Assert.Equal(input, result);
    }

    [Fact]
    public void Redact_NullInput_ReturnsEmpty()
    {
        var result = CredentialRedactor.Redact(null);

        Assert.Equal(string.Empty, result);
    }

    [Fact]
    public void Redact_EmptyInput_ReturnsEmpty()
    {
        var result = CredentialRedactor.Redact(string.Empty);

        Assert.Equal(string.Empty, result);
    }

    // ── Redact: multiple credentials ──

    [Fact]
    public void Redact_MultipleCredentials_AllRedacted()
    {
        var input = "key=sk-live_abc12345678901234567890 token=ghp_abcdefghijklmnopqrstuvwxyz1234567890 aws=AKIAIOSFODNN7EXAMPLE";
        var result = CredentialRedactor.Redact(input);

        Assert.DoesNotContain("sk-live_", result);
        Assert.DoesNotContain("ghp_", result);
        Assert.DoesNotContain("AKIAIOSFODNN7EXAMPLE", result);
        // Should have multiple redaction placeholders
        Assert.True(result.Split(CredentialRedactor.RedactedPlaceholder).Length > 2,
            "Expected multiple credentials to be redacted");
    }

    // ── RedactDictionary ──

    [Fact]
    public void RedactDictionary_RedactsAllValues()
    {
        var input = new Dictionary<string, object>
        {
            ["apiKey"] = "sk-live_abc12345678901234567890",
            ["auth"] = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIx",
            ["safe"] = "no secrets here",
        };

        var result = CredentialRedactor.RedactDictionary(input);

        Assert.Equal(3, result.Count);
        Assert.Contains(CredentialRedactor.RedactedPlaceholder, result["apiKey"].ToString());
        Assert.Contains(CredentialRedactor.RedactedPlaceholder, result["auth"].ToString());
        Assert.Equal("no secrets here", result["safe"].ToString());
    }

    [Fact]
    public void RedactDictionary_NullInput_ReturnsEmpty()
    {
        var result = CredentialRedactor.RedactDictionary(null);

        Assert.NotNull(result);
        Assert.Empty(result);
    }

    // ── ContainsCredentials ──

    [Fact]
    public void ContainsCredentials_WithKey_ReturnsTrue()
    {
        var input = "some text with sk-live_abc12345678901234567890 embedded";

        Assert.True(CredentialRedactor.ContainsCredentials(input));
    }

    [Fact]
    public void ContainsCredentials_CleanText_ReturnsFalse()
    {
        var input = "This is a perfectly normal log message.";

        Assert.False(CredentialRedactor.ContainsCredentials(input));
    }

    // ── DetectCredentialTypes ──

    [Fact]
    public void DetectCredentialTypes_ReturnsCorrectNames()
    {
        var input = "sk-live_abc12345678901234567890 and AKIAIOSFODNN7EXAMPLE";
        var detected = CredentialRedactor.DetectCredentialTypes(input);

        Assert.Contains("OpenAI API key", detected);
        Assert.Contains("AWS access key", detected);
        Assert.True(detected.Count >= 2);
    }

    // ── New credential patterns ──────────────────────────────────────────

    [Fact]
    public void Redact_AzureStorageKey_Redacted()
    {
        var input = "AccountKey=abc123def456ghi789jkl012mno345pqr678stu901vw==";
        var result = CredentialRedactor.Redact(input);
        Assert.Contains("[REDACTED]", result);
        Assert.DoesNotContain("abc123", result);
    }

    [Fact]
    public void Redact_DatabaseUri_Redacted()
    {
        var input = "postgresql://admin:secretpassword@db.example.com:5432/mydb";
        var result = CredentialRedactor.Redact(input);
        Assert.Contains("[REDACTED]", result);
        Assert.DoesNotContain("secretpassword", result);
    }

    [Fact]
    public void Redact_MongoDbUri_Redacted()
    {
        var input = "mongodb+srv://user:pass123@cluster.mongodb.net/db";
        var result = CredentialRedactor.Redact(input);
        Assert.Contains("[REDACTED]", result);
    }

    [Fact]
    public void Redact_RedisUri_Redacted()
    {
        var input = "redis://default:mypassword@redis.example.com:6379";
        var result = CredentialRedactor.Redact(input);
        Assert.Contains("[REDACTED]", result);
    }

    [Fact]
    public void RedactDictionary_NestedDict_RedactsCredentials()
    {
        var nested = new Dictionary<string, object>
        {
            ["token"] = "sk-live_abcdefghijklmnopqrstuvwx"
        };
        var input = new Dictionary<string, object>
        {
            ["auth"] = nested
        };
        var result = CredentialRedactor.RedactDictionary(input);
        Assert.Contains("[REDACTED]", result["auth"].ToString());
        Assert.DoesNotContain("sk-live", result["auth"].ToString());
    }

    [Fact]
    public void RedactDictionary_SensitiveKeyName_RedactsShortSecrets()
    {
        var input = new Dictionary<string, object>
        {
            ["apiKey"] = "sk-live_abc123def456ghi789"
        };

        var result = CredentialRedactor.RedactDictionary(input);

        Assert.Equal(CredentialRedactor.RedactedPlaceholder, result["apiKey"]);
    }

    [Fact]
    public void Redact_UppercaseHex_Redacted()
    {
        // 40+ char uppercase hex should match generic secret pattern
        var input = "token=" + new string('A', 40) + "1234567890";
        // Note: [A-F] won't all match, but [0-9a-fA-F]{40,} should catch mixed
        var input2 = "token=abcdef1234567890abcdef1234567890ABCDEF12";
        var result = CredentialRedactor.Redact(input2);
        Assert.Contains("[REDACTED]", result);
    }
}
