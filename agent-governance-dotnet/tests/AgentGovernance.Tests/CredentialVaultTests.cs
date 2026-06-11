// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using AgentGovernance.Security;
using Xunit;

namespace AgentGovernance.Tests;

public class CredentialVaultAdminTests
{
    private static CredentialVault MakeVault()
    {
        var v = new CredentialVault();
        v.Put("github_pat", "ghp_real_secret_value", "bearer_token");
        v.Put("db_password", "p@ss-w0rd!", "password");
        return v;
    }

    [Fact]
    public void Put_ReturnsHandle_WithPlaceholder()
    {
        var v = new CredentialVault();
        var h = v.Put("k1", "v1");
        Assert.Equal("k1", h.Name);
        Assert.Equal("{{cred:k1}}", h.Placeholder());
    }

    [Fact]
    public void Put_RejectsBadNames()
    {
        var v = new CredentialVault();
        Assert.Throws<ArgumentException>(() => v.Put("", "v"));
        Assert.Throws<ArgumentException>(() => v.Put("bad name", "v"));
        Assert.Throws<ArgumentException>(() => v.Put(new string('a', 200), "v"));
    }

    [Fact]
    public void ListHandles_NeverLeaksValues()
    {
        var v = MakeVault();
        var names = v.ListHandles();
        Assert.Equal(new[] { "db_password", "github_pat" }, names);
        foreach (var meta in names.Select(n => v.GetMetadata(n)))
        {
            Assert.NotNull(meta);
            Assert.False(meta!.ContainsKey("value"));
            Assert.DoesNotContain("ghp_real", JsonSerializer.Serialize(meta));
        }
    }

    [Fact]
    public void Rotate_PreservesHandleName_BumpsVersion()
    {
        var v = MakeVault();
        var before = v.GetMetadata("github_pat")!;
        Assert.Equal(1, (int)before["version"]!);
        var h = v.Rotate("github_pat", "ghp_new");
        var after = v.GetMetadata("github_pat")!;
        Assert.Equal("github_pat", h.Name);
        Assert.Equal(2, (int)after["version"]!);
        Assert.NotNull(after["rotatedAt"]);
    }

    [Fact]
    public void Rotate_Unknown_Throws()
    {
        var v = MakeVault();
        Assert.Throws<KeyNotFoundException>(() => v.Rotate("nope", "x"));
    }

    [Fact]
    public void Delete_ReturnsPresenceFlag()
    {
        var v = MakeVault();
        var first = v.Delete("db_password");
        var second = v.Delete("db_password");
        Assert.True(first);
        Assert.False(second);
    }
}

public class CredentialVaultScopingTests
{
    private static CredentialVault MakeVault()
    {
        var v = new CredentialVault();
        v.Put("github_pat", "GHP-VALUE");
        v.Put("db_password", "DB-VALUE");
        v.RegisterProfile(new CredentialProfile("did:web:agent-ci",
            new Dictionary<string, string>
            {
                ["github:read_issues"] = "github_pat",
                ["github:push_code"] = "github_pat",
            }));
        v.RegisterProfile(new CredentialProfile("did:web:agent-analytics",
            new Dictionary<string, string> { ["db:query"] = "db_password" }));
        return v;
    }

    [Fact]
    public void CheckAccess_AllowsBoundAction()
    {
        var v = MakeVault();
        Assert.True(v.CheckAccess("did:web:agent-ci", "github_pat", "github:read_issues"));
    }

    [Fact]
    public void CheckAccess_DeniesUnknownAgent()
    {
        var v = MakeVault();
        Assert.False(v.CheckAccess("did:web:rogue", "github_pat", "github:read_issues"));
    }

    [Fact]
    public void CheckAccess_DeniesUnboundAction()
    {
        var v = MakeVault();
        Assert.False(v.CheckAccess("did:web:agent-ci", "db_password", "db:query"));
    }

    [Fact]
    public void CheckAccess_DeniesCrossActionReuse()
    {
        var v = MakeVault();
        Assert.False(v.CheckAccess("did:web:agent-analytics", "db_password", "db:admin"));
    }

    [Fact]
    public void ProfileBindings_IsolatedFromCallerMutation()
    {
        var bindings = new Dictionary<string, string> { ["a"] = "h" };
        var p = new CredentialProfile("did:web:x", bindings);
        bindings["a"] = "other";
        Assert.Equal("h", p.CapabilityFor("a"));
    }
}

public class CredentialInjectorTests
{
    private static (CredentialVault v, CredentialInjector i) MakeStack()
    {
        var v = new CredentialVault();
        v.Put("github_pat", "GHP-RESOLVED-VALUE");
        v.Put("db_password", "DBP-VALUE");
        v.RegisterProfile(new CredentialProfile("did:web:agent-ci",
            new Dictionary<string, string>
            {
                ["github:read_issues"] = "github_pat",
                ["github:push_code"] = "github_pat",
            }));
        v.RegisterProfile(new CredentialProfile("did:web:agent-analytics",
            new Dictionary<string, string> { ["db:query"] = "db_password" }));
        return (v, new CredentialInjector(v));
    }

    [Fact]
    public void InjectHeaders_HappyPath()
    {
        var (_, i) = MakeStack();
        var r = i.InjectHeaders("did:web:agent-ci",
            new Dictionary<string, string>
            {
                ["Authorization"] = "Bearer {{cred:github_pat}}",
                ["Accept"] = "application/json",
            },
            new InjectionOptions
            {
                ActionClass = "github:read_issues",
                TargetService = "api.github.com",
                AllowedHandles = new[] { "github_pat" },
                PolicyVersion = "v1",
            });
        Assert.True(r.Allowed);
        var headers = (Dictionary<string, string>)r.Payload;
        Assert.Equal("Bearer GHP-RESOLVED-VALUE", headers["Authorization"]);
        Assert.Null(r.DenyReceipt);
        Assert.Single(r.AuditEvents);
        Assert.Equal(CredentialDecision.Allow, r.AuditEvents[0].Decision);
    }

    [Fact]
    public void InjectEnv_RendersValues()
    {
        var (_, i) = MakeStack();
        var r = i.InjectEnv("did:web:agent-ci",
            new Dictionary<string, string>
            {
                ["PATH"] = "/usr/bin",
                ["GITHUB_TOKEN"] = "{{cred:github_pat}}",
            },
            new InjectionOptions
            {
                ActionClass = "github:read_issues",
                TargetService = "subprocess",
                AllowedHandles = new[] { "github_pat" },
            });
        Assert.True(r.Allowed);
        var env = (Dictionary<string, string>)r.Payload;
        Assert.Equal("GHP-RESOLVED-VALUE", env["GITHUB_TOKEN"]);
    }

    [Fact]
    public void UnauthorizedPlaceholder_DeniesWholeCall_McpUntrusted()
    {
        var (_, i) = MakeStack();
        var r = i.InjectToolArgs("did:web:agent-analytics",
            new Dictionary<string, string> { ["sql"] = "SELECT 1", ["auth"] = "{{cred:github_pat}}" },
            new InjectionOptions
            {
                ActionClass = "db:query",
                TargetService = "pg",
                AllowedHandles = new[] { "db_password" },
            });
        Assert.False(r.Allowed);
        Assert.IsType<DenyReceipt>(r.Payload);
        Assert.Equal(CredentialVault.DenyReason, ((DenyReceipt)r.Payload).Reason);
    }

    [Fact]
    public void Missing_And_OutOfScope_ReturnIdenticalDeny()
    {
        var (_, i) = MakeStack();
        var missing = i.InjectHeaders("did:web:agent-ci",
            new Dictionary<string, string> { ["X"] = "{{cred:does_not_exist}}" },
            new InjectionOptions
            {
                ActionClass = "github:read_issues",
                TargetService = "svc",
                AllowedHandles = new[] { "does_not_exist" },
            });
        var outOfScope = i.InjectHeaders("did:web:agent-ci",
            new Dictionary<string, string> { ["X"] = "{{cred:db_password}}" },
            new InjectionOptions
            {
                ActionClass = "github:read_issues",
                TargetService = "svc",
                AllowedHandles = new[] { "db_password" },
            });
        Assert.False(missing.Allowed);
        Assert.False(outOfScope.Allowed);
        Assert.Equal(missing.DenyReceipt, outOfScope.DenyReceipt);
    }

    [Fact]
    public void PolicyCheck_RunsBeforeVaultRead()
    {
        var (_, i) = MakeStack();
        var seen = new List<InjectionContext>();
        var r = i.InjectHeaders("did:web:agent-ci",
            new Dictionary<string, string> { ["Authorization"] = "Bearer {{cred:github_pat}}" },
            new InjectionOptions
            {
                ActionClass = "github:push_code",
                TargetService = "api.github.com",
                AllowedHandles = new[] { "github_pat" },
                PolicyVersion = "v7",
                PolicyCheck = ctx => { seen.Add(ctx); return new PolicyOutcome(false, "no"); },
            });
        Assert.False(r.Allowed);
        Assert.Single(seen);
        Assert.Equal(new[] { "github_pat" }, seen[0].RequestedHandles);
        Assert.Equal("v7", seen[0].PolicyVersion);
    }

    [Fact]
    public void SameDenyAcrossSurfaces()
    {
        var (_, i) = MakeStack();
        var opts = new InjectionOptions
        {
            ActionClass = "db:query",
            TargetService = "svc",
            AllowedHandles = new[] { "github_pat" },
        };
        var h = i.InjectHeaders("did:web:agent-analytics",
            new Dictionary<string, string> { ["Authorization"] = "{{cred:github_pat}}" }, opts);
        var a = i.InjectToolArgs("did:web:agent-analytics",
            new Dictionary<string, string> { ["x"] = "{{cred:github_pat}}" }, opts);
        var e = i.InjectEnv("did:web:agent-analytics",
            new Dictionary<string, string> { ["TOKEN"] = "{{cred:github_pat}}" }, opts);
        foreach (var r in new[] { h, a, e })
        {
            Assert.False(r.Allowed);
            Assert.Equal(CredentialVault.DenyReason, r.DenyReceipt!.Reason);
        }
    }

    [Fact]
    public void PayloadWithoutPlaceholders_PassesThrough()
    {
        var (_, i) = MakeStack();
        var r = i.InjectHeaders("did:web:agent-ci",
            new Dictionary<string, string> { ["Accept"] = "application/json" },
            new InjectionOptions
            {
                ActionClass = "github:read_issues",
                TargetService = "svc",
                AllowedHandles = Array.Empty<string>(),
            });
        Assert.True(r.Allowed);
        Assert.Equal("application/json", ((Dictionary<string, string>)r.Payload)["Accept"]);
    }
}

public class CredentialAuditTests
{
    [Fact]
    public void AuditRecords_NoValueLeakage()
    {
        var v = new CredentialVault();
        v.Put("github_pat", "GHP-RESOLVED-VALUE");
        v.RegisterProfile(new CredentialProfile("did:web:agent-ci",
            new Dictionary<string, string> { ["github:read_issues"] = "github_pat" }));
        var i = new CredentialInjector(v);
        i.InjectHeaders("did:web:agent-ci",
            new Dictionary<string, string> { ["Authorization"] = "Bearer {{cred:github_pat}}" },
            new InjectionOptions
            {
                ActionClass = "github:read_issues",
                TargetService = "svc",
                AllowedHandles = new[] { "github_pat" },
                PolicyVersion = "v1",
            });
        var events = v.AuditLog();
        Assert.Single(events);
        Assert.Equal(CredentialDecision.Allow, events[0].Decision);
        Assert.DoesNotContain("GHP-RESOLVED-VALUE", JsonSerializer.Serialize(events));
    }

    [Fact]
    public void Digest_StableAndKeyDependent()
    {
        var v = new CredentialVault();
        v.Put("k", "x");
        v.RegisterProfile(new CredentialProfile("did:web:a",
            new Dictionary<string, string> { ["act"] = "k" }));
        var i = new CredentialInjector(v);
        i.InjectHeaders("did:web:a",
            new Dictionary<string, string> { ["A"] = "{{cred:k}}" },
            new InjectionOptions
            {
                ActionClass = "act",
                TargetService = "svc",
                AllowedHandles = new[] { "k" },
            });
        var events = v.AuditLog();
        var k1 = Encoding.UTF8.GetBytes("k");
        var k2 = Encoding.UTF8.GetBytes("other");
        Assert.Equal(CredentialAudit.Digest(events, k1), CredentialAudit.Digest(events, k1));
        Assert.NotEqual(CredentialAudit.Digest(events, k1), CredentialAudit.Digest(events, k2));
    }
}

public class CredentialVaultRotationTests
{
    [Fact]
    public void Rotation_DoesNotRequirePromptChanges()
    {
        var v = new CredentialVault();
        v.Put("github_pat", "GHP-V1");
        v.RegisterProfile(new CredentialProfile("did:web:agent-ci",
            new Dictionary<string, string> { ["github:read_issues"] = "github_pat" }));
        var i = new CredentialInjector(v);
        var saved = new Dictionary<string, string> { ["Authorization"] = "Bearer {{cred:github_pat}}" };

        var before = i.InjectHeaders("did:web:agent-ci", saved, new InjectionOptions
        {
            ActionClass = "github:read_issues",
            TargetService = "svc",
            AllowedHandles = new[] { "github_pat" },
        });
        Assert.Equal("Bearer GHP-V1", ((Dictionary<string, string>)before.Payload)["Authorization"]);

        v.Rotate("github_pat", "GHP-V2");

        var after = i.InjectHeaders("did:web:agent-ci", saved, new InjectionOptions
        {
            ActionClass = "github:read_issues",
            TargetService = "svc",
            AllowedHandles = new[] { "github_pat" },
        });
        Assert.Equal("Bearer GHP-V2", ((Dictionary<string, string>)after.Payload)["Authorization"]);
        Assert.Equal("Bearer {{cred:github_pat}}", saved["Authorization"]);
    }
}

public class CredentialVaultPersistenceTests
{
    [Fact]
    public void RoundTrip_DistinctivePlaintextNotOnDisk() // gitleaks:allow
    {
        var key = CredentialVault.GenerateKey();
        var tmp = Path.Join(Path.GetTempPath(), $"vault-{Guid.NewGuid():N}.bin");
        try
        {
            var secret = "distinctive rotated fixture not a real key"; // gitleaks:allow
            var v1 = new CredentialVault(tmp, key);
            v1.Put("k", "original");
            v1.Rotate("k", secret);

            var blob = File.ReadAllBytes(tmp);
            // secret bytes not present anywhere in blob
            var secretBytes = Encoding.UTF8.GetBytes(secret);
            Assert.False(BytesContain(blob, secretBytes));
            Assert.False(BytesContain(blob, Encoding.UTF8.GetBytes("\"value\"")));

            var v2 = new CredentialVault(tmp, key);
            Assert.Equal(new[] { "k" }, v2.ListHandles());
            var meta = v2.GetMetadata("k")!;
            Assert.Equal(2, (int)meta["version"]!);
        }
        finally
        {
            if (File.Exists(tmp)) File.Delete(tmp);
        }
    }

    [Fact]
    public void Persistence_RequiresKey()
    {
        Assert.Throws<ArgumentException>(() =>
            new CredentialVault("/tmp/x.bin", null!));
        Assert.Throws<ArgumentException>(() =>
            new CredentialVault("/tmp/x.bin", new byte[16]));
    }

    private static bool BytesContain(byte[] haystack, byte[] needle)
    {
        if (needle.Length == 0) return true;
        for (int i = 0; i <= haystack.Length - needle.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j]) { match = false; break; }
            }
            if (match) return true;
        }
        return false;
    }
}

public class CredentialPlaceholderRegexTests
{
    [Theory]
    [InlineData("{{cred:abc}}", "abc")]
    [InlineData("{{ cred:a.b-c_1 }}", "a.b-c_1")]
    public void MatchesValid(string input, string expected)
    {
        var matches = CredentialInjector.PlaceholderRegex.Matches(input);
        Assert.Single(matches);
        Assert.Equal(expected, matches[0].Groups[1].Value);
    }

    [Theory]
    [InlineData("{{cred:has space}}")]
    [InlineData("{{cred:bad/slash}}")]
    public void RejectsInvalid(string input)
    {
        Assert.Empty(CredentialInjector.PlaceholderRegex.Matches(input).Cast<object>());
    }
}
