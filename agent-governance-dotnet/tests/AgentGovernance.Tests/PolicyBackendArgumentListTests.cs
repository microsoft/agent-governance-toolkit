// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics;
using AgentGovernance.Policy;
using Xunit;

namespace AgentGovernance.Tests;

/// <summary>
/// Regression tests for the REVIEW.md HIGH .NET #1 finding: both
/// <see cref="CedarPolicyBackend"/> and <see cref="OpaPolicyBackend"/>
/// previously built the CLI invocation via
/// <c>ProcessStartInfo.Arguments = $"... \"{path}\" ..."</c>, which mis-tokenises
/// any path or query containing a double-quote (legal on Linux) or shell
/// metacharacters. The fix uses <see cref="ProcessStartInfo.ArgumentList"/>
/// so each argument is passed verbatim with no string-level escaping.
/// </summary>
public class PolicyBackendArgumentListTests
{
    // ---------------------------------------------------------------------
    // Cedar
    // ---------------------------------------------------------------------

    [Fact]
    public void Cedar_BuildStartInfo_UsesArgumentListNotArgumentsString()
    {
        var info = CedarPolicyBackend.BuildCedarStartInfo(
            executable: "cedar",
            policyPath: "/tmp/policy.cedar",
            entitiesPath: "/tmp/entities.json",
            requestPath: "/tmp/request.json");

        // The legacy `Arguments` string must be empty — all arguments go
        // through ArgumentList so the OS-level argv builder handles quoting.
        Assert.Equal(string.Empty, info.Arguments);
        Assert.Equal(
            new[]
            {
                "authorize",
                "--policies",
                "/tmp/policy.cedar",
                "--entities",
                "/tmp/entities.json",
                "--request-json",
                "/tmp/request.json",
            },
            info.ArgumentList);
    }

    [Fact]
    public void Cedar_BuildStartInfo_PreservesQuoteInPath()
    {
        // A Linux-legal path containing a double-quote previously broke out of
        // the naive `Arguments = $"... \"{path}\" ..."` quoting.
        const string evilPath = "/tmp/evil\" --extra-flag /etc/passwd";

        var info = CedarPolicyBackend.BuildCedarStartInfo(
            executable: "cedar",
            policyPath: evilPath,
            entitiesPath: "/tmp/entities.json",
            requestPath: "/tmp/request.json");

        // The quote-bearing path must land in ArgumentList verbatim — not
        // tokenised by a string-level argv parser.
        Assert.Contains(evilPath, info.ArgumentList);
        // And the injected "extra-flag" must NOT appear as a standalone arg.
        Assert.DoesNotContain("--extra-flag", info.ArgumentList);
    }

    [Fact]
    public void Cedar_BuildStartInfo_PreservesShellMetacharacters()
    {
        const string shellyPath = "/tmp/a b; rm -rf /";

        var info = CedarPolicyBackend.BuildCedarStartInfo(
            executable: "cedar",
            policyPath: shellyPath,
            entitiesPath: "/tmp/entities.json",
            requestPath: "/tmp/request.json");

        Assert.Contains(shellyPath, info.ArgumentList);
        // The space-separated chunks must not appear as separate args.
        Assert.DoesNotContain("b;", info.ArgumentList);
        Assert.DoesNotContain("rm", info.ArgumentList);
    }

    [Fact]
    public void Cedar_BuildStartInfo_NoShellExecuteWithRedirectedStreams()
    {
        var info = CedarPolicyBackend.BuildCedarStartInfo(
            "cedar", "/p", "/e", "/r");

        Assert.False(info.UseShellExecute);
        Assert.True(info.RedirectStandardOutput);
        Assert.True(info.RedirectStandardError);
        Assert.True(info.CreateNoWindow);
    }

    // ---------------------------------------------------------------------
    // OPA
    // ---------------------------------------------------------------------

    [Fact]
    public void Opa_BuildStartInfo_UsesArgumentListNotArgumentsString()
    {
        var info = OpaPolicyBackend.BuildOpaStartInfo(
            executable: "opa",
            regoPath: "/tmp/policy.rego",
            query: "data.agentgovernance.allow");

        Assert.Equal(string.Empty, info.Arguments);
        Assert.Equal(
            new[]
            {
                "eval",
                "--format",
                "json",
                "--stdin-input",
                "--data",
                "/tmp/policy.rego",
                "data.agentgovernance.allow",
            },
            info.ArgumentList);
    }

    [Fact]
    public void Opa_BuildStartInfo_PreservesQuoteInRegoPath()
    {
        const string evilPath = "/tmp/evil\" --insecure /etc/shadow";

        var info = OpaPolicyBackend.BuildOpaStartInfo(
            executable: "opa",
            regoPath: evilPath,
            query: "data.x.allow");

        Assert.Contains(evilPath, info.ArgumentList);
        Assert.DoesNotContain("--insecure", info.ArgumentList);
    }

    [Fact]
    public void Opa_BuildStartInfo_PreservesQuoteInQuery()
    {
        // OPA's query is also caller-supplied via `_query`. A query string
        // containing a double-quote previously broke out of the naive quoting.
        const string evilQuery = "data.x.allow\"; data.evil.exec";

        var info = OpaPolicyBackend.BuildOpaStartInfo(
            executable: "opa",
            regoPath: "/tmp/policy.rego",
            query: evilQuery);

        Assert.Contains(evilQuery, info.ArgumentList);
        // The injected second-query chunk must not appear as a standalone arg.
        Assert.DoesNotContain("data.evil.exec", info.ArgumentList);
    }

    [Fact]
    public void Opa_BuildStartInfo_PipeInputViaStdinNotCommandLine()
    {
        // OPA still uses stdin for the JSON input (RedirectStandardInput);
        // ArgumentList must NOT contain the input JSON.
        var info = OpaPolicyBackend.BuildOpaStartInfo(
            "opa", "/tmp/policy.rego", "data.x.allow");

        Assert.True(info.RedirectStandardInput);
        Assert.False(info.UseShellExecute);
        Assert.DoesNotContain("--input", info.ArgumentList);
        Assert.Contains("--stdin-input", info.ArgumentList);
    }
}
