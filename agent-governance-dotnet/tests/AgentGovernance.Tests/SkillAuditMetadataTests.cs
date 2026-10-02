// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentGovernance.Audit;
using Xunit;

namespace AgentGovernance.Tests;

public sealed class SkillAuditMetadataTests
{
    [Fact]
    public void Build_UsesOnlyTrustedSkillSource_AndHashesBothContexts()
    {
        var source = TrustedSkillMetadataSource.Create("  finance_skill  ", " catalog ");

        var metadata = SkillAuditMetadataBuilder.Build(
            source,
            new Dictionary<string, object> { ["before"] = true },
            new Dictionary<string, object> { ["after"] = true });

        Assert.NotNull(metadata);
        Assert.Equal("finance_skill", metadata.SkillName);
        Assert.Equal("catalog", metadata.SkillOrigin);
        Assert.Equal("trusted", metadata.ProvenanceSourceTrust);
        Assert.Equal(64, metadata.ContextHashBefore?.Length);
        Assert.Equal(64, metadata.ContextHashAfter?.Length);
    }

    [Fact]
    public void Build_DoesNotReadSkillNamesFromUntrustedContext()
    {
        var payload = new Dictionary<string, object>
        {
            ["skill_name"] = "spoofed_skill",
            ["skill_origin"] = "untrusted_request"
        };

        var metadata = SkillAuditMetadataBuilder.Build(null, payload);

        Assert.NotNull(metadata);
        Assert.Null(metadata.SkillName);
        Assert.Null(metadata.SkillOrigin);
        Assert.Null(metadata.ProvenanceSourceTrust);
        Assert.Equal(64, metadata.ContextHashBefore?.Length);
    }

    [Fact]
    public void HashContext_IsStableForNestedObjectKeyOrder()
    {
        var left = new Dictionary<string, object>
        {
            ["outer"] = new Dictionary<string, object>
            {
                ["z"] = 2,
                ["a"] = 1
            },
            ["items"] = new object[]
            {
                new Dictionary<string, object> { ["b"] = 2, ["a"] = 1 }
            }
        };
        var right = new Dictionary<string, object>
        {
            ["items"] = new object[]
            {
                new Dictionary<string, object> { ["a"] = 1, ["b"] = 2 }
            },
            ["outer"] = new Dictionary<string, object>
            {
                ["a"] = 1,
                ["z"] = 2
            }
        };

        Assert.Equal(
            SkillAuditMetadataBuilder.HashContext(left),
            SkillAuditMetadataBuilder.HashContext(right));
    }

    [Fact]
    public void HashContext_UsesSharedCanonicalUtf8JsonEncoding()
    {
        var context = new Dictionary<string, object> { ["text"] = "<&>+ café" };

        Assert.Equal(
            "64fc8ac088af1d1df47ae20c50f35b46a0037eb05a13c2cd6745da93e03ad9e9",
            SkillAuditMetadataBuilder.HashContext(context));
    }

    [Fact]
    public void HashContext_ReturnsNullForUnsupportedContext()
    {
        Assert.Null(SkillAuditMetadataBuilder.HashContext(new Action(static () => { })));
        Assert.Null(SkillAuditMetadataBuilder.HashContext(null));
    }
}
