// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentGovernance.Audit;
using Xunit;

namespace AgentGovernance.Tests;

public class AuditLoggerTests
{
    [Fact]
    public void Log_CreatesGenesisEntry_WithEmptyPreviousHash()
    {
        var logger = new AuditLogger();

        var entry = logger.Log("did:agentmesh:agent1", "tool_call", "allow");

        Assert.Equal(0, entry.Seq);
        Assert.Equal(string.Empty, entry.PreviousHash);
        Assert.NotEmpty(entry.Hash);
        Assert.Equal("did:agentmesh:agent1", entry.AgentId);
        Assert.Equal("tool_call", entry.Action);
        Assert.Equal("allow", entry.Decision);
    }

    [Fact]
    public void Log_SecondEntry_LinksToPreviousHash()
    {
        var logger = new AuditLogger();

        var first = logger.Log("did:agentmesh:a", "action1", "allow");
        var second = logger.Log("did:agentmesh:b", "action2", "deny");

        Assert.Equal(1, second.Seq);
        Assert.Equal(first.Hash, second.PreviousHash);
        Assert.NotEqual(first.Hash, second.Hash);
    }

    [Fact]
    public void Log_MultipleEntries_FormsChain()
    {
        var logger = new AuditLogger();

        var e1 = logger.Log("did:agentmesh:a", "read", "allow");
        var e2 = logger.Log("did:agentmesh:a", "write", "deny");
        var e3 = logger.Log("did:agentmesh:b", "delete", "allow");

        Assert.Equal(string.Empty, e1.PreviousHash);
        Assert.Equal(e1.Hash, e2.PreviousHash);
        Assert.Equal(e2.Hash, e3.PreviousHash);
        Assert.Equal(3, logger.Count);
    }

    [Fact]
    public void Verify_EmptyLog_ReturnsTrue()
    {
        var logger = new AuditLogger();
        Assert.True(logger.Verify());
    }

    [Fact]
    public void Verify_ValidChain_ReturnsTrue()
    {
        var logger = new AuditLogger();

        logger.Log("did:agentmesh:a", "action1", "allow");
        logger.Log("did:agentmesh:b", "action2", "deny");
        logger.Log("did:agentmesh:c", "action3", "allow");

        Assert.True(logger.Verify());
    }

    [Fact]
    public void Verify_SingleEntry_ReturnsTrue()
    {
        var logger = new AuditLogger();
        logger.Log("did:agentmesh:a", "action1", "allow");

        Assert.True(logger.Verify());
    }

    [Fact]
    public void GetEntries_NoFilter_ReturnsAll()
    {
        var logger = new AuditLogger();
        logger.Log("did:agentmesh:a", "read", "allow");
        logger.Log("did:agentmesh:b", "write", "deny");
        logger.Log("did:agentmesh:a", "delete", "allow");

        var entries = logger.GetEntries();
        Assert.Equal(3, entries.Count);
    }

    [Fact]
    public void GetEntries_FilterByAgentId_ReturnsMatching()
    {
        var logger = new AuditLogger();
        logger.Log("did:agentmesh:a", "read", "allow");
        logger.Log("did:agentmesh:b", "write", "deny");
        logger.Log("did:agentmesh:a", "delete", "allow");

        var entries = logger.GetEntries(agentId: "did:agentmesh:a");
        Assert.Equal(2, entries.Count);
        Assert.All(entries, e => Assert.Equal("did:agentmesh:a", e.AgentId));
    }

    [Fact]
    public void GetEntries_FilterByAction_ReturnsMatching()
    {
        var logger = new AuditLogger();
        logger.Log("did:agentmesh:a", "read", "allow");
        logger.Log("did:agentmesh:b", "write", "deny");
        logger.Log("did:agentmesh:a", "read", "deny");

        var entries = logger.GetEntries(action: "read");
        Assert.Equal(2, entries.Count);
        Assert.All(entries, e => Assert.Equal("read", e.Action));
    }

    [Fact]
    public void GetEntries_FilterByBothAgentAndAction_ReturnsMatching()
    {
        var logger = new AuditLogger();
        logger.Log("did:agentmesh:a", "read", "allow");
        logger.Log("did:agentmesh:a", "write", "deny");
        logger.Log("did:agentmesh:b", "read", "allow");

        var entries = logger.GetEntries(agentId: "did:agentmesh:a", action: "read");
        Assert.Single(entries);
        Assert.Equal("did:agentmesh:a", entries[0].AgentId);
        Assert.Equal("read", entries[0].Action);
    }

    [Fact]
    public void GetEntries_NoMatch_ReturnsEmpty()
    {
        var logger = new AuditLogger();
        logger.Log("did:agentmesh:a", "read", "allow");

        var entries = logger.GetEntries(agentId: "did:agentmesh:unknown");
        Assert.Empty(entries);
    }

    [Fact]
    public void ExportJson_ReturnsValidJson()
    {
        var logger = new AuditLogger();
        logger.Log("did:agentmesh:a", "read", "allow");
        logger.Log("did:agentmesh:b", "write", "deny");

        var json = logger.ExportJson();

        Assert.NotEmpty(json);
        Assert.Contains("did:agentmesh:a", json);
        Assert.Contains("did:agentmesh:b", json);
        Assert.Contains("read", json);
        Assert.Contains("write", json);
    }

    [Fact]
    public void ExportJson_EmptyLog_ReturnsEmptyArray()
    {
        var logger = new AuditLogger();
        var json = logger.ExportJson();
        Assert.Equal("[]", json);
    }

    [Fact]
    public void Count_ReturnsCorrectCount()
    {
        var logger = new AuditLogger();
        Assert.Equal(0, logger.Count);

        logger.Log("did:agentmesh:a", "read", "allow");
        Assert.Equal(1, logger.Count);

        logger.Log("did:agentmesh:b", "write", "deny");
        Assert.Equal(2, logger.Count);
    }

    [Fact]
    public void Log_NullAgentId_Throws()
    {
        var logger = new AuditLogger();
        Assert.ThrowsAny<ArgumentException>(() => logger.Log(null!, "action", "decision"));
    }

    [Fact]
    public void Log_EmptyAction_Throws()
    {
        var logger = new AuditLogger();
        Assert.Throws<ArgumentException>(() => logger.Log("did:agentmesh:a", "", "decision"));
    }

    [Fact]
    public void Log_EmptyDecision_Throws()
    {
        var logger = new AuditLogger();
        Assert.Throws<ArgumentException>(() => logger.Log("did:agentmesh:a", "action", " "));
    }

    [Fact]
    public void Timestamp_IsUtc()
    {
        var logger = new AuditLogger();
        var entry = logger.Log("did:agentmesh:a", "action", "allow");

        Assert.Equal(TimeSpan.Zero, entry.Timestamp.Offset);
    }

    [Fact]
    public void HashChain_IsConsistent_AcrossMultipleVerifications()
    {
        var logger = new AuditLogger();

        for (int i = 0; i < 10; i++)
        {
            logger.Log($"did:agentmesh:agent{i}", $"action{i}", i % 2 == 0 ? "allow" : "deny");
        }

        Assert.True(logger.Verify());
        Assert.True(logger.Verify());
    }
}
