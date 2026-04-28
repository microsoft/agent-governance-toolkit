// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using AgentGovernance.Trust;
using Xunit;

namespace AgentGovernance.Tests;

public class FileTrustStoreTests : IDisposable
{
    private readonly string _tempFile;

    public FileTrustStoreTests()
    {
        _tempFile = Path.Combine(Path.GetTempPath(), $"trust-store-test-{Guid.NewGuid():N}.json");
    }

    [Fact]
    public void GetScore_UnknownAgent_ReturnsDefault()
    {
        using var store = new FileTrustStore(_tempFile, defaultScore: 500);
        Assert.Equal(500, store.GetScore("did:agentmesh:unknown"));
    }

    [Fact]
    public void SetScore_And_GetScore_RoundTrips()
    {
        using var store = new FileTrustStore(_tempFile, decayRate: 0);
        store.SetScore("did:agentmesh:agent1", 850);
        Assert.Equal(850, store.GetScore("did:agentmesh:agent1"));
    }

    [Fact]
    public void SetScore_ClampsToRange()
    {
        using var store = new FileTrustStore(_tempFile, decayRate: 0);
        store.SetScore("did:agentmesh:a", 1500);
        Assert.Equal(1000, store.GetScore("did:agentmesh:a"));

        store.SetScore("did:agentmesh:b", -100);
        Assert.Equal(0, store.GetScore("did:agentmesh:b"));
    }

    [Fact]
    public void RecordPositiveSignal_IncreasesScore()
    {
        using var store = new FileTrustStore(_tempFile, defaultScore: 500, decayRate: 0);
        store.SetScore("did:agentmesh:agent1", 500);
        store.RecordPositiveSignal("did:agentmesh:agent1", boost: 25);
        Assert.Equal(525, store.GetScore("did:agentmesh:agent1"));
    }

    [Fact]
    public void RecordNegativeSignal_DecreasesScore()
    {
        using var store = new FileTrustStore(_tempFile, defaultScore: 500, decayRate: 0);
        store.SetScore("did:agentmesh:agent1", 500);
        store.RecordNegativeSignal("did:agentmesh:agent1", penalty: 100);
        Assert.Equal(400, store.GetScore("did:agentmesh:agent1"));
    }

    [Fact]
    public void RecordNegativeSignal_DoesNotGoBelowZero()
    {
        using var store = new FileTrustStore(_tempFile, defaultScore: 50, decayRate: 0);
        store.SetScore("did:agentmesh:agent1", 50);
        store.RecordNegativeSignal("did:agentmesh:agent1", penalty: 200);
        Assert.Equal(0, store.GetScore("did:agentmesh:agent1"));
    }

    [Fact]
    public void PersistsToFile_And_ReloadsCorrectly()
    {
        // Write
        using (var store = new FileTrustStore(_tempFile, decayRate: 0))
        {
            store.SetScore("did:agentmesh:agent1", 750);
            store.SetScore("did:agentmesh:agent2", 300);
        }

        // Read back in a new instance
        using (var store = new FileTrustStore(_tempFile, decayRate: 0))
        {
            Assert.Equal(750, store.GetScore("did:agentmesh:agent1"));
            Assert.Equal(300, store.GetScore("did:agentmesh:agent2"));
        }
    }

    [Fact]
    public void GetAllScores_ReturnsAllTrackedAgents()
    {
        using var store = new FileTrustStore(_tempFile, decayRate: 0);
        store.SetScore("did:agentmesh:a", 100);
        store.SetScore("did:agentmesh:b", 200);
        store.SetScore("did:agentmesh:c", 300);

        var all = store.GetAllScores();
        Assert.Equal(3, all.Count);
        Assert.Equal(100, all["did:agentmesh:a"]);
        Assert.Equal(200, all["did:agentmesh:b"]);
        Assert.Equal(300, all["did:agentmesh:c"]);
    }

    [Fact]
    public void Count_ReturnsTrackedAgentCount()
    {
        using var store = new FileTrustStore(_tempFile);
        Assert.Equal(0, store.Count);

        store.SetScore("did:agentmesh:a", 500);
        store.SetScore("did:agentmesh:b", 600);
        Assert.Equal(2, store.Count);
    }

    [Fact]
    public void Remove_RemovesAgent()
    {
        using var store = new FileTrustStore(_tempFile, decayRate: 0);
        store.SetScore("did:agentmesh:agent1", 750);
        Assert.True(store.Remove("did:agentmesh:agent1"));
        Assert.Equal(500, store.GetScore("did:agentmesh:agent1")); // Falls back to default
    }

    [Fact]
    public void Remove_UnknownAgent_ReturnsFalse()
    {
        using var store = new FileTrustStore(_tempFile);
        Assert.False(store.Remove("did:agentmesh:unknown"));
    }

    [Fact]
    public void CorruptedFile_StartsClean()
    {
        File.WriteAllText(_tempFile, "NOT VALID JSON {{{");
        using var store = new FileTrustStore(_tempFile, defaultScore: 500);
        Assert.Equal(500, store.GetScore("did:agentmesh:any"));
        Assert.Equal(0, store.Count);
    }

    public void Dispose()
    {
        try { File.Delete(_tempFile); } catch { }
    }
}
