// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentGovernance.Discovery;
using Xunit;

namespace AgentGovernance.Tests;

public class ShadowDiscoveryTests
{
    [Fact]
    public void Inventory_Ingest_DeduplicatesByFingerprint()
    {
        var fingerprint = DiscoveredAgent.ComputeFingerprint(new Dictionary<string, string>
        {
            ["path"] = "repo\\agentmesh.yaml",
            ["framework"] = "agentmesh"
        });

        var inventory = new AgentInventory();
        var result = new ScanResult { ScannerName = "config" };

        var first = new DiscoveredAgent
        {
            Fingerprint = fingerprint,
            Name = "agentmesh",
            AgentType = "agentmesh"
        };
        first.AddEvidence(new Evidence
        {
            Scanner = "config",
            Basis = DetectionBasis.ConfigFile,
            Source = "repo\\agentmesh.yaml",
            Detail = "first",
            Confidence = 0.7
        });

        var second = new DiscoveredAgent
        {
            Fingerprint = fingerprint,
            Name = "agentmesh",
            AgentType = "agentmesh"
        };
        second.AddEvidence(new Evidence
        {
            Scanner = "config",
            Basis = DetectionBasis.ConfigFile,
            Source = "repo\\copy.yaml",
            Detail = "second",
            Confidence = 0.9
        });

        result.Agents.Add(first);
        result.Agents.Add(second);
        inventory.Ingest(result);

        Assert.Equal(1, inventory.Count);
        Assert.Equal(2, inventory.Agents[0].Evidence.Count);
        Assert.Equal(0.9, inventory.Agents[0].Confidence);
    }

    [Fact]
    public void Reconciler_ProducesShadowAgents_ForUnknownDids()
    {
        var inventory = new AgentInventory();
        var scan = new ScanResult { ScannerName = "config" };
        var agent = new DiscoveredAgent
        {
            Fingerprint = DiscoveredAgent.ComputeFingerprint(new Dictionary<string, string>
            {
                ["path"] = "repo\\mcp.json",
                ["framework"] = "mcp"
            }),
            Name = "mcp",
            AgentType = "mcp"
        };
        agent.AddEvidence(new Evidence
        {
            Scanner = "config",
            Basis = DetectionBasis.ConfigFile,
            Source = "repo\\mcp.json",
            Detail = "mcp config",
            Confidence = 0.95
        });
        scan.Agents.Add(agent);
        inventory.Ingest(scan);

        var reconciler = new Reconciler(inventory, new StaticRegistryProvider([]));
        var shadows = reconciler.Reconcile();

        Assert.Single(shadows);
        Assert.Equal(AgentStatus.Shadow, shadows[0].Agent.Status);
        Assert.NotNull(shadows[0].Risk);
        Assert.NotEmpty(shadows[0].RecommendedActions);
    }

    [Fact]
    public void RiskScorer_HighlightsMissingOwnerAndIdentity()
    {
        var agent = new DiscoveredAgent
        {
            Fingerprint = "abcd1234",
            Name = "shadow-agent",
            AgentType = "mcp"
        };
        agent.AddEvidence(new Evidence
        {
            Scanner = "process",
            Basis = DetectionBasis.Process,
            Source = "42",
            Detail = "process",
            Confidence = 0.95
        });

        var risk = new RiskScorer().Score(agent);

        Assert.True(risk.Score >= 60);
        Assert.True(risk.Level >= RiskLevel.High);
        Assert.Contains("No governed identity", risk.Factors);
    }

    [Fact]
    public void ConfigScanner_DetectsKnownConfigFiles()
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), $"agt-config-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempRoot);

        try
        {
            var configPath = Path.Combine(tempRoot, "agentmesh.yaml");
            File.WriteAllText(configPath, "name: test-agent", System.Text.Encoding.UTF8);

            var result = new ConfigScanner().Scan([tempRoot]);

            Assert.Single(result.Agents);
            Assert.Equal("agentmesh", result.Agents[0].AgentType);
        }
        finally
        {
            Directory.Delete(tempRoot, recursive: true);
        }
    }

    [Fact]
    public void ProcessScanner_RedactsSecretLikeFragments()
    {
        var redacted = ProcessScanner.RedactSensitiveText("token=abc123 password=hunter2");

        Assert.DoesNotContain("abc123", redacted);
        Assert.DoesNotContain("hunter2", redacted);
        Assert.Contains("<redacted>", redacted);
    }

    [Fact]
    public void ProcessScanner_RedactsSecretsInsideLongPayload()
    {
        // 1MiB of junk with a secret-shaped fragment in the middle. The
        // compiled regex with a 250ms match timeout should still find and
        // redact the secret without stalling.
        var prefix = new string('x', 512 * 1024);
        var suffix = new string('y', 512 * 1024);
        var payload = $"{prefix} api_key=topsecret {suffix}";

        var redacted = ProcessScanner.RedactSensitiveText(payload);

        Assert.DoesNotContain("topsecret", redacted);
        Assert.Contains("api_key=<redacted>", redacted);
    }
}
