// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace AgentGovernance.Discovery;

/// <summary>
/// Scores risk for discovered agents that are not governed.
/// </summary>
public sealed class RiskScorer
{
    /// <summary>
    /// Score a discovered agent.
    /// </summary>
    public RiskAssessment Score(DiscoveredAgent agent)
    {
        ArgumentNullException.ThrowIfNull(agent);

        var score = 10.0;
        var factors = new List<string>();

        if (string.IsNullOrWhiteSpace(agent.Did))
        {
            score += 25;
            factors.Add("No governed identity");
        }

        if (string.IsNullOrWhiteSpace(agent.Owner))
        {
            score += 20;
            factors.Add("No owner assigned");
        }

        if (agent.Evidence.Any(evidence => evidence.Basis == DetectionBasis.Process))
        {
            score += 20;
            factors.Add("Live process detected");
        }

        if (agent.Confidence >= 0.9)
        {
            score += 15;
            factors.Add("High-confidence discovery");
        }

        if (agent.Evidence.Count >= 2)
        {
            score += 10;
            factors.Add("Multiple corroborating observations");
        }

        if (string.Equals(agent.AgentType, "mcp", StringComparison.OrdinalIgnoreCase))
        {
            score += 10;
            factors.Add("Network-exposed MCP surface");
        }

        var bounded = Math.Min(100, score);
        var level = bounded switch
        {
            >= 80 => RiskLevel.Critical,
            >= 60 => RiskLevel.High,
            >= 40 => RiskLevel.Medium,
            >= 20 => RiskLevel.Low,
            _ => RiskLevel.Info
        };

        return new RiskAssessment
        {
            Level = level,
            Score = bounded,
            Factors = factors
        };
    }
}
