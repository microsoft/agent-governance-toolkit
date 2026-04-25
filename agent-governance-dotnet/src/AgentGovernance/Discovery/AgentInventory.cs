// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace AgentGovernance.Discovery;

/// <summary>
/// Persistent in-memory inventory of discovered agents with deduplication.
/// </summary>
public sealed class AgentInventory
{
    private readonly Dictionary<string, DiscoveredAgent> _agents = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    /// <summary>
    /// Read-only snapshot of the inventory.
    /// </summary>
    public IReadOnlyList<DiscoveredAgent> Agents
    {
        get
        {
            lock (_gate)
            {
                return _agents.Values.ToArray();
            }
        }
    }

    /// <summary>
    /// Number of logical agents in the inventory.
    /// </summary>
    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _agents.Count;
            }
        }
    }

    /// <summary>
    /// Ingest a scanner result into the inventory.
    /// </summary>
    public void Ingest(ScanResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        lock (_gate)
        {
            foreach (var candidate in result.Agents)
            {
                if (!_agents.TryGetValue(candidate.Fingerprint, out var existing))
                {
                    _agents[candidate.Fingerprint] = candidate;
                    continue;
                }

                Merge(existing, candidate);
            }
        }
    }

    private static void Merge(DiscoveredAgent existing, DiscoveredAgent incoming)
    {
        if (string.IsNullOrWhiteSpace(existing.Did))
        {
            existing.Did = incoming.Did;
        }

        if (string.IsNullOrWhiteSpace(existing.Owner))
        {
            existing.Owner = incoming.Owner;
        }

        if (string.IsNullOrWhiteSpace(existing.Description))
        {
            existing.Description = incoming.Description;
        }

        if (string.Equals(existing.AgentType, "unknown", StringComparison.OrdinalIgnoreCase) && !string.Equals(incoming.AgentType, "unknown", StringComparison.OrdinalIgnoreCase))
        {
            existing.AgentType = incoming.AgentType;
        }

        foreach (var pair in incoming.MergeKeys)
        {
            existing.MergeKeys[pair.Key] = pair.Value;
        }

        foreach (var pair in incoming.Tags)
        {
            existing.Tags[pair.Key] = pair.Value;
        }

        foreach (var evidence in incoming.Evidence)
        {
            existing.AddEvidence(evidence);
        }
    }
}
