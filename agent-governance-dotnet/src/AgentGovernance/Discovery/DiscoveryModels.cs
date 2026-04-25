// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Text;

namespace AgentGovernance.Discovery;

/// <summary>
/// Basis for a discovery finding.
/// </summary>
public enum DetectionBasis
{
    /// <summary>Detected from a running process.</summary>
    Process,
    /// <summary>Detected from a configuration file.</summary>
    ConfigFile,
    /// <summary>Detected from repository contents.</summary>
    Repository,
    /// <summary>Manual import.</summary>
    Manual
}

/// <summary>
/// Governance state of a discovered agent.
/// </summary>
public enum AgentStatus
{
    /// <summary>Registered in governance.</summary>
    Registered,
    /// <summary>Not found in governance.</summary>
    Unregistered,
    /// <summary>Shadow agent operating outside governance.</summary>
    Shadow,
    /// <summary>Unknown state.</summary>
    Unknown
}

/// <summary>
/// Risk level assigned to a discovered or shadow agent.
/// </summary>
public enum RiskLevel
{
    /// <summary>Informational only.</summary>
    Info,
    /// <summary>Low risk.</summary>
    Low,
    /// <summary>Medium risk.</summary>
    Medium,
    /// <summary>High risk.</summary>
    High,
    /// <summary>Critical risk.</summary>
    Critical
}

/// <summary>
/// Evidence supporting a discovery finding.
/// </summary>
public sealed class Evidence
{
    /// <summary>Scanner that produced the evidence.</summary>
    public required string Scanner { get; init; }

    /// <summary>Detection basis.</summary>
    public DetectionBasis Basis { get; init; }

    /// <summary>Source location such as a path or PID.</summary>
    public required string Source { get; init; }

    /// <summary>Human-readable detail.</summary>
    public required string Detail { get; init; }

    /// <summary>Structured scanner metadata.</summary>
    public Dictionary<string, string> RawData { get; init; } = new(StringComparer.Ordinal);

    /// <summary>Confidence from 0-1.</summary>
    public double Confidence { get; init; }

    /// <summary>When the evidence was observed.</summary>
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;
}

/// <summary>
/// Logical agent record deduplicated across scanners.
/// </summary>
public sealed class DiscoveredAgent
{
    /// <summary>Stable deduplication key.</summary>
    public required string Fingerprint { get; init; }

    /// <summary>Best guess name for the agent.</summary>
    public required string Name { get; set; }

    /// <summary>Detected framework or agent type.</summary>
    public string AgentType { get; set; } = "unknown";

    /// <summary>Optional description.</summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>Optional DID.</summary>
    public string? Did { get; set; }

    /// <summary>Optional owner.</summary>
    public string? Owner { get; set; }

    /// <summary>Governance status.</summary>
    public AgentStatus Status { get; set; } = AgentStatus.Unknown;

    /// <summary>Evidence chain.</summary>
    public List<Evidence> Evidence { get; } = [];

    /// <summary>Aggregate confidence.</summary>
    public double Confidence { get; private set; }

    /// <summary>Stable merge keys used to compute the fingerprint.</summary>
    public Dictionary<string, string> MergeKeys { get; } = new(StringComparer.Ordinal);

    /// <summary>First seen timestamp.</summary>
    public DateTime FirstSeenAt { get; private set; } = DateTime.UtcNow;

    /// <summary>Last seen timestamp.</summary>
    public DateTime LastSeenAt { get; private set; } = DateTime.UtcNow;

    /// <summary>Additional tags.</summary>
    public Dictionary<string, string> Tags { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Add a new piece of evidence and update rollups.
    /// </summary>
    public void AddEvidence(Evidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        Evidence.Add(evidence);
        Confidence = Math.Max(Confidence, evidence.Confidence);
        FirstSeenAt = evidence.Timestamp < FirstSeenAt ? evidence.Timestamp : FirstSeenAt;
        LastSeenAt = evidence.Timestamp > LastSeenAt ? evidence.Timestamp : LastSeenAt;
    }

    /// <summary>
    /// Compute a stable fingerprint from merge keys.
    /// </summary>
    public static string ComputeFingerprint(IReadOnlyDictionary<string, string> mergeKeys)
    {
        ArgumentNullException.ThrowIfNull(mergeKeys);
        var canonical = string.Join("|", mergeKeys.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => $"{pair.Key}={pair.Value}"));
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Convert.ToHexString(bytes).ToLowerInvariant()[..16];
    }
}

/// <summary>
/// Output from a single scanner pass.
/// </summary>
public sealed class ScanResult
{
    /// <summary>Scanner name.</summary>
    public required string ScannerName { get; init; }

    /// <summary>Discovered agents.</summary>
    public List<DiscoveredAgent> Agents { get; } = [];

    /// <summary>Scanner errors.</summary>
    public List<string> Errors { get; } = [];

    /// <summary>UTC scan start.</summary>
    public DateTime StartedAt { get; init; } = DateTime.UtcNow;

    /// <summary>UTC scan completion.</summary>
    public DateTime? CompletedAt { get; set; }

    /// <summary>Number of scanned targets.</summary>
    public int ScannedTargets { get; set; }
}

/// <summary>
/// Risk assessment for a discovered agent.
/// </summary>
public sealed class RiskAssessment
{
    /// <summary>Risk level.</summary>
    public RiskLevel Level { get; init; }

    /// <summary>Score from 0-100.</summary>
    public double Score { get; init; }

    /// <summary>Contributing factors.</summary>
    public IReadOnlyList<string> Factors { get; init; } = Array.Empty<string>();

    /// <summary>UTC timestamp of the assessment.</summary>
    public DateTime AssessedAt { get; init; } = DateTime.UtcNow;
}

/// <summary>
/// Shadow agent result from reconciliation.
/// </summary>
public sealed class ShadowAgent
{
    /// <summary>Discovered agent.</summary>
    public required DiscoveredAgent Agent { get; init; }

    /// <summary>Risk assessment.</summary>
    public RiskAssessment? Risk { get; init; }

    /// <summary>Recommended next actions.</summary>
    public IReadOnlyList<string> RecommendedActions { get; init; } = Array.Empty<string>();
}
