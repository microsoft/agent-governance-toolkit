// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics;
using System.Text.RegularExpressions;

namespace AgentGovernance.Discovery;

/// <summary>
/// Read-only process scanner for common agent framework indicators.
/// </summary>
public sealed class ProcessScanner
{
    private static readonly Dictionary<string, string> Indicators = new(StringComparer.OrdinalIgnoreCase)
    {
        ["langchain"] = "langchain",
        ["crewai"] = "crewai",
        ["autogen"] = "autogen",
        ["semantic-kernel"] = "semantic-kernel",
        ["semantic kernel"] = "semantic-kernel",
        ["agentmesh"] = "agentmesh",
        ["agent-os"] = "agent-os",
        ["mcp"] = "mcp",
        ["llamaindex"] = "llamaindex",
        ["haystack"] = "haystack",
        ["pydanticai"] = "pydanticai",
        ["google-adk"] = "google-adk"
    };

    private static readonly Regex SecretPattern = new(@"(?i)(api[_-]?key|token|password|secret|jwt)=\S+", RegexOptions.CultureInvariant);

    /// <summary>
    /// Scan currently running processes.
    /// </summary>
    public ScanResult Scan()
    {
        var result = new ScanResult
        {
            ScannerName = "process"
        };

        foreach (var process in Process.GetProcesses())
        {
            result.ScannedTargets++;

            try
            {
                var name = process.ProcessName;
                var executablePath = TryGetExecutablePath(process);
                var framework = DetectFramework($"{name} {executablePath}");
                if (framework is null)
                {
                    continue;
                }

                var source = process.Id.ToString(System.Globalization.CultureInfo.InvariantCulture);
                var mergeKeys = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["pid"] = source,
                    ["framework"] = framework
                };

                var agent = new DiscoveredAgent
                {
                    Fingerprint = DiscoveredAgent.ComputeFingerprint(mergeKeys),
                    Name = name,
                    AgentType = framework,
                    Description = $"Running {framework} process detected."
                };

                foreach (var pair in mergeKeys)
                {
                    agent.MergeKeys[pair.Key] = pair.Value;
                }

                agent.AddEvidence(new Evidence
                {
                    Scanner = "process",
                    Basis = DetectionBasis.Process,
                    Source = source,
                    Detail = $"Detected {framework} process.",
                    Confidence = 0.9,
                    RawData = new Dictionary<string, string>(StringComparer.Ordinal)
                    {
                        ["process_name"] = RedactSensitiveText(name),
                        ["path"] = RedactSensitiveText(executablePath ?? string.Empty)
                    }
                });

                result.Agents.Add(agent);
            }
            catch
            {
                // Keep scanning; process access is best-effort only.
            }
            finally
            {
                process.Dispose();
            }
        }

        result.CompletedAt = DateTime.UtcNow;
        return result;
    }

    /// <summary>
    /// Redact obvious secret-like key/value fragments from captured process metadata.
    /// </summary>
    public static string RedactSensitiveText(string value) => SecretPattern.Replace(value, "$1=<redacted>");

    private static string? DetectFramework(string value)
    {
        foreach (var pair in Indicators)
        {
            if (value.Contains(pair.Key, StringComparison.OrdinalIgnoreCase))
            {
                return pair.Value;
            }
        }

        return null;
    }

    private static string? TryGetExecutablePath(Process process)
    {
        try
        {
            return process.MainModule?.FileName;
        }
        catch
        {
            return null;
        }
    }
}
