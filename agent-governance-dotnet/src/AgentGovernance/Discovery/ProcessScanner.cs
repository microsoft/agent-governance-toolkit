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

    // Compiled + ignore-case + bounded match timeout. The inline `(?i)` was
    // replaced with an options flag (equivalent), `Compiled` amortises the
    // first call's setup, and a 250ms ceiling caps any pathological input
    // (e.g. a multi-megabyte process name) so the redactor cannot stall a
    // scan thread. The pattern itself has no alternation/quantifier overlap,
    // so this is defence-in-depth rather than fixing a catastrophic-backtrack.
    private static readonly Regex SecretPattern = new(
        @"(api[_-]?key|token|password|secret|jwt)=\S+",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(250));

    // Hard cap on text fed to the redactor / substring matcher. Process names
    // and executable paths above this length are almost certainly hostile or
    // truncated junk; clipping bounds the linear-time regex pass and protects
    // the per-process dictionary entries from absurd payloads.
    private const int MaxScannedTextLength = 4096;

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
                var name = ClipForScan(process.ProcessName);

                // Two-phase detection: try the cheap name check first; only
                // pay the MainModule access cost when the name alone cannot
                // classify the process. The previous version always called
                // TryGetExecutablePath, which triggers PROCESS_QUERY_INFORMATION
                // for every running PID.
                string? executablePath = null;
                var framework = DetectFramework(name);
                if (framework is null)
                {
                    var path = TryGetExecutablePath(process);
                    if (path is null)
                    {
                        continue;
                    }

                    executablePath = ClipForScan(path);
                    framework = DetectFramework(executablePath);
                    if (framework is null)
                    {
                        continue;
                    }
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
    public static string RedactSensitiveText(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return value;
        }

        try
        {
            return SecretPattern.Replace(value, "$1=<redacted>");
        }
        catch (RegexMatchTimeoutException)
        {
            // Refuse to return the raw input on timeout — the very thing we
            // were trying to redact (a secret-shaped fragment) might be in it.
            return "<scrubbed:regex-timeout>";
        }
    }

    private static string ClipForScan(string value)
    {
        return value.Length <= MaxScannedTextLength
            ? value
            : value[..MaxScannedTextLength];
    }

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
