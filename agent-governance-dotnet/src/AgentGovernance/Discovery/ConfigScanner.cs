// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text;

namespace AgentGovernance.Discovery;

/// <summary>
/// Read-only scanner for agent-related configuration artifacts.
/// </summary>
public sealed class ConfigScanner
{
    private static readonly string[] KnownConfigNames =
    [
        "agentmesh.yaml",
        "crewai.yaml",
        "mcp.json",
        "docker-compose.yml",
        "compose.yml",
        "package.json",
        "pyproject.toml",
        "requirements.txt"
    ];

    private static readonly Dictionary<string, string> FrameworkIndicators = new(StringComparer.OrdinalIgnoreCase)
    {
        ["langchain"] = "langchain",
        ["crewai"] = "crewai",
        ["autogen"] = "autogen",
        ["semantic kernel"] = "semantic-kernel",
        ["semantic-kernel"] = "semantic-kernel",
        ["agentmesh"] = "agentmesh",
        ["agent os"] = "agent-os",
        ["mcp"] = "mcp",
        ["llamaindex"] = "llamaindex",
        ["haystack"] = "haystack",
        ["pydanticai"] = "pydanticai",
        ["google-adk"] = "google-adk"
    };

    /// <summary>
    /// Scan directories for agent configuration files.
    /// </summary>
    public ScanResult Scan(IEnumerable<string> paths)
    {
        ArgumentNullException.ThrowIfNull(paths);

        var result = new ScanResult
        {
            ScannerName = "config"
        };

        foreach (var root in paths.Where(path => !string.IsNullOrWhiteSpace(path)))
        {
            if (!Directory.Exists(root))
            {
                result.Errors.Add($"Directory not found: {root}");
                continue;
            }

            foreach (var file in EnumerateFilesSafe(root))
            {
                result.ScannedTargets++;
                if (!KnownConfigNames.Contains(Path.GetFileName(file), StringComparer.OrdinalIgnoreCase))
                {
                    continue;
                }

                var content = TryReadText(file);
                var framework = DetectFramework(file, content);
                if (framework is null)
                {
                    continue;
                }

                var mergeKeys = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["path"] = file,
                    ["framework"] = framework
                };

                var agent = new DiscoveredAgent
                {
                    Fingerprint = DiscoveredAgent.ComputeFingerprint(mergeKeys),
                    Name = Path.GetFileNameWithoutExtension(file),
                    AgentType = framework,
                    Description = $"Configuration artifact detected for {framework}."
                };

                foreach (var pair in mergeKeys)
                {
                    agent.MergeKeys[pair.Key] = pair.Value;
                }

                agent.AddEvidence(new Evidence
                {
                    Scanner = "config",
                    Basis = DetectionBasis.ConfigFile,
                    Source = file,
                    Detail = $"Detected {framework} indicator in configuration.",
                    Confidence = 0.8,
                    RawData = new Dictionary<string, string>(StringComparer.Ordinal)
                    {
                        ["file_name"] = Path.GetFileName(file),
                        ["framework"] = framework
                    }
                });

                result.Agents.Add(agent);
            }
        }

        result.CompletedAt = DateTime.UtcNow;
        return result;
    }

    private static IEnumerable<string> EnumerateFilesSafe(string root)
    {
        var pending = new Stack<string>();
        pending.Push(root);

        while (pending.Count > 0)
        {
            var current = pending.Pop();
            IEnumerable<string> directories = [];
            IEnumerable<string> files = [];

            try
            {
                directories = Directory.EnumerateDirectories(current);
                files = Directory.EnumerateFiles(current);
            }
            catch
            {
                continue;
            }

            foreach (var file in files)
            {
                yield return file;
            }

            foreach (var directory in directories)
            {
                pending.Push(directory);
            }
        }
    }

    private static string? TryReadText(string path)
    {
        try
        {
            return File.ReadAllText(path, Encoding.UTF8);
        }
        catch
        {
            return null;
        }
    }

    private static string? DetectFramework(string path, string? content)
    {
        var fileName = Path.GetFileName(path);
        if (fileName.Equals("mcp.json", StringComparison.OrdinalIgnoreCase))
        {
            return "mcp";
        }

        if (fileName.Equals("agentmesh.yaml", StringComparison.OrdinalIgnoreCase))
        {
            return "agentmesh";
        }

        if (fileName.Equals("crewai.yaml", StringComparison.OrdinalIgnoreCase))
        {
            return "crewai";
        }

        if (string.IsNullOrWhiteSpace(content))
        {
            return null;
        }

        foreach (var pair in FrameworkIndicators)
        {
            if (content.Contains(pair.Key, StringComparison.OrdinalIgnoreCase))
            {
                return pair.Value;
            }
        }

        return null;
    }
}
