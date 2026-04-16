// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace AgentGovernance.Mcp;

/// <summary>
/// Threat categories detected in MCP tool metadata.
/// </summary>
public enum McpThreatType
{
    /// <summary>Prompt-injection patterns hidden in tool descriptions.</summary>
    ToolPoisoning,

    /// <summary>Tool name suspiciously similar to a well-known tool.</summary>
    Typosquatting,

    /// <summary>Zero-width characters or homoglyphs hiding instructions.</summary>
    HiddenInstruction,

    /// <summary>Tool definition changed after initial registration.</summary>
    RugPull,

    /// <summary>Schema requests sensitive fields or contains instruction text.</summary>
    SchemaAbuse,

    /// <summary>Duplicate or near-duplicate tool name across MCP servers.</summary>
    CrossServerAttack,

    /// <summary>Description contains prompt-like control language.</summary>
    DescriptionInjection
}

/// <summary>
/// Severity of a detected MCP threat.
/// </summary>
public enum McpSeverity
{
    /// <summary>Low-risk indicator.</summary>
    Low = 0,
    /// <summary>Moderate risk warranting review.</summary>
    Medium = 1,
    /// <summary>High-confidence attack pattern.</summary>
    High = 2,
    /// <summary>Critical threat requiring immediate blocking.</summary>
    Critical = 3
}

/// <summary>
/// A single threat finding from an MCP tool scan.
/// </summary>
public sealed class McpThreat
{
    /// <summary>Category of the threat.</summary>
    public required McpThreatType Type { get; init; }

    /// <summary>Severity level.</summary>
    public required McpSeverity Severity { get; init; }

    /// <summary>Human-readable description of the finding.</summary>
    public required string Description { get; init; }

    /// <summary>Evidence string (e.g., the matched pattern or character).</summary>
    public string? Evidence { get; init; }

    /// <summary>Name of the tool that triggered the finding.</summary>
    public string? ToolName { get; init; }

    /// <summary>Server name associated with the tool.</summary>
    public string? ServerName { get; init; }
}

/// <summary>
/// Minimal MCP tool definition accepted by the scanner.
/// </summary>
public sealed class McpToolDefinition
{
    /// <summary>Tool name as registered in the MCP server.</summary>
    public required string Name { get; init; }

    /// <summary>Tool description provided by the MCP server.</summary>
    public required string Description { get; init; }

    /// <summary>Optional JSON schema string for the tool's input parameters.</summary>
    public string? InputSchema { get; init; }

    /// <summary>Name of the MCP server hosting this tool.</summary>
    public string ServerName { get; init; } = "default";
}

/// <summary>
/// Result of scanning one or more MCP tool definitions.
/// </summary>
public sealed class McpScanResult
{
    /// <summary>Name of the scanned tool.</summary>
    public required string ToolName { get; init; }

    /// <summary>All threats detected.</summary>
    public required IReadOnlyList<McpThreat> Threats { get; init; }

    /// <summary>Aggregate risk score (0–100).</summary>
    public int RiskScore { get; init; }

    /// <summary>True when no threats were detected.</summary>
    public bool Safe => Threats.Count == 0;
}

/// <summary>
/// Stored fingerprint for rug-pull detection.
/// </summary>
public sealed record McpToolFingerprint
{
    /// <summary>Tool name.</summary>
    public required string ToolName { get; init; }
    /// <summary>Server that hosts the tool.</summary>
    public required string ServerName { get; init; }
    /// <summary>SHA-256 hash of the tool description.</summary>
    public required string DescriptionHash { get; init; }
    /// <summary>SHA-256 hash of the tool input schema.</summary>
    public required string SchemaHash { get; init; }
    /// <summary>When the tool was first registered.</summary>
    public DateTimeOffset FirstSeen { get; init; }
    /// <summary>When the tool was last seen.</summary>
    public DateTimeOffset LastSeen { get; set; }
    /// <summary>Fingerprint version (incremented on definition change).</summary>
    public int Version { get; set; } = 1;
}

/// <summary>
/// Scans MCP tool definitions for security threats including tool poisoning,
/// typosquatting, hidden instructions, rug pulls, schema abuse, and cross-server attacks.
/// Thread-safe.
/// </summary>
public sealed class McpSecurityScanner
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);

    private static readonly string[] KnownToolNames =
    [
        "read_file", "write_file", "execute_command", "search", "browse",
        "fetch", "list_directory", "create_file", "delete_file", "run_script",
        "get_weather", "send_email", "query_database", "http_request", "calculator"
    ];

    private static readonly Regex[] PoisoningPatterns =
    [
        Compile(@"<system>"),
        Compile(@"ignore\s+previous"),
        Compile(@"you\s+must"),
        Compile(@"disregard"),
        Compile(@"override"),
        Compile(@"forget\s+(all|your|previous)"),
        Compile(@"new\s+instructions"),
        Compile(@"act\s+as")
    ];

    private static readonly char[] ZeroWidthChars =
    [
        '\u200B', '\u200C', '\u200D', '\uFEFF', '\u00AD', '\u2060', '\u180E'
    ];

    private static readonly Dictionary<char, char> HomoglyphMap = new()
    {
        ['\u0430'] = 'a', ['\u0435'] = 'e', ['\u043E'] = 'o',
        ['\u0440'] = 'p', ['\u0441'] = 'c', ['\u0443'] = 'y',
        ['\u0445'] = 'x', ['\u0456'] = 'i', ['\u0458'] = 'j',
        ['\u03B1'] = 'a', ['\u03BF'] = 'o', ['\u03C1'] = 'p'
    };

    private static readonly Regex[] InstructionPatterns =
    [
        Compile(@"you\s+(should|must|need\s+to)"),
        Compile(@"always\s"),
        Compile(@"never\s"),
        Compile(@"do\s+not\s"),
        Compile(@"important:"),
        Compile(@"warning:"),
        Compile(@"note:"),
        Compile(@"step\s+\d"),
        Compile(@"first,"),
        Compile(@"finally,")
    ];

    private static readonly string[] DescriptionInjectionPhrases =
    [
        "you are", "your task is", "send to", "curl ", "wget ", "post to"
    ];

    private static readonly string[] SensitiveSchemaFields =
    [
        "system_prompt", "secret", "token", "password"
    ];

    private static readonly string[] SchemaInstructionPhrases =
    [
        "ignore previous", "override", "send secrets"
    ];

    private static readonly Regex EncodedPayloadPattern =
        Compile(@"[A-Za-z0-9+/]{40,}={0,2}");

    private static readonly Regex HiddenCommentPattern =
        Compile(@"(?s)<!--.*?-->|\[//\]:\s*#\s*\(.*?\)");

    private const int RugPullDescriptionLength = 500;
    private const int RugPullMinInstructionMatches = 2;

    private readonly object _registryLock = new();
    private readonly Dictionary<string, McpToolFingerprint> _registry = new();

    private static readonly Dictionary<McpSeverity, int> SeverityWeight = new()
    {
        [McpSeverity.Low] = 10,
        [McpSeverity.Medium] = 25,
        [McpSeverity.High] = 50,
        [McpSeverity.Critical] = 80
    };

    /// <summary>
    /// Registers a tool definition for rug-pull tracking.
    /// Call this when a tool is first discovered.
    /// </summary>
    public McpToolFingerprint RegisterTool(McpToolDefinition tool)
    {
        ArgumentNullException.ThrowIfNull(tool);
        var key = $"{tool.ServerName}::{tool.Name}";
        var descHash = ComputeHash(tool.Description);
        var schemaHash = ComputeHash(tool.InputSchema ?? "");

        lock (_registryLock)
        {
            if (_registry.TryGetValue(key, out var existing))
            {
                if (existing.DescriptionHash != descHash || existing.SchemaHash != schemaHash)
                {
                    existing = existing with
                    {
                        DescriptionHash = descHash,
                        SchemaHash = schemaHash,
                        Version = existing.Version + 1
                    };
                    _registry[key] = existing;
                }
                existing.LastSeen = DateTimeOffset.UtcNow;
                return existing;
            }

            var fingerprint = new McpToolFingerprint
            {
                ToolName = tool.Name,
                ServerName = tool.ServerName,
                DescriptionHash = descHash,
                SchemaHash = schemaHash,
                FirstSeen = DateTimeOffset.UtcNow,
                LastSeen = DateTimeOffset.UtcNow
            };
            _registry[key] = fingerprint;
            return fingerprint;
        }
    }

    /// <summary>
    /// Scans a single MCP tool definition for all threat categories.
    /// </summary>
    public McpScanResult Scan(McpToolDefinition tool)
    {
        ArgumentNullException.ThrowIfNull(tool);
        var threats = new List<McpThreat>();

        DetectToolPoisoning(tool, threats);
        DetectTyposquatting(tool, threats);
        DetectHiddenInstructions(tool, threats);
        DetectRugPull(tool, threats);
        DetectSchemaAbuse(tool, threats);
        DetectDescriptionInjection(tool, threats);
        DetectCrossServer(tool, threats);

        var riskScore = Math.Min(100, threats.Sum(t => SeverityWeight[t.Severity]));

        return new McpScanResult
        {
            ToolName = tool.Name,
            Threats = threats.AsReadOnly(),
            RiskScore = riskScore
        };
    }

    /// <summary>
    /// Scans multiple tool definitions.
    /// </summary>
    public IReadOnlyList<McpScanResult> ScanAll(IEnumerable<McpToolDefinition> tools)
    {
        return tools.Select(Scan).ToList().AsReadOnly();
    }

    private static void DetectToolPoisoning(McpToolDefinition tool, List<McpThreat> threats)
    {
        var text = tool.Description;
        foreach (var pattern in PoisoningPatterns)
        {
            var match = pattern.Match(text);
            if (match.Success)
            {
                threats.Add(new McpThreat
                {
                    Type = McpThreatType.ToolPoisoning,
                    Severity = McpSeverity.Critical,
                    Description = $"Prompt-injection pattern detected in tool description: \"{match.Value}\"",
                    Evidence = match.Value,
                    ToolName = tool.Name,
                    ServerName = tool.ServerName
                });
            }
        }

        // Encoded payloads
        if (text.Contains('%') && Uri.TryCreate($"http://x/?q={text}", UriKind.Absolute, out _))
        {
            try
            {
                var decoded = Uri.UnescapeDataString(text);
                if (decoded != text)
                {
                    foreach (var pattern in PoisoningPatterns)
                    {
                        var match = pattern.Match(decoded);
                        if (match.Success)
                        {
                            threats.Add(new McpThreat
                            {
                                Type = McpThreatType.ToolPoisoning,
                                Severity = McpSeverity.Critical,
                                Description = $"Encoded prompt-injection detected after URL-decoding: \"{match.Value}\"",
                                Evidence = match.Value,
                                ToolName = tool.Name,
                                ServerName = tool.ServerName
                            });
                        }
                    }
                }
            }
            catch
            {
                // Malformed encoding — not a threat by itself.
            }
        }

        // Encoded payloads (base64-like) or hidden comments
        if (EncodedPayloadPattern.IsMatch(text) || HiddenCommentPattern.IsMatch(text))
        {
            var lower = text.ToLowerInvariant();
            if (lower.Contains("ignore previous") || lower.Contains("override the instructions"))
            {
                threats.Add(new McpThreat
                {
                    Type = McpThreatType.ToolPoisoning,
                    Severity = McpSeverity.Critical,
                    Description = "Tool poisoning indicators detected (encoded payload or hidden comment with override language)",
                    ToolName = tool.Name,
                    ServerName = tool.ServerName
                });
            }
        }
    }

    private static void DetectTyposquatting(McpToolDefinition tool, List<McpThreat> threats)
    {
        var name = tool.Name.ToLowerInvariant();
        foreach (var known in KnownToolNames)
        {
            if (name == known) continue;
            var dist = LevenshteinDistance(name, known);
            if (dist is > 0 and <= 2)
            {
                threats.Add(new McpThreat
                {
                    Type = McpThreatType.Typosquatting,
                    Severity = dist == 1 ? McpSeverity.High : McpSeverity.Medium,
                    Description = $"Tool name \"{tool.Name}\" is suspiciously similar to known tool \"{known}\" (edit distance {dist})",
                    Evidence = known,
                    ToolName = tool.Name,
                    ServerName = tool.ServerName
                });
            }
        }
    }

    private static void DetectHiddenInstructions(McpToolDefinition tool, List<McpThreat> threats)
    {
        var text = tool.Description;

        // Zero-width characters
        foreach (var zwc in ZeroWidthChars)
        {
            if (text.Contains(zwc))
            {
                threats.Add(new McpThreat
                {
                    Type = McpThreatType.HiddenInstruction,
                    Severity = McpSeverity.High,
                    Description = $"Zero-width character U+{(int)zwc:X4} found in description",
                    Evidence = $"U+{(int)zwc:X4}",
                    ToolName = tool.Name,
                    ServerName = tool.ServerName
                });
                break;
            }
        }

        // Homoglyphs
        foreach (var ch in text)
        {
            if (HomoglyphMap.TryGetValue(ch, out var latin))
            {
                threats.Add(new McpThreat
                {
                    Type = McpThreatType.HiddenInstruction,
                    Severity = McpSeverity.High,
                    Description = $"Homoglyph character detected: \"{ch}\" looks like \"{latin}\" but is a different Unicode code point",
                    Evidence = ch.ToString(),
                    ToolName = tool.Name,
                    ServerName = tool.ServerName
                });
                break;
            }
        }
    }

    private void DetectRugPull(McpToolDefinition tool, List<McpThreat> threats)
    {
        // Check fingerprint registry for definition changes
        var key = $"{tool.ServerName}::{tool.Name}";
        lock (_registryLock)
        {
            if (_registry.TryGetValue(key, out var existing))
            {
                var descHash = ComputeHash(tool.Description);
                var schemaHash = ComputeHash(tool.InputSchema ?? "");
                var changed = new List<string>();
                if (existing.DescriptionHash != descHash) changed.Add("description");
                if (existing.SchemaHash != schemaHash) changed.Add("schema");

                if (changed.Count > 0)
                {
                    threats.Add(new McpThreat
                    {
                        Type = McpThreatType.RugPull,
                        Severity = McpSeverity.Critical,
                        Description = $"Tool definition changed since registration (fields: {string.Join(", ", changed)}, version: {existing.Version})",
                        Evidence = string.Join(",", changed),
                        ToolName = tool.Name,
                        ServerName = tool.ServerName
                    });
                }
            }
        }

        // Long description with instruction patterns
        var text = tool.Description;
        if (text.Length <= RugPullDescriptionLength) return;

        var instructionMatches = InstructionPatterns.Count(p => p.IsMatch(text));
        if (instructionMatches >= RugPullMinInstructionMatches)
        {
            threats.Add(new McpThreat
            {
                Type = McpThreatType.RugPull,
                Severity = McpSeverity.Medium,
                Description = $"Unusually long description ({text.Length} chars) with {instructionMatches} instruction-like patterns — possible rug-pull payload",
                Evidence = $"length={text.Length}, instruction_patterns={instructionMatches}",
                ToolName = tool.Name,
                ServerName = tool.ServerName
            });
        }
    }

    private static void DetectSchemaAbuse(McpToolDefinition tool, List<McpThreat> threats)
    {
        if (string.IsNullOrEmpty(tool.InputSchema)) return;

        var schemaLower = tool.InputSchema.ToLowerInvariant();

        // Sensitive fields in schema
        foreach (var field in SensitiveSchemaFields)
        {
            if (schemaLower.Contains($"\"{field}\""))
            {
                threats.Add(new McpThreat
                {
                    Type = McpThreatType.SchemaAbuse,
                    Severity = McpSeverity.High,
                    Description = $"Schema references sensitive field \"{field}\"",
                    Evidence = field,
                    ToolName = tool.Name,
                    ServerName = tool.ServerName
                });
            }
        }

        // Instruction text buried in schema values
        foreach (var phrase in SchemaInstructionPhrases)
        {
            if (schemaLower.Contains(phrase))
            {
                threats.Add(new McpThreat
                {
                    Type = McpThreatType.SchemaAbuse,
                    Severity = McpSeverity.Critical,
                    Description = "Schema contains instruction-bearing text",
                    Evidence = phrase,
                    ToolName = tool.Name,
                    ServerName = tool.ServerName
                });
                break;
            }
        }
    }

    private static void DetectDescriptionInjection(McpToolDefinition tool, List<McpThreat> threats)
    {
        var lower = tool.Description.ToLowerInvariant();
        if (!DescriptionInjectionPhrases.Any(p => lower.Contains(p))) return;

        threats.Add(new McpThreat
        {
            Type = McpThreatType.DescriptionInjection,
            Severity = McpSeverity.Medium,
            Description = "Description contains prompt-like control language",
            ToolName = tool.Name,
            ServerName = tool.ServerName
        });
    }

    private void DetectCrossServer(McpToolDefinition tool, List<McpThreat> threats)
    {
        lock (_registryLock)
        {
            foreach (var fingerprint in _registry.Values)
            {
                if (fingerprint.ServerName == tool.ServerName) continue;

                if (fingerprint.ToolName == tool.Name)
                {
                    threats.Add(new McpThreat
                    {
                        Type = McpThreatType.CrossServerAttack,
                        Severity = McpSeverity.Medium,
                        Description = $"Duplicate tool name \"{tool.Name}\" exists on server \"{fingerprint.ServerName}\"",
                        Evidence = fingerprint.ServerName,
                        ToolName = tool.Name,
                        ServerName = tool.ServerName
                    });
                    continue;
                }

                if (LevenshteinDistance(fingerprint.ToolName, tool.Name) <= 2)
                {
                    threats.Add(new McpThreat
                    {
                        Type = McpThreatType.CrossServerAttack,
                        Severity = McpSeverity.Medium,
                        Description = $"Potential typosquatting: \"{tool.Name}\" is similar to \"{fingerprint.ToolName}\" on server \"{fingerprint.ServerName}\"",
                        Evidence = fingerprint.ToolName,
                        ToolName = tool.Name,
                        ServerName = tool.ServerName
                    });
                }
            }
        }
    }

    internal static int LevenshteinDistance(string a, string b)
    {
        var m = a.Length;
        var n = b.Length;
        var costs = new int[n + 1];
        for (var j = 0; j <= n; j++) costs[j] = j;

        for (var i = 1; i <= m; i++)
        {
            var prev = costs[0];
            costs[0] = i;
            for (var j = 1; j <= n; j++)
            {
                var old = costs[j];
                var sub = a[i - 1] == b[j - 1] ? prev : prev + 1;
                costs[j] = Math.Min(Math.Min(costs[j] + 1, costs[j - 1] + 1), sub);
                prev = old;
            }
        }
        return costs[n];
    }

    private static string ComputeHash(string input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static Regex Compile(string pattern) =>
        new(pattern, RegexOptions.Compiled | RegexOptions.IgnoreCase, RegexTimeout);
}
