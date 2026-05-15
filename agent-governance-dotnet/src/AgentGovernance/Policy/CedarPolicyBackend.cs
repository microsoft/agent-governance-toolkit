// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AgentGovernance.Policy;

/// <summary>
/// Evaluation mode for Cedar policies.
/// </summary>
public enum CedarEvaluationMode
{
    /// <summary>Try CLI first, then built-in fallback.</summary>
    Auto,
    /// <summary>Use the Cedar CLI.</summary>
    Cli,
    /// <summary>Use the built-in evaluator.</summary>
    Builtin
}

/// <summary>
/// Cedar external policy backend.
/// </summary>
public sealed class CedarPolicyBackend : IExternalPolicyBackend
{
    private static readonly Regex StatementRegex = new(@"(?<effect>permit|forbid)\s*\((?<body>.*?)\)\s*;", RegexOptions.Singleline | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
    private static readonly Regex ActionConstraintRegex = new(@"action\s*==\s*(?<action>Action::""[^""]+"")", RegexOptions.CultureInvariant);

    private readonly string? _policyContent;
    private readonly string? _policyPath;
    private readonly CedarEvaluationMode _mode;
    private readonly TimeSpan _timeout;

    /// <summary>
    /// Initialize the Cedar backend.
    /// </summary>
    public CedarPolicyBackend(
        string? policyContent = null,
        string? policyPath = null,
        CedarEvaluationMode mode = CedarEvaluationMode.Auto,
        TimeSpan? timeout = null)
    {
        _policyContent = policyContent;
        _policyPath = policyPath;
        _mode = mode;
        _timeout = timeout ?? TimeSpan.FromSeconds(5);
    }

    /// <inheritdoc />
    public string Name => "cedar";

    /// <inheritdoc />
    public ExternalPolicyDecision Evaluate(IReadOnlyDictionary<string, object> context)
    {
        var sw = Stopwatch.StartNew();

        try
        {
            var decision = ResolveMode() == CedarEvaluationMode.Cli
                ? EvaluateWithCli(context)
                : EvaluateBuiltin(context);

            sw.Stop();
            return new ExternalPolicyDecision
            {
                Backend = decision.Backend,
                Allowed = decision.Allowed,
                Reason = decision.Reason,
                Error = decision.Error,
                Metadata = decision.Metadata,
                EvaluationMs = sw.Elapsed.TotalMilliseconds
            };
        }
        catch (Exception ex)
        {
            sw.Stop();
            return new ExternalPolicyDecision
            {
                Backend = Name,
                Allowed = false,
                Reason = "Cedar evaluation failed — see server logs for details",
                Error = "INTERNAL_ERROR",
                EvaluationMs = sw.Elapsed.TotalMilliseconds
            };
        }
    }

    private CedarEvaluationMode ResolveMode()
    {
        if (_mode != CedarEvaluationMode.Auto)
        {
            return _mode;
        }

        return ExternalBackendUtilities.CommandExists(OperatingSystem.IsWindows() ? "cedar.exe" : "cedar")
            ? CedarEvaluationMode.Cli
            : CedarEvaluationMode.Builtin;
    }

    private ExternalPolicyDecision EvaluateWithCli(IReadOnlyDictionary<string, object> context)
    {
        var policy = ResolvePolicyContent();
        if (string.IsNullOrWhiteSpace(policy))
        {
            return new ExternalPolicyDecision
            {
                Backend = Name,
                Allowed = false,
                Reason = "No Cedar policy content was provided.",
                Error = "missing_policy"
            };
        }

        using var tempDirectory = new TempDirectory();
        var policyPath = Path.Combine(tempDirectory.Path, "policy.cedar");
        File.WriteAllText(policyPath, policy, Encoding.UTF8);

        var requestPath = Path.Combine(tempDirectory.Path, "request.json");
        var request = JsonSerializer.Serialize(BuildRequest(context));
        File.WriteAllText(requestPath, request, Encoding.UTF8);

        var entitiesPath = Path.Combine(tempDirectory.Path, "entities.json");
        File.WriteAllText(entitiesPath, "[]", Encoding.UTF8);

        var startInfo = BuildCedarStartInfo(
            OperatingSystem.IsWindows() ? "cedar.exe" : "cedar",
            policyPath,
            entitiesPath,
            requestPath);

        using var process = Process.Start(startInfo);
        if (process is null)
        {
            return EvaluateBuiltin(context);
        }

        process.WaitForExit((int)_timeout.TotalMilliseconds);
        if (!process.HasExited)
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch
            {
                // Best effort only.
            }

            return new ExternalPolicyDecision
            {
                Backend = Name,
                Allowed = false,
                Reason = "Cedar CLI evaluation timed out.",
                Error = "timeout"
            };
        }

        if (process.ExitCode != 0)
        {
            return new ExternalPolicyDecision
            {
                Backend = Name,
                Allowed = false,
                Reason = "Cedar CLI evaluation failed.",
                Error = process.StandardError.ReadToEnd()
            };
        }

        var output = process.StandardOutput.ReadToEnd();
        using var document = JsonDocument.Parse(output);
        var decision = document.RootElement.GetProperty("decision").GetString();
        var allowed = string.Equals(decision, "ALLOW", StringComparison.OrdinalIgnoreCase);

        return new ExternalPolicyDecision
        {
            Backend = Name,
            Allowed = allowed,
            Reason = allowed ? "Cedar CLI allowed the request." : "Cedar CLI denied the request.",
            Metadata = new Dictionary<string, object>
            {
                ["mode"] = "cli"
            }
        };
    }

    private ExternalPolicyDecision EvaluateBuiltin(IReadOnlyDictionary<string, object> context)
    {
        var policy = ResolvePolicyContent();
        if (string.IsNullOrWhiteSpace(policy))
        {
            return new ExternalPolicyDecision
            {
                Backend = Name,
                Allowed = false,
                Reason = "No Cedar policy content was provided.",
                Error = "missing_policy"
            };
        }

        var request = BuildRequest(context);
        var statements = ParseStatements(policy);

        foreach (var statement in statements.Where(candidate => string.Equals(candidate.Effect, "forbid", StringComparison.OrdinalIgnoreCase)))
        {
            if (StatementMatches(statement, request))
            {
                return new ExternalPolicyDecision
                {
                    Backend = Name,
                    Allowed = false,
                    Reason = $"Cedar forbid statement matched {statement.ActionConstraint ?? "request"}."
                };
            }
        }

        foreach (var statement in statements.Where(candidate => string.Equals(candidate.Effect, "permit", StringComparison.OrdinalIgnoreCase)))
        {
            if (StatementMatches(statement, request))
            {
                return new ExternalPolicyDecision
                {
                    Backend = Name,
                    Allowed = true,
                    Reason = $"Cedar permit statement matched {statement.ActionConstraint ?? "request"}.",
                    Metadata = new Dictionary<string, object>
                    {
                        ["mode"] = "builtin"
                    }
                };
            }
        }

        return new ExternalPolicyDecision
        {
            Backend = Name,
            Allowed = false,
            Reason = "Cedar built-in fallback denied the request by default.",
            Metadata = new Dictionary<string, object>
            {
                ["mode"] = "builtin"
            }
        };
    }

    private static CedarRequest BuildRequest(IReadOnlyDictionary<string, object> context)
    {
        var action = TryGet(context, "tool_name") ?? TryGet(context, "action") ?? "unknown";
        var principal = TryGet(context, "agent_did") ?? TryGet(context, "principal") ?? "anonymous";
        var resource = TryGet(context, "resource") ?? "default";

        return new CedarRequest(
            Principal: principal.Contains("::", StringComparison.Ordinal) ? principal : $"Agent::\"{principal}\"",
            Action: action.Contains("::", StringComparison.Ordinal) ? action : $"Action::\"{ToolToCedarAction(action)}\"",
            Resource: resource.Contains("::", StringComparison.Ordinal) ? resource : $"Resource::\"{resource}\"");
    }

    private static IReadOnlyList<CedarStatement> ParseStatements(string policy)
    {
        var statements = new List<CedarStatement>();
        foreach (Match match in StatementRegex.Matches(policy))
        {
            var body = match.Groups["body"].Value;
            var actionMatch = ActionConstraintRegex.Match(body);
            statements.Add(new CedarStatement(match.Groups["effect"].Value, actionMatch.Success ? actionMatch.Groups["action"].Value : null));
        }

        return statements;
    }

    private static bool StatementMatches(CedarStatement statement, CedarRequest request)
    {
        return statement.ActionConstraint is null
            || string.Equals(statement.ActionConstraint, request.Action, StringComparison.Ordinal);
    }

    private static string ToolToCedarAction(string toolName)
    {
        var pieces = toolName
            .Split(['_', '-', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(piece => char.ToUpperInvariant(piece[0]) + piece[1..].ToLowerInvariant());
        return string.Concat(pieces);
    }

    private static string? TryGet(IReadOnlyDictionary<string, object> context, string key)
    {
        foreach (var pair in context)
        {
            if (string.Equals(pair.Key, key, StringComparison.OrdinalIgnoreCase))
            {
                return pair.Value switch
                {
                    null => null,
                    JsonElement element when element.ValueKind == JsonValueKind.String => element.GetString(),
                    JsonElement element => element.ToString(),
                    _ => pair.Value.ToString()
                };
            }
        }

        return null;
    }

    private string? ResolvePolicyContent()
    {
        if (!string.IsNullOrWhiteSpace(_policyContent))
        {
            return _policyContent;
        }

        return !string.IsNullOrWhiteSpace(_policyPath) && File.Exists(_policyPath)
            ? File.ReadAllText(_policyPath, Encoding.UTF8)
            : null;
    }

    /// <summary>
    /// Builds the <see cref="ProcessStartInfo"/> for the Cedar CLI using
    /// <see cref="ProcessStartInfo.ArgumentList"/> so paths containing quote
    /// characters (legal on Linux) cannot break out of the quoting that a
    /// naive <c>Arguments</c>-string assignment would impose. Exposed so the
    /// argv shape is inspectable by callers (e.g. for debugging or in tests)
    /// without invoking the Cedar binary.
    /// </summary>
    /// <remarks>
    /// This helper is intentionally <c>public</c> rather than <c>internal</c>
    /// + <c>InternalsVisibleTo</c>. Strong-name signing on this assembly is
    /// identity, not a security boundary, so <c>InternalsVisibleTo</c> would
    /// be API hygiene rather than real isolation; the helper is a pure
    /// argv-builder with no state or I/O, so public exposure adds no
    /// practical attack surface. Maintainers who prefer the smaller public
    /// surface can demote to <c>internal</c> + signed
    /// <c>InternalsVisibleTo, PublicKey=...</c> without behavioural change.
    /// </remarks>
    public static ProcessStartInfo BuildCedarStartInfo(
        string executable,
        string policyPath,
        string entitiesPath,
        string requestPath)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("authorize");
        startInfo.ArgumentList.Add("--policies");
        startInfo.ArgumentList.Add(policyPath);
        startInfo.ArgumentList.Add("--entities");
        startInfo.ArgumentList.Add(entitiesPath);
        startInfo.ArgumentList.Add("--request-json");
        startInfo.ArgumentList.Add(requestPath);
        return startInfo;
    }

    private sealed record CedarStatement(string Effect, string? ActionConstraint);

    private sealed record CedarRequest(string Principal, string Action, string Resource);

    private sealed class TempDirectory : IDisposable
    {
        public TempDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"agt-cedar-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            try
            {
                Directory.Delete(Path, recursive: true);
            }
            catch
            {
                // Best effort cleanup only.
            }
        }
    }
}
