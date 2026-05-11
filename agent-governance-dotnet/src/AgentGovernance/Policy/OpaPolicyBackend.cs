// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AgentGovernance.Policy;

/// <summary>
/// Evaluation mode for OPA/Rego policies.
/// </summary>
public enum OpaEvaluationMode
{
    /// <summary>Automatically choose between local and remote evaluation.</summary>
    Auto,
    /// <summary>Query a remote OPA server.</summary>
    Remote,
    /// <summary>Use local CLI or built-in evaluation.</summary>
    Local
}

/// <summary>
/// OPA/Rego external policy backend.
/// </summary>
public sealed class OpaPolicyBackend : IExternalPolicyBackend
{
    private static readonly Regex AllowBlockRegex = new(@"allow\s*\{(?<body>.*?)\}", RegexOptions.Singleline | RegexOptions.CultureInvariant);
    private static readonly Regex EqualityRegex = new(@"^input\.(?<field>[A-Za-z0-9_]+)\s*(?<op>==|!=)\s*(?<value>true|false|""[^""]*"")$", RegexOptions.CultureInvariant);
    private static readonly Regex NotRegex = new(@"^not\s+input\.(?<field>[A-Za-z0-9_]+)$", RegexOptions.CultureInvariant);
    private static readonly HttpClient HttpClient = new();

    private readonly string? _regoContent;
    private readonly string? _regoPath;
    private readonly string _query;
    private readonly string _opaUrl;
    private readonly OpaEvaluationMode _mode;
    private readonly TimeSpan _timeout;

    /// <summary>
    /// Initialize the OPA policy backend.
    /// </summary>
    public OpaPolicyBackend(
        string? regoContent = null,
        string? regoPath = null,
        string query = "data.agentgovernance.allow",
        string opaUrl = "http://localhost:8181",
        OpaEvaluationMode mode = OpaEvaluationMode.Auto,
        TimeSpan? timeout = null)
    {
        _regoContent = regoContent;
        _regoPath = regoPath;
        _query = query;
        _opaUrl = opaUrl.TrimEnd('/');
        _mode = mode;
        _timeout = timeout ?? TimeSpan.FromSeconds(5);
    }

    /// <inheritdoc />
    public string Name => "opa";

    /// <inheritdoc />
    public ExternalPolicyDecision Evaluate(IReadOnlyDictionary<string, object> context)
    {
        var sw = Stopwatch.StartNew();

        try
        {
            var decision = ResolveMode() switch
            {
                OpaEvaluationMode.Remote => EvaluateRemote(context),
                _ => EvaluateLocal(context)
            };

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
                Reason = $"OPA evaluation failed: {ex.Message}",
                Error = ex.Message,
                EvaluationMs = sw.Elapsed.TotalMilliseconds
            };
        }
    }

    private OpaEvaluationMode ResolveMode()
    {
        if (_mode != OpaEvaluationMode.Auto)
        {
            return _mode;
        }

        return string.IsNullOrWhiteSpace(_regoContent) && string.IsNullOrWhiteSpace(_regoPath)
            ? OpaEvaluationMode.Remote
            : OpaEvaluationMode.Local;
    }

    private ExternalPolicyDecision EvaluateRemote(IReadOnlyDictionary<string, object> context)
    {
        if (!Regex.IsMatch(_query, @"^[a-zA-Z0-9._\-]+$"))
        {
            return new ExternalPolicyDecision
            {
                Backend = Name,
                Allowed = false,
                Reason = $"Invalid OPA query path '{_query}'.",
                Error = "invalid_query"
            };
        }

        var path = _query.StartsWith("data.", StringComparison.Ordinal)
            ? _query["data.".Length..]
            : _query;

        var payload = JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["input"] = context
        });

        using var request = new HttpRequestMessage(HttpMethod.Post, $"{_opaUrl}/v1/data/{path.Replace('.', '/')}")
        {
            Content = new StringContent(payload, Encoding.UTF8, "application/json")
        };

        using var cts = new CancellationTokenSource(_timeout);
        using var response = HttpClient.Send(request, cts.Token);
        var content = response.Content.ReadAsStringAsync(cts.Token).GetAwaiter().GetResult();

        if (!response.IsSuccessStatusCode)
        {
            return new ExternalPolicyDecision
            {
                Backend = Name,
                Allowed = false,
                Reason = $"OPA server returned {(int)response.StatusCode}.",
                Error = content
            };
        }

        using var document = JsonDocument.Parse(content);
        var allowed = document.RootElement.TryGetProperty("result", out var result) && EvaluateJsonTruthiness(result);

        return new ExternalPolicyDecision
        {
            Backend = Name,
            Allowed = allowed,
            Reason = allowed ? $"OPA backend '{_query}' allowed the request." : $"OPA backend '{_query}' denied the request.",
            Metadata = new Dictionary<string, object>
            {
                ["query"] = _query,
                ["mode"] = "remote"
            }
        };
    }

    private ExternalPolicyDecision EvaluateLocal(IReadOnlyDictionary<string, object> context)
    {
        if (!string.IsNullOrWhiteSpace(_regoPath) && File.Exists(_regoPath))
        {
            var cliDecision = TryEvaluateWithCli(context);
            if (cliDecision is not null)
            {
                return cliDecision;
            }
        }

        var rego = ResolveRegoContent();
        if (string.IsNullOrWhiteSpace(rego))
        {
            return new ExternalPolicyDecision
            {
                Backend = Name,
                Allowed = false,
                Reason = "No Rego policy content was provided.",
                Error = "missing_rego"
            };
        }

        var allowed = EvaluateBuiltin(rego, context);
        return new ExternalPolicyDecision
        {
            Backend = Name,
            Allowed = allowed,
            Reason = allowed ? "OPA built-in fallback allowed the request." : "OPA built-in fallback denied the request.",
            Metadata = new Dictionary<string, object>
            {
                ["query"] = _query,
                ["mode"] = "builtin"
            }
        };
    }

    private ExternalPolicyDecision? TryEvaluateWithCli(IReadOnlyDictionary<string, object> context)
    {
        var opaExecutable = OperatingSystem.IsWindows() ? "opa.exe" : "opa";
        if (!CommandExists(opaExecutable))
        {
            return null;
        }

        var regoPath = _regoPath!;
        var inputJson = JsonSerializer.Serialize(context);
        var startInfo = BuildOpaStartInfo(opaExecutable, regoPath, _query);

        using var process = Process.Start(startInfo);
        if (process is null)
        {
            return null;
        }

        process.StandardInput.Write(inputJson);
        process.StandardInput.Close();
        process.WaitForExit((int)_timeout.TotalMilliseconds);

        if (!process.HasExited)
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch
            {
                // Best effort only; caller still receives a fail-closed result.
            }

            return new ExternalPolicyDecision
            {
                Backend = Name,
                Allowed = false,
                Reason = "OPA CLI evaluation timed out.",
                Error = "timeout"
            };
        }

        if (process.ExitCode != 0)
        {
            return new ExternalPolicyDecision
            {
                Backend = Name,
                Allowed = false,
                Reason = "OPA CLI evaluation failed.",
                Error = process.StandardError.ReadToEnd()
            };
        }

        using var document = JsonDocument.Parse(process.StandardOutput.ReadToEnd());
        var result = document.RootElement.GetProperty("result");
        var expressions = result[0].GetProperty("expressions");
        var value = expressions[0].GetProperty("value");

        var allowed = EvaluateJsonTruthiness(value);
        return new ExternalPolicyDecision
        {
            Backend = Name,
            Allowed = allowed,
            Reason = allowed ? "OPA CLI allowed the request." : "OPA CLI denied the request.",
            Metadata = new Dictionary<string, object>
            {
                ["query"] = _query,
                ["mode"] = "cli"
            }
        };
    }

    private static bool EvaluateBuiltin(string rego, IReadOnlyDictionary<string, object> context)
    {
        foreach (Match match in AllowBlockRegex.Matches(rego))
        {
            var body = match.Groups["body"].Value;
            var clauses = body.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Where(clause => !string.IsNullOrWhiteSpace(clause))
                .ToArray();

            if (clauses.Length == 0)
            {
                continue;
            }

            if (clauses.All(clause => EvaluateClause(clause, context)))
            {
                return true;
            }
        }

        return false;
    }

    private static bool EvaluateClause(string clause, IReadOnlyDictionary<string, object> context)
    {
        var notMatch = NotRegex.Match(clause);
        if (notMatch.Success)
        {
            return !TryGetContextValue(context, notMatch.Groups["field"].Value, out var value) || !AsBoolean(value);
        }

        var equalityMatch = EqualityRegex.Match(clause);
        if (equalityMatch.Success)
        {
            var field = equalityMatch.Groups["field"].Value;
            var op = equalityMatch.Groups["op"].Value;
            var expectedToken = equalityMatch.Groups["value"].Value;

            if (!TryGetContextValue(context, field, out var actual))
            {
                return false;
            }

            var expected = ParseLiteral(expectedToken);
            var comparison = Equals(Normalize(actual), expected);
            return op == "==" ? comparison : !comparison;
        }

        return false;
    }

    private static object ParseLiteral(string token)
    {
        if (string.Equals(token, "true", StringComparison.Ordinal))
        {
            return true;
        }

        if (string.Equals(token, "false", StringComparison.Ordinal))
        {
            return false;
        }

        return token.Trim('"');
    }

    private static object? Normalize(object? value) => value switch
    {
        JsonElement element when element.ValueKind == JsonValueKind.String => element.GetString(),
        JsonElement element when element.ValueKind == JsonValueKind.True => true,
        JsonElement element when element.ValueKind == JsonValueKind.False => false,
        _ => value
    };

    private static bool TryGetContextValue(IReadOnlyDictionary<string, object> context, string key, out object? value)
    {
        if (context.TryGetValue(key, out var direct))
        {
            value = direct;
            return true;
        }

        foreach (var pair in context)
        {
            if (string.Equals(pair.Key, key, StringComparison.OrdinalIgnoreCase))
            {
                value = pair.Value;
                return true;
            }
        }

        value = null;
        return false;
    }

    private static bool EvaluateJsonTruthiness(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Number => element.TryGetInt32(out var value) && value != 0,
        JsonValueKind.Null => false,
        JsonValueKind.Undefined => false,
        _ => true
    };

    private static bool AsBoolean(object? value) => value switch
    {
        bool boolean => boolean,
        JsonElement element when element.ValueKind == JsonValueKind.True => true,
        JsonElement element when element.ValueKind == JsonValueKind.False => false,
        string text when bool.TryParse(text, out var parsed) => parsed,
        _ => false
    };

    /// <summary>
    /// Builds the <see cref="ProcessStartInfo"/> for the OPA CLI using
    /// <see cref="ProcessStartInfo.ArgumentList"/> so the rego file path
    /// (caller-supplied via <c>_regoPath</c>) and the query string
    /// (caller-supplied via <c>_query</c>) cannot break out of quoting. The
    /// naive <c>Arguments = $"...\"{regoPath}\" \"{_query}\""</c> form would
    /// mis-tokenize any input containing a double-quote (legal on Linux
    /// paths) or shell metacharacters that the underlying
    /// CommandLineToArgvW-style parser re-splits on.
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
    public static ProcessStartInfo BuildOpaStartInfo(
        string executable,
        string regoPath,
        string query)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("eval");
        startInfo.ArgumentList.Add("--format");
        startInfo.ArgumentList.Add("json");
        startInfo.ArgumentList.Add("--stdin-input");
        startInfo.ArgumentList.Add("--data");
        startInfo.ArgumentList.Add(regoPath);
        startInfo.ArgumentList.Add(query);
        return startInfo;
    }

    private static bool CommandExists(string executable)
    {
        var path = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        foreach (var directory in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var candidate = Path.Combine(directory, executable);
            if (File.Exists(candidate))
            {
                return true;
            }
        }

        return false;
    }

    private string? ResolveRegoContent()
    {
        if (!string.IsNullOrWhiteSpace(_regoContent))
        {
            return _regoContent;
        }

        return !string.IsNullOrWhiteSpace(_regoPath) && File.Exists(_regoPath)
            ? File.ReadAllText(_regoPath, Encoding.UTF8)
            : null;
    }
}
