// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Concurrent;
using System.Linq;
using System.Text.RegularExpressions;

namespace AgentGovernance.Policy;

/// <summary>
/// Function signature for a protocol facet extractor. Receives the
/// sub-dictionary stored at the registered context key and returns the
/// facet fields to merge back into that sub-dictionary.
/// </summary>
public delegate IReadOnlyDictionary<string, object> FacetExtractor(
    IReadOnlyDictionary<string, object> sub);

/// <summary>
/// Holds protocol facet extractors keyed by context field name.
/// </summary>
/// <remarks>
/// Each extractor receives the sub-dictionary at its registered key and
/// returns fields to merge back. Exceptions thrown inside an extractor are
/// caught and logged so a broken parser can never block policy evaluation.
/// </remarks>
public sealed class FacetRegistry
{
    private readonly object _gate = new();
    private readonly List<(string Key, FacetExtractor Extractor)> _extractors = new();

    /// <summary>Number of registered extractors (primarily for tests).</summary>
    public int Count
    {
        get
        {
            lock (_gate) { return _extractors.Count; }
        }
    }

    /// <summary>Register an extractor for sub-dictionaries at <paramref name="contextKey"/>.</summary>
    public void Register(string contextKey, FacetExtractor extractor)
    {
        if (string.IsNullOrEmpty(contextKey)) throw new ArgumentException("key required", nameof(contextKey));
        ArgumentNullException.ThrowIfNull(extractor);
        lock (_gate)
        {
            _extractors.Add((contextKey, extractor));
        }
    }

    /// <summary>Remove all registered extractors. Primarily for tests.</summary>
    public void Clear()
    {
        lock (_gate) { _extractors.Clear(); }
    }

    /// <summary>
    /// Run all registered extractors against <paramref name="context"/> in place.
    /// </summary>
    /// <remarks>
    /// For each registered key whose value is a string-keyed dictionary, the
    /// extractor is called and the returned fields are merged back into that
    /// sub-dictionary. Existing dot-path field resolution in
    /// <see cref="PolicyRule"/> already navigates nested dictionaries, so no
    /// top-level flattening is required.
    /// </remarks>
    public void Extract(IDictionary<string, object> context)
    {
        ArgumentNullException.ThrowIfNull(context);

        // Snapshot under the gate; do extractor work without holding the lock
        // so a buggy or slow extractor cannot block registration.
        List<(string Key, FacetExtractor Extractor)> snapshot;
        lock (_gate) { snapshot = new(_extractors); }

        foreach (var (key, extractor) in snapshot)
        {
            if (!context.TryGetValue(key, out var sub) || sub is null) continue;
            if (sub is not IDictionary<string, object> subDict) continue;

            IReadOnlyDictionary<string, object> facets;
            try
            {
                facets = extractor(new Dictionary<string, object>(subDict));
            }
            catch (ArgumentException ex)
            {
                Console.Error.WriteLine(
                    $"[protocol-facets] extractor for '{key}' threw: {ex.Message}");
                continue;
            }
            catch (InvalidOperationException ex)
            {
                Console.Error.WriteLine(
                    $"[protocol-facets] extractor for '{key}' threw: {ex.Message}");
                continue;
            }
            catch (Exception ex) when (!IsFatal(ex))
            {
                Console.Error.WriteLine(
                    $"[protocol-facets] extractor for '{key}' threw: {ex.Message}");
                continue;
            }
            if (facets is null) continue;

            // Replace the sub-dictionary slot with a fresh copy that contains
            // the original entries plus the extracted facets. Mutating
            // `subDict` in place would mutate any caller dictionary aliased
            // into the context, which the PolicyEngine relies on NOT
            // happening (Evaluate must not modify caller state).
            var merged = new Dictionary<string, object>(subDict, StringComparer.Ordinal);
            foreach (var kvp in facets)
            {
                merged[kvp.Key] = kvp.Value;
            }
            context[key] = merged;
        }
    }

    private static bool IsFatal(Exception ex) =>
        ex is OutOfMemoryException
        or StackOverflowException
        or AccessViolationException
        or AppDomainUnloadedException
        or BadImageFormatException
        or CannotUnloadAppDomainException
        or InvalidProgramException
        or ThreadAbortException;
}

/// <summary>
/// Built-in SQL and Kubernetes facet extractors and the process-wide
/// default <see cref="FacetRegistry"/>.
/// </summary>
public static partial class ProtocolFacets
{
    private static readonly Lazy<FacetRegistry> s_default = new(() =>
    {
        var r = new FacetRegistry();
        r.Register("sql", ExtractSqlFacets);
        r.Register("k8s", ExtractK8sFacets);
        return r;
    });

    /// <summary>
    /// Process-wide default <see cref="FacetRegistry"/>, pre-loaded with SQL
    /// and Kubernetes extractors. Add new protocols via <see cref="FacetRegistry.Register"/>.
    /// </summary>
    public static FacetRegistry DefaultRegistry => s_default.Value;

    /// <summary>
    /// Enrich a policy evaluation context with wire-protocol facets using
    /// the default registry. Mutates <paramref name="context"/> in place.
    /// </summary>
    public static void ExtractProtocolFacets(IDictionary<string, object> context)
        => DefaultRegistry.Extract(context);

    /// <summary>
    /// Enrich a policy evaluation context using a caller-supplied registry.
    /// </summary>
    public static void ExtractProtocolFacets(IDictionary<string, object> context, FacetRegistry registry)
    {
        ArgumentNullException.ThrowIfNull(registry);
        registry.Extract(context);
    }

    // ── SQL ─────────────────────────────────────────────────────────────

    private static readonly HashSet<string> SqlKnownVerbs = new(StringComparer.Ordinal)
    {
        "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE", "ALTER",
        "CREATE", "GRANT", "REVOKE", "MERGE", "CALL", "EXECUTE", "EXPLAIN",
        "WITH", "REPLACE", "RENAME", "COMMENT",
    };

    private static readonly HashSet<string> SqlFunctionDenylist = new(StringComparer.Ordinal)
    {
        "VALUES", "IN", "EXISTS", "ANY", "ALL", "SOME", "CAST", "CASE", "IF",
        "DISTINCT", "ON", "USING", "WHEN", "THEN", "ELSE", "AND", "OR", "NOT",
    };

    private const string IdentPart =
        @"(?:[A-Za-z_][A-Za-z0-9_]*|""[^""]+""|`[^`]+`|\[[^\]]+\])";
    private const string Ident = "(" + IdentPart + @"(?:\." + IdentPart + ")*)";

    // The two hottest patterns (first-word verb scan and function-call
    // detection) are materialised as compile-time regexes via the
    // `GeneratedRegex` source generator on .NET 7+. This skips the runtime
    // compiler entirely and lets the JIT inline the matcher.
    [GeneratedRegex(@"^\s*([A-Za-z]+)")]
    private static partial Regex SqlFirstWord();

    [GeneratedRegex(@"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")]
    private static partial Regex FuncRe();

    // Cache for dynamic (verb-templated) patterns produced by the verb
    // dispatch in `PickTarget` / `ExtractTables`. The set of distinct
    // patterns is fully determined by that dispatch and is therefore
    // bounded by a small constant — there is no path from caller input to
    // a new entry in this cache, so unbounded growth is impossible.
    // If a future change ever lets caller-supplied strings flow into `Re`,
    // this cache must be replaced with a bounded LRU.
    private static readonly ConcurrentDictionary<string, Regex> _regexCache = new();
    private static Regex Re(string pattern) =>
        _regexCache.GetOrAdd(pattern, p => new Regex(p, RegexOptions.Compiled | RegexOptions.IgnoreCase));

    /// <summary>
    /// SQL facet extractor. Reads <c>sub["query"]</c> and returns
    /// <c>{verb, target, tables, functions}</c> (all strings).
    /// </summary>
    public static IReadOnlyDictionary<string, object> ExtractSqlFacets(
        IReadOnlyDictionary<string, object> sub)
    {
        ArgumentNullException.ThrowIfNull(sub);
        if (!sub.TryGetValue("query", out var raw) || raw is not string rawStr || string.IsNullOrWhiteSpace(rawStr))
        {
            return EmptySqlFacets();
        }

        var stripped = StripSqlComments(rawStr).Trim();
        if (stripped.Length == 0) return EmptySqlFacets();

        var statements = SplitSqlStatements(stripped);
        if (statements.Count > 1) return UnknownSqlFacets();
        var query = statements.Count == 1 ? statements[0] : stripped;

        var firstWordMatch = SqlFirstWord().Match(query);
        if (!firstWordMatch.Success) return UnknownSqlFacets();
        var surface = firstWordMatch.Groups[1].Value.ToUpperInvariant();

        string verb = surface == "WITH"
            ? DetectCteInnerVerb(query)
            : SqlKnownVerbs.Contains(surface) ? surface : "UNKNOWN";

        var tables = ExtractTables(query, verb);
        var functions = ExtractFunctions(query);
        var target = PickTarget(query, verb, tables);

        return new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["verb"] = verb,
            ["target"] = target,
            ["tables"] = string.Join(",", tables),
            ["functions"] = string.Join(",", functions),
        };
    }

    private static Dictionary<string, object> EmptySqlFacets() => new(StringComparer.Ordinal)
    {
        ["verb"] = string.Empty,
        ["target"] = string.Empty,
        ["tables"] = string.Empty,
        ["functions"] = string.Empty,
    };

    private static Dictionary<string, object> UnknownSqlFacets()
    {
        var m = EmptySqlFacets();
        m["verb"] = "UNKNOWN";
        return m;
    }

    /// <summary>
    /// Quote-aware comment stripper. A naive regex `--[^\n]*` would
    /// corrupt input like <c>SELECT '--'; DROP TABLE x</c> by treating the
    /// in-string <c>--</c> as a line comment and consuming the rest of
    /// the input.
    /// </summary>
    private static string StripSqlComments(string sql)
    {
        var sb = new System.Text.StringBuilder(sql.Length);
        char quote = '\0';
        int i = 0;
        while (i < sql.Length)
        {
            char c = sql[i];
            if (quote != '\0')
            {
                sb.Append(c);
                if (c == quote)
                {
                    if (i + 1 < sql.Length && sql[i + 1] == quote)
                    {
                        // Doubled-quote escape
                        sb.Append(sql[i + 1]);
                        i += 2;
                        continue;
                    }
                    quote = '\0';
                }
                i++;
                continue;
            }
            if (c == '\'' || c == '"' || c == '`')
            {
                quote = c;
                sb.Append(c);
                i++;
                continue;
            }
            if (c == '-' && i + 1 < sql.Length && sql[i + 1] == '-')
            {
                i += 2;
                while (i < sql.Length && sql[i] != '\n' && sql[i] != '\r') i++;
                sb.Append(' ');
                continue;
            }
            if (c == '/' && i + 1 < sql.Length && sql[i + 1] == '*')
            {
                i += 2;
                while (i + 1 < sql.Length && !(sql[i] == '*' && sql[i + 1] == '/')) i++;
                if (i + 1 < sql.Length) i += 2;
                sb.Append(' ');
                continue;
            }
            sb.Append(c);
            i++;
        }
        return sb.ToString();
    }

    private static List<string> SplitSqlStatements(string sql)
    {
        var result = new List<string>();
        var sb = new System.Text.StringBuilder();
        char quote = '\0';
        for (int i = 0; i < sql.Length; i++)
        {
            char c = sql[i];
            if (quote != '\0')
            {
                sb.Append(c);
                if (c == quote)
                {
                    if (i + 1 < sql.Length && sql[i + 1] == quote)
                    {
                        sb.Append(sql[++i]);
                    }
                    else
                    {
                        quote = '\0';
                    }
                }
                continue;
            }
            if (c == '\'' || c == '"' || c == '`')
            {
                quote = c;
                sb.Append(c);
                continue;
            }
            if (c == ';')
            {
                var trimmed = sb.ToString().Trim();
                if (trimmed.Length > 0) result.Add(trimmed);
                sb.Clear();
                continue;
            }
            sb.Append(c);
        }
        var tail = sb.ToString().Trim();
        if (tail.Length > 0) result.Add(tail);
        return result;
    }

    /// <summary>
    /// For a <c>WITH ... &lt;verb&gt; ...</c> query, find the first DML
    /// keyword at top-level paren depth (i.e. outside any CTE body or
    /// subquery). Falls back to SELECT.
    /// </summary>
    private static string DetectCteInnerVerb(string query)
    {
        int depth = 0;
        char quote = '\0';
        var token = new System.Text.StringBuilder();
        bool sawWith = false;

        for (int i = 0; i <= query.Length; i++)
        {
            char c = i < query.Length ? query[i] : ' ';
            if (quote != '\0')
            {
                if (c == quote) quote = '\0';
                continue;
            }
            if (c == '\'' || c == '"' || c == '`')
            {
                quote = c;
                continue;
            }
            if (c == '(') { depth++; token.Clear(); continue; }
            if (c == ')') { depth = Math.Max(0, depth - 1); token.Clear(); continue; }
            if (char.IsAsciiLetter(c) || c == '_')
            {
                token.Append(c);
                continue;
            }
            if (token.Length > 0)
            {
                if (depth == 0)
                {
                    var up = token.ToString().ToUpperInvariant();
                    if (!sawWith && up == "WITH") { sawWith = true; }
                    else if (up is "SELECT" or "INSERT" or "UPDATE" or "DELETE" or "MERGE")
                    {
                        return up;
                    }
                }
                token.Clear();
            }
        }
        return "SELECT";
    }

    private static List<string> ExtractTables(string query, string verb)
    {
        var patterns = new List<Regex>
        {
            Re(@"\bFROM\s+" + Ident),
            Re(@"\bJOIN\s+" + Ident),
            Re(@"\bINTO\s+" + Ident),
            Re(@"\bUPDATE\s+" + Ident),
        };
        if (verb is "DROP" or "TRUNCATE" or "ALTER" or "CREATE" or "RENAME")
        {
            patterns.Add(Re(@"\b" + verb +
                @"\s+(?:TABLE|VIEW|INDEX|SEQUENCE|SCHEMA|DATABASE|TRIGGER|FUNCTION|PROCEDURE)?\s*(?:IF\s+(?:NOT\s+)?EXISTS\s+)?" + Ident));
            patterns.Add(Re(@"\bON\s+" + Ident));
        }
        if (verb is "GRANT" or "REVOKE")
        {
            patterns.Add(Re(@"\bON\s+(?:TABLE\s+)?" + Ident));
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        var result = new List<string>();
        foreach (var re in patterns)
        {
            foreach (var name in re.Matches(query).Cast<Match>().Select(m => NormalizeIdent(m.Groups[1].Value)).Where(name => name.Length > 0))
            {
                if (seen.Add(name)) result.Add(name);
            }
        }
        return result;
    }

    private static List<string> ExtractFunctions(string query)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var result = new List<string>();
        foreach (var up in FuncRe().Matches(query).Cast<Match>().Select(m => m.Groups[1].Value.ToUpperInvariant()).Where(up => !SqlFunctionDenylist.Contains(up)))
        {
            if (seen.Add(up)) result.Add(up);
        }
        return result;
    }

    private static string PickTarget(string query, string verb, List<string> tables)
    {
        string? pattern = verb switch
        {
            "INSERT" or "MERGE" => @"\bINTO\s+" + Ident,
            "UPDATE" => @"\bUPDATE\s+" + Ident,
            "DELETE" => @"\bDELETE\s+FROM\s+" + Ident,
            "DROP" or "TRUNCATE" or "ALTER" or "CREATE" or "RENAME" =>
                @"\b" + verb +
                @"\s+(?:TABLE|VIEW|INDEX|SEQUENCE|SCHEMA|DATABASE|TRIGGER|FUNCTION|PROCEDURE)?\s*(?:IF\s+(?:NOT\s+)?EXISTS\s+)?" + Ident,
            "GRANT" or "REVOKE" => @"\bON\s+(?:TABLE\s+)?" + Ident,
            _ => @"\bFROM\s+" + Ident,
        };
        var m = Re(pattern).Match(query);
        if (m.Success) return NormalizeIdent(m.Groups[1].Value);

        // Dialect-specific fallbacks.
        if (verb == "INSERT")
        {
            // Some dialects allow `INSERT <table> (...) VALUES (...)` without INTO.
            var bare = Re(@"\bINSERT\s+(?!INTO\b)" + Ident).Match(query);
            if (bare.Success) return NormalizeIdent(bare.Groups[1].Value);
        }
        if (verb == "DELETE")
        {
            var fb = Re(@"\bFROM\s+" + Ident).Match(query);
            if (fb.Success) return NormalizeIdent(fb.Groups[1].Value);
        }
        return tables.Count > 0 ? tables[0] : string.Empty;
    }

    /// <summary>
    /// Take the last dotted segment of an identifier and strip surrounding
    /// quotes / brackets so <c>"public"."users"</c> normalises to <c>users</c>
    /// (matches the Python sqlglot <c>Table.name</c> behaviour).
    /// </summary>
    private static string NormalizeIdent(string ident)
    {
        var parts = new List<string>();
        var buf = new System.Text.StringBuilder();
        char depth = '\0';
        foreach (var ch in ident.Trim())
        {
            if (depth != '\0')
            {
                buf.Append(ch);
                char close = depth switch { '"' => '"', '`' => '`', '[' => ']', _ => '\0' };
                if (ch == close) depth = '\0';
                continue;
            }
            switch (ch)
            {
                case '"': case '`': case '[':
                    depth = ch;
                    buf.Append(ch);
                    break;
                case '.':
                    parts.Add(buf.ToString());
                    buf.Clear();
                    break;
                default:
                    buf.Append(ch);
                    break;
            }
        }
        parts.Add(buf.ToString());
        var last = parts[^1].Trim();
        if ((last.StartsWith('"') && last.EndsWith('"')) ||
            (last.StartsWith('`') && last.EndsWith('`')) ||
            (last.StartsWith('[') && last.EndsWith(']')))
        {
            last = last.Substring(1, last.Length - 2);
        }
        return last;
    }

    // ── Kubernetes ──────────────────────────────────────────────────────

    private static readonly IReadOnlyDictionary<string, string> MethodToVerbNamed =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["GET"] = "get",
            ["DELETE"] = "delete",
            ["PUT"] = "update",
            ["PATCH"] = "patch",
            ["POST"] = "create",
            ["HEAD"] = "get",
        };

    private static readonly IReadOnlyDictionary<string, string> MethodToVerbCollection =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["GET"] = "list",
            ["POST"] = "create",
            ["DELETE"] = "deletecollection",
            ["PUT"] = "update",
            ["PATCH"] = "patch",
            ["HEAD"] = "list",
        };

    private sealed class K8sPattern
    {
        public Regex Re { get; }
        public string[] Groups { get; }
        public bool IsWatch { get; }

        public K8sPattern(string pattern, string[] groups, bool isWatch)
        {
            Re = new Regex(pattern, RegexOptions.Compiled);
            Groups = groups;
            IsWatch = isWatch;
        }
    }

    private static readonly K8sPattern[] K8sPatterns =
    {
        // Watch — namespaced collection
        new(@"^/api/[^/]+/watch/namespaces/([^/]+)/([^/]+)/?$", new[] { "namespace", "resource" }, true),
        new(@"^/apis/[^/]+/[^/]+/watch/namespaces/([^/]+)/([^/]+)/?$", new[] { "namespace", "resource" }, true),
        // Watch — namespaced named
        new(@"^/api/[^/]+/watch/namespaces/([^/]+)/([^/]+)/([^/]+)/?$", new[] { "namespace", "resource", "name" }, true),
        new(@"^/apis/[^/]+/[^/]+/watch/namespaces/([^/]+)/([^/]+)/([^/]+)/?$", new[] { "namespace", "resource", "name" }, true),
        // Watch — cluster
        new(@"^/api/[^/]+/watch/([^/]+)/?$", new[] { "resource" }, true),
        new(@"^/apis/[^/]+/[^/]+/watch/([^/]+)/?$", new[] { "resource" }, true),
        // Proxy tail
        new(@"^/api/[^/]+/namespaces/([^/]+)/([^/]+)/([^/]+)/(proxy)(?:/.*)?$",
            new[] { "namespace", "resource", "name", "subresource" }, false),
        new(@"^/apis/[^/]+/[^/]+/namespaces/([^/]+)/([^/]+)/([^/]+)/(proxy)(?:/.*)?$",
            new[] { "namespace", "resource", "name", "subresource" }, false),
        // Generic — most specific first
        new(@"^/api/[^/]+/namespaces/([^/]+)/([^/]+)/([^/]+)/([^/]+)/?$",
            new[] { "namespace", "resource", "name", "subresource" }, false),
        new(@"^/apis/[^/]+/[^/]+/namespaces/([^/]+)/([^/]+)/([^/]+)/([^/]+)/?$",
            new[] { "namespace", "resource", "name", "subresource" }, false),
        new(@"^/api/[^/]+/namespaces/([^/]+)/([^/]+)/([^/]+)/?$",
            new[] { "namespace", "resource", "name" }, false),
        new(@"^/apis/[^/]+/[^/]+/namespaces/([^/]+)/([^/]+)/([^/]+)/?$",
            new[] { "namespace", "resource", "name" }, false),
        new(@"^/api/[^/]+/namespaces/([^/]+)/([^/]+)/?$",
            new[] { "namespace", "resource" }, false),
        new(@"^/apis/[^/]+/[^/]+/namespaces/([^/]+)/([^/]+)/?$",
            new[] { "namespace", "resource" }, false),
        new(@"^/api/[^/]+/([^/]+)/([^/]+)/([^/]+)/?$", new[] { "resource", "name", "subresource" }, false),
        new(@"^/apis/[^/]+/[^/]+/([^/]+)/([^/]+)/([^/]+)/?$", new[] { "resource", "name", "subresource" }, false),
        new(@"^/api/[^/]+/([^/]+)/([^/]+)/(proxy)(?:/.*)?$",
            new[] { "resource", "name", "subresource" }, false),
        new(@"^/apis/[^/]+/[^/]+/([^/]+)/([^/]+)/(proxy)(?:/.*)?$",
            new[] { "resource", "name", "subresource" }, false),
        new(@"^/api/[^/]+/([^/]+)/([^/]+)/?$", new[] { "resource", "name" }, false),
        new(@"^/apis/[^/]+/[^/]+/([^/]+)/([^/]+)/?$", new[] { "resource", "name" }, false),
        new(@"^/api/[^/]+/([^/]+)/?$", new[] { "resource" }, false),
        new(@"^/apis/[^/]+/[^/]+/([^/]+)/?$", new[] { "resource" }, false),
    };

    /// <summary>
    /// Kubernetes facet extractor. Reads <c>sub["method"]</c> and
    /// <c>sub["path"]</c> and returns <c>{verb, resource, namespace, name, subresource}</c>.
    /// </summary>
    public static IReadOnlyDictionary<string, object> ExtractK8sFacets(
        IReadOnlyDictionary<string, object> sub)
    {
        ArgumentNullException.ThrowIfNull(sub);

        string method = sub.TryGetValue("method", out var m) && m is string ms ? ms.ToUpperInvariant() : string.Empty;
        string rawPath = sub.TryGetValue("path", out var p) && p is string ps ? ps : string.Empty;

        var result = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["verb"] = string.Empty,
            ["resource"] = string.Empty,
            ["namespace"] = string.Empty,
            ["name"] = string.Empty,
            ["subresource"] = string.Empty,
        };
        if (rawPath.Length == 0) return result;

        // Strip query / fragment before matching so resources or namespaces
        // with names containing "watch" cannot spoof the verb signal, and
        // honour ?watch=true as an alternate watch indicator.
        string pathOnly = rawPath;
        string query = string.Empty;
        int q = pathOnly.IndexOf('?');
        if (q >= 0) { query = pathOnly[(q + 1)..]; pathOnly = pathOnly[..q]; }
        int hash = pathOnly.IndexOf('#');
        if (hash >= 0) pathOnly = pathOnly[..hash];

        var matched = new Dictionary<string, string>(StringComparer.Ordinal);
        bool matchedIsWatch = false;
        foreach (var pat in K8sPatterns)
        {
            var match = pat.Re.Match(pathOnly);
            if (!match.Success) continue;
            for (int i = 0; i < pat.Groups.Length; i++)
            {
                matched[pat.Groups[i]] = match.Groups[i + 1].Value;
            }
            matchedIsWatch = pat.IsWatch;
            break;
        }

        bool queryIsWatch = false;
        if (query.Length > 0)
        {
            foreach (var kv in query.Split('&'))
            {
                int eq = kv.IndexOf('=');
                if (eq < 0) continue;
                if (kv[..eq].Equals("watch", StringComparison.Ordinal))
                {
                    var v = kv[(eq + 1)..];
                    if (v is "true" or "1" or "True") { queryIsWatch = true; break; }
                }
            }
        }

        string resource = matched.GetValueOrDefault("resource", string.Empty);
        string ns = matched.GetValueOrDefault("namespace", string.Empty);
        string name = matched.GetValueOrDefault("name", string.Empty);
        string subresource = matched.GetValueOrDefault("subresource", string.Empty);

        // `watch` is a read-only verb in the Kubernetes API: it only makes
        // sense for GET (or an empty/unspecified method). If a caller
        // supplies a write method together with a watch path or
        // ?watch=true, fall through to the method-derived verb so the rule
        // engine sees the actual intent (e.g. POST on /watch/... becomes
        // `create`, which is what the apiserver would consider it).
        bool methodAllowsWatch = method.Length == 0 || method == "GET" || method == "HEAD";
        bool isWatch = (matchedIsWatch || queryIsWatch) && methodAllowsWatch;
        string verb;
        if (isWatch) verb = "watch";
        else if (method.Length > 0)
        {
            var tbl = name.Length > 0 ? MethodToVerbNamed : MethodToVerbCollection;
            verb = tbl.TryGetValue(method, out var v) ? v : method.ToLowerInvariant();
        }
        else verb = string.Empty;

        result["verb"] = verb;
        result["resource"] = resource;
        result["namespace"] = ns;
        result["name"] = name;
        result["subresource"] = subresource;
        return result;
    }
}
