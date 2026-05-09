// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text.Json;
using System.Text.RegularExpressions;
using AgentGovernance.Integration;
using AgentGovernance.Policy;

namespace AgentGovernance.Examples.AspNetMiddleware;

/// <summary>
/// ASP.NET Core middleware that runs every inbound HTTP request through the
/// <see cref="GovernanceKernel"/> before it reaches any controller or endpoint.
///
/// Each request is converted into a synthetic "tool call" of the form
/// <c>HTTP_{METHOD}_{routeTemplate}</c> (falling back to the raw path when no
/// route template is available). The path, query, route values, and the
/// resolved agent identity are passed as evaluation arguments so that
/// policy rules can match on any of them.
///
/// Endpoints decorated with <see cref="SkipGovernanceAttribute"/> bypass
/// the check entirely (useful for health probes).
/// </summary>
public sealed class GovernanceCheckMiddleware
{
    private const string AnonymousAgentId = "did:agentmesh:http-anonymous";
    private const string AgentIdHeader = "X-Agent-Id";

    private readonly RequestDelegate _next;
    private readonly GovernanceKernel _kernel;
    private readonly ILogger<GovernanceCheckMiddleware> _logger;

    public GovernanceCheckMiddleware(
        RequestDelegate next,
        GovernanceKernel kernel,
        ILogger<GovernanceCheckMiddleware> logger)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _kernel = kernel ?? throw new ArgumentNullException(nameof(kernel));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Allow opt-out via endpoint metadata.
        var endpoint = context.GetEndpoint();
        if (endpoint?.Metadata.GetMetadata<SkipGovernanceAttribute>() is not null)
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        var agentId = ResolveAgentId(context);
        var routeTemplate =
            (endpoint as Microsoft.AspNetCore.Routing.RouteEndpoint)?.RoutePattern.RawText
            ?? context.Request.Path.Value
            ?? "/";
        // Route templates from attribute routing are typically already prefixed
        // with '/'. Normalize for stable rule matching.
        if (!routeTemplate.StartsWith('/'))
        {
            routeTemplate = "/" + routeTemplate;
        }
        // Strip route constraints (e.g. "{id:int}" -> "{id}") so policy rules
        // can be written against the simpler template form.
        routeTemplate = RouteConstraintRegex.Replace(routeTemplate, "{$1}");

        var toolName = $"HTTP_{context.Request.Method.ToUpperInvariant()}_{routeTemplate}";

        var args = new Dictionary<string, object>
        {
            ["agent_id"] = agentId,
            ["method"] = context.Request.Method,
            ["route"] = routeTemplate,
            ["path"] = context.Request.Path.Value ?? string.Empty,
            ["query"] = context.Request.QueryString.HasValue ? context.Request.QueryString.Value! : string.Empty,
        };

        ToolCallResult result;
        try
        {
            result = _kernel.EvaluateToolCall(agentId, toolName, args);
        }
        catch (Exception ex) when (
            ex is not OutOfMemoryException &&
            ex is not StackOverflowException &&
            ex is not AccessViolationException &&
            ex is not AppDomainUnloadedException &&
            ex is not BadImageFormatException &&
            ex is not CannotUnloadAppDomainException &&
            ex is not InvalidProgramException &&
            ex is not System.Threading.ThreadAbortException)
        {
            // Fail-closed on evaluation errors: do not let an unexpected
            // exception silently allow a request through.
            _logger.LogError(ex, "Governance evaluation threw for {Tool}; failing closed", toolName);
            await WriteJsonErrorAsync(context, StatusCodes.Status500InternalServerError, new
            {
                error = "governance_evaluation_failed",
                message = "An error occurred while evaluating governance policies.",
            }).ConfigureAwait(false);
            return;
        }

        if (result.Allowed)
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        // Surface the deny in a structured response with the most relevant status code.
        var (status, code) = ClassifyDenial(result);
        _logger.LogWarning(
            "[governance] BLOCK agent={AgentId} tool={Tool} rule={Rule} reason={Reason}",
            agentId,
            toolName,
            result.PolicyDecision?.MatchedRule ?? "(default)",
            result.Reason);

        await WriteJsonErrorAsync(context, status, new
        {
            error = code,
            agent_id = agentId,
            tool = toolName,
            rule = result.PolicyDecision?.MatchedRule,
            policy = result.PolicyDecision?.PolicyName,
            action = result.PolicyDecision?.Action,
            reason = result.Reason,
            approvers = result.PolicyDecision?.Approvers,
            rate_limit_reset = result.PolicyDecision?.RateLimitReset,
        }).ConfigureAwait(false);
    }

    private static string ResolveAgentId(HttpContext context)
    {
        // Prefer an authenticated identity when present.
        var name = context.User?.Identity?.Name;
        if (!string.IsNullOrWhiteSpace(name))
        {
            return $"did:agentmesh:{name}";
        }

        // Fall back to a caller-supplied header (illustrative — tighten for production).
        if (context.Request.Headers.TryGetValue(AgentIdHeader, out var headerValues))
        {
            var headerValue = headerValues.ToString();
            if (!string.IsNullOrWhiteSpace(headerValue))
            {
                return headerValue;
            }
        }

        return AnonymousAgentId;
    }

    private static (int Status, string Code) ClassifyDenial(ToolCallResult result)
    {
        if (result.PolicyDecision?.RateLimited == true)
        {
            return (StatusCodes.Status429TooManyRequests, "rate_limited");
        }

        var action = result.PolicyDecision?.Action;
        return action switch
        {
            "requireapproval" => (StatusCodes.Status403Forbidden, "approval_required"),
            "deny" => (StatusCodes.Status403Forbidden, "policy_denied"),
            _ => (StatusCodes.Status403Forbidden, "policy_denied"),
        };
    }

    private static Task WriteJsonErrorAsync(HttpContext context, int status, object payload)
    {
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/json; charset=utf-8";
        return context.Response.WriteAsync(JsonSerializer.Serialize(payload, SerializerOptions));
    }

    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
    };

    // Matches "{name:constraint}" or "{name:c1:c2}" and captures just "name".
    private static readonly Regex RouteConstraintRegex =
        new(@"\{([^:{}]+):[^{}]+\}", RegexOptions.Compiled);
}
