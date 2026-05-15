// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using AgentGovernance;
using AgentGovernance.Audit;
using AgentGovernance.Policy;
using AgentGovernance.Examples.AspNetMiddleware;

var builder = WebApplication.CreateBuilder(args);

// ---------------------------------------------------------------
// 1. Register the GovernanceKernel as a singleton
// ---------------------------------------------------------------
// The kernel is thread-safe and meant to be reused for the lifetime
// of the process. It owns the policy engine, audit emitter, rate limiter,
// and any optional defenses you opt into.
var policyPath = Path.Join(AppContext.BaseDirectory, "policies", "aspnet.yaml");

builder.Services.AddSingleton(_ => new GovernanceKernel(new GovernanceOptions
{
    PolicyPaths = new List<string> { policyPath },
    ConflictStrategy = ConflictResolutionStrategy.PriorityFirstMatch,
    EnablePromptInjectionDetection = true,
}));

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

var app = builder.Build();

// Log every governance event to the console.
var kernel = app.Services.GetRequiredService<GovernanceKernel>();
kernel.OnAllEvents(evt =>
    app.Logger.LogInformation(
        "[governance] {Type} agent={AgentId} policy={Policy}",
        evt.Type, evt.AgentId, evt.PolicyName ?? "(none)"));

// ---------------------------------------------------------------
// 2. Plug the governance middleware into the HTTP pipeline
// ---------------------------------------------------------------
// Every request goes through GovernanceCheckMiddleware before reaching
// any controller. Denied requests short-circuit with a structured 403
// (or 429 when rate-limited).
app.UseMiddleware<GovernanceCheckMiddleware>();

app.MapControllers();

// Tiny health endpoint that bypasses the middleware via route metadata.
app.MapGet("/healthz", () => Results.Ok(new { status = "ok" }))
   .WithMetadata(new SkipGovernanceAttribute());

app.Run();
