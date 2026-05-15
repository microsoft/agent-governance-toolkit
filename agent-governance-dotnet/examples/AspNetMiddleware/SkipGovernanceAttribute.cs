// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace AgentGovernance.Examples.AspNetMiddleware;

/// <summary>
/// Marker attribute for endpoints that should bypass the
/// <see cref="GovernanceCheckMiddleware"/> (e.g., health probes).
/// Apply via endpoint metadata, e.g.
/// <c>app.MapGet(...).WithMetadata(new SkipGovernanceAttribute())</c>.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false)]
public sealed class SkipGovernanceAttribute : Attribute
{
}
