// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using Microsoft.AspNetCore.Mvc;

namespace AgentGovernance.Examples.AspNetMiddleware.Controllers;

/// <summary>
/// Sensitive admin endpoint used to demonstrate the
/// <c>require-approval-admin</c> policy rule. Every request is blocked at
/// the middleware with a 403 + <c>approval_required</c> until an out-of-band
/// approval workflow grants it.
/// </summary>
[ApiController]
[Route("admin")]
public sealed class AdminController : ControllerBase
{
    [HttpPost("reset")]
    public IActionResult Reset()
    {
        // Never reached — middleware blocks the request first.
        return Ok(new { message = "system reset" });
    }
}
