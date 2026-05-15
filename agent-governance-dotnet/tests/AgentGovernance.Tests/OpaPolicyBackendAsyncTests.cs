// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Net;
using System.Text;
using System.Text.Json;
using AgentGovernance.Policy;
using Xunit;

namespace AgentGovernance.Tests;

/// <summary>
/// Tests for the OPA backend's Remote evaluation path. The REVIEW.md HIGH
/// .NET #2 finding called out
/// <c>response.Content.ReadAsStringAsync(...).GetAwaiter().GetResult()</c>
/// inside the synchronous <c>Evaluate</c> as a thread-pool starvation
/// hazard. The fix is two-fold:
/// <list type="bullet">
///   <item>The sync path reads via <see cref="HttpContent.ReadAsStream(System.Threading.CancellationToken)"/>
///   instead of blocking on an async read.</item>
///   <item>A new <see cref="OpaPolicyBackend.EvaluateAsync"/> override exposes
///   a genuine async path that uses
///   <see cref="HttpClient.SendAsync(HttpRequestMessage, System.Threading.CancellationToken)"/>
///   + <see cref="HttpContent.ReadAsStringAsync(System.Threading.CancellationToken)"/>
///   for callers in async contexts.</item>
/// </list>
/// </summary>
public sealed class OpaPolicyBackendAsyncTests : IDisposable
{
    private readonly HttpListener _listener;
    private readonly string _baseUrl;
    private readonly CancellationTokenSource _stopServer = new();
    private readonly Task _serverTask;

    public OpaPolicyBackendAsyncTests()
    {
        // Find a free port and start a minimal local HTTP listener.
        // The handler returns a fixed JSON document mimicking OPA's
        // /v1/data/<path> response shape: { "result": true|false }
        var port = GetFreePort();
        _baseUrl = $"http://127.0.0.1:{port}";
        _listener = new HttpListener();
        _listener.Prefixes.Add($"{_baseUrl}/");
        _listener.Start();

        _serverTask = Task.Run(async () =>
        {
            while (!_stopServer.IsCancellationRequested)
            {
                HttpListenerContext ctx;
                try
                {
                    ctx = await _listener.GetContextAsync().ConfigureAwait(false);
                }
                catch
                {
                    return; // listener stopped
                }
                try
                {
                    // Default: allow. Query path determines decision.
                    var pathSegments = ctx.Request.Url!.AbsolutePath.TrimStart('/').Split('/');
                    var deny = pathSegments.Contains("deny");
                    var body = Encoding.UTF8.GetBytes(
                        deny ? "{\"result\":false}" : "{\"result\":true}");
                    ctx.Response.StatusCode = (int)HttpStatusCode.OK;
                    ctx.Response.ContentType = "application/json";
                    ctx.Response.ContentLength64 = body.Length;
                    await ctx.Response.OutputStream.WriteAsync(body).ConfigureAwait(false);
                    ctx.Response.OutputStream.Close();
                }
                catch
                {
                    // Best-effort: any I/O error in the test server is fatal.
                }
            }
        });
    }

    public void Dispose()
    {
        _stopServer.Cancel();
        try
        {
            _listener.Stop();
            _listener.Close();
        }
        catch { /* swallow */ }
    }

    private static int GetFreePort()
    {
        using var sock = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        sock.Start();
        var port = ((IPEndPoint)sock.LocalEndpoint).Port;
        sock.Stop();
        return port;
    }

    // ---------------------------------------------------------------------
    // EvaluateAsync — the new async path
    // ---------------------------------------------------------------------

    [Fact]
    public async Task EvaluateAsync_RemoteAllow_ReturnsAllowed()
    {
        var backend = new OpaPolicyBackend(
            opaUrl: _baseUrl,
            mode: OpaEvaluationMode.Remote,
            query: "data.agentgovernance.allow");

        var decision = await backend.EvaluateAsync(new Dictionary<string, object>
        {
            ["tool_name"] = "file_read"
        });

        Assert.Equal("opa", decision.Backend);
        Assert.True(decision.Allowed);
        Assert.Null(decision.Error);
        Assert.Equal("remote", decision.Metadata?["mode"]);
    }

    [Fact]
    public async Task EvaluateAsync_RemoteDeny_ReturnsDenied()
    {
        var backend = new OpaPolicyBackend(
            opaUrl: _baseUrl,
            mode: OpaEvaluationMode.Remote,
            query: "data.agentgovernance.deny");

        var decision = await backend.EvaluateAsync(new Dictionary<string, object>
        {
            ["tool_name"] = "file_write"
        });

        Assert.False(decision.Allowed);
    }

    [Fact]
    public async Task EvaluateAsync_RemoteInvalidQuery_FailsClosedWithoutHttpCall()
    {
        // A query containing characters outside the validated set must be
        // rejected before any HTTP request is dispatched. Point the URL at
        // an unrouteable host to confirm no network call occurs — if it
        // did, the test would hang or throw a connection error.
        var backend = new OpaPolicyBackend(
            opaUrl: "http://127.0.0.1:1",  // closed port
            mode: OpaEvaluationMode.Remote,
            query: "data.evil;`drop`");

        var decision = await backend.EvaluateAsync(new Dictionary<string, object>());

        Assert.False(decision.Allowed);
        Assert.Equal("invalid_query", decision.Error);
    }

    [Fact]
    public async Task EvaluateAsync_RespectsCallerCancellation()
    {
        // Point at an unrouteable address with a long backend timeout, but
        // cancel via the caller-supplied token. The cancellation must
        // propagate and surface as a failed evaluation, not a hang.
        var backend = new OpaPolicyBackend(
            opaUrl: "http://10.255.255.1",  // RFC 6890 unreachable
            mode: OpaEvaluationMode.Remote,
            query: "data.x.allow",
            timeout: TimeSpan.FromSeconds(30));

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var decision = await backend.EvaluateAsync(
            new Dictionary<string, object>(),
            cts.Token);
        sw.Stop();

        // Should return well before the 30s backend timeout — caller's
        // 250 ms cancellation must drive the deadline.
        Assert.True(
            sw.Elapsed < TimeSpan.FromSeconds(5),
            $"EvaluateAsync took {sw.Elapsed} — caller cancellation was not honoured.");
        Assert.False(decision.Allowed);
        Assert.NotNull(decision.Error);
    }

    // ---------------------------------------------------------------------
    // Sync path still works, no thread-pool starvation
    // ---------------------------------------------------------------------

    [Fact]
    public void Evaluate_RemoteAllow_StillWorksAfterSyncReadFix()
    {
        // The sync path now reads via HttpContent.ReadAsStream, not
        // ReadAsStringAsync(...).GetAwaiter().GetResult(). The decision
        // contract is unchanged.
        var backend = new OpaPolicyBackend(
            opaUrl: _baseUrl,
            mode: OpaEvaluationMode.Remote,
            query: "data.agentgovernance.allow");

        var decision = backend.Evaluate(new Dictionary<string, object>
        {
            ["tool_name"] = "file_read"
        });

        Assert.True(decision.Allowed);
        Assert.Equal("remote", decision.Metadata?["mode"]);
    }

    // ---------------------------------------------------------------------
    // Interface default implementation — backends that don't override
    // ---------------------------------------------------------------------

    [Fact]
    public async Task IExternalPolicyBackend_EvaluateAsync_DefaultsToSyncEvaluate()
    {
        // A backend that does NOT override EvaluateAsync must still expose
        // a working async surface via the interface's default
        // implementation. CedarPolicyBackend (in Builtin mode) is a
        // genuinely sync implementor with no async I/O — exercising
        // EvaluateAsync against it confirms the default wraps Evaluate in
        // Task.FromResult correctly.
        IExternalPolicyBackend cedar = new CedarPolicyBackend(
            policyContent: """
                permit(
                    principal,
                    action == Action::"ReadData",
                    resource
                );
                """,
            mode: CedarEvaluationMode.Builtin);

        var decision = await cedar.EvaluateAsync(new Dictionary<string, object>
        {
            ["tool_name"] = "read_data",
            ["agent_did"] = "did:mesh:test"
        });

        Assert.Equal("cedar", decision.Backend);
        Assert.True(decision.Allowed);
    }
}
